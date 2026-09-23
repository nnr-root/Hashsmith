package main

// A second batch of *2smith converters: password vaults, encrypted disks,
// office documents and the credential files a server configuration leaves
// behind.
//
// As with the key stores next door, every format here already had a verifier
// and no way to reach a real file.

import (
	"archive/zip"
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

// ── Lotus Notes user.id ───────────────────────────────────────────────────────

func runExtractLotus(args []string) error {
	return runFileRecordExtractor("lotus2smith", args, extractLotusRecords)
}

const (
	lotusBlobLengthAt = 0xD6
	lotusBlobStart    = 0xD8
)

// extractLotusRecords pulls the user blob out of a Notes .id file.
//
// The whole file is a container of Notes' own; the only part that matters is
// a length-prefixed blob whose offset is fixed. Reading it needs no format
// knowledge beyond those two numbers, which is why John's converter is six
// lines and this is not much more. The record is bare uppercase hex because
// the format has no tag — see crack_lotus85.go for why that makes it a
// shape match rather than a signature one.
func extractLotusRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var length [2]byte
	if _, err := f.ReadAt(length[:], lotusBlobLengthAt); err != nil {
		return nil, errors.New("this file is too short to be a Notes ID file")
	}
	n := int(binary.LittleEndian.Uint16(length[:]))
	if n < lotus85MinBlob || n > lotus85MaxBlob {
		return nil, fmt.Errorf("the user blob length reads %d, which is outside the 40 to 100 bytes a Notes ID file holds", n)
	}
	blob := make([]byte, n)
	if _, err := f.ReadAt(blob, lotusBlobStart); err != nil {
		return nil, errors.New("the Notes ID file ends inside its user blob")
	}
	return []string{strings.ToUpper(hex.EncodeToString(blob))}, nil
}

// ── andOTP backup ─────────────────────────────────────────────────────────────

func runExtractAndOTP(args []string) error {
	return runFileRecordExtractor("andotp2smith", args, extractAndOTPRecords)
}

// extractAndOTPRecords splits an andOTP backup into its three parts.
//
// The file is nothing but AES-GCM output: a 12-byte nonce, the ciphertext, and
// a 16-byte tag, with no header at all. That means nothing identifies it — any
// file of at least 30 bytes has this shape — so the extractor cannot refuse a
// wrong file and the record cannot be detected by signature. What it does have
// is a real authenticator: GCM's tag makes a wrong password wrong with
// certainty, so a bad extraction fails loudly at crack time rather than
// quietly returning nonsense.
func extractAndOTPRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	const nonce, tag = 12, 16
	if len(data) < nonce+2+tag {
		return nil, errors.New("this file is too short to be an andOTP backup")
	}
	return []string{fmt.Sprintf("$andotp$0*%s*%s*%s",
		hex.EncodeToString(data[:nonce]),
		hex.EncodeToString(data[nonce:len(data)-tag]),
		hex.EncodeToString(data[len(data)-tag:]))}, nil
}

// ── Dashlane vault ────────────────────────────────────────────────────────────

func runExtractDashlane(args []string) error {
	return runFileRecordExtractor("dashlane2smith", args, extractDashlaneRecords)
}

// extractDashlaneRecords reads a Dashlane vault or exported archive.
//
// Two shapes reach the same record. A raw .aes file starts with the salt; an
// exported "secure archive" is base64 on the line after a "Data BEGIN" marker
// and decodes to the same bytes. In both, a four-byte "KWC3" after the salt
// says the payload was compressed before encryption, which changes the
// version field rather than anything the extractor does.
func extractDashlaneRecords(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data := raw
	if i := indexAfterLine(raw, []byte("Data BEGIN")); i >= 0 {
		line := raw[i:]
		if j := indexOfAnyByte(line, "\r\n"); j >= 0 {
			line = line[:j]
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(line)))
		if err != nil {
			return nil, errors.New("the line after \"Data BEGIN\" is not base64")
		}
		data = decoded
	}
	// 256 bytes is what John takes and what the verifier reads; more would
	// only make the record longer.
	if len(data) > 256 {
		data = data[:256]
	}
	if len(data) < 32+16 {
		return nil, errors.New("this file is too short to be a Dashlane vault")
	}
	salt, rest := data[:32], data[32:]
	version := 0
	if len(rest) > 4 && string(rest[:4]) == "KWC3" {
		version, rest = 1, rest[4:]
	}
	return []string{fmt.Sprintf("$dashlane$%d*%s*%d*%s",
		version, hex.EncodeToString(salt), len(rest), hex.EncodeToString(rest))}, nil
}

// indexAfterLine returns the offset just past the line containing marker.
func indexAfterLine(data, marker []byte) int {
	i := strings.Index(string(data), string(marker))
	if i < 0 {
		return -1
	}
	j := strings.IndexByte(string(data[i:]), '\n')
	if j < 0 {
		return -1
	}
	return i + j + 1
}

func indexOfAnyByte(data []byte, set string) int {
	return strings.IndexAny(string(data), set)
}

// ── Padlock ───────────────────────────────────────────────────────────────────

func runExtractPadlock(args []string) error {
	return runFileRecordExtractor("padlock2smith", args, extractPadlockRecords)
}

type padlockContainer struct {
	Cipher     string `json:"cipher"`
	Mode       string `json:"mode"`
	TagLen     int    `json:"ts"`
	Iterations int    `json:"iter"`
	KeySize    int    `json:"keySize"`
	AData      string `json:"adata"`
	IV         string `json:"iv"`
	Salt       string `json:"salt"`
	CT         string `json:"ct"`
}

// extractPadlockRecords reads Padlock's JSON container.
//
// Padlock stores an SJCL object verbatim, so the record is that object's
// fields re-spelled in hex. The three checks below are John's and they are
// worth keeping: anything other than AES-256 in CCM mode is a different
// problem, and passing such a container through would produce a record that
// the verifier reads as AES-CCM and answers wrongly.
func extractPadlockRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c padlockContainer
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, errors.New("this file is not a Padlock JSON container")
	}
	if c.Cipher != "AES" {
		return nil, fmt.Errorf("this container names cipher %q, not AES", c.Cipher)
	}
	if c.Mode != "ccm" {
		return nil, fmt.Errorf("this container names mode %q, not ccm", c.Mode)
	}
	if c.KeySize != 256 {
		return nil, fmt.Errorf("this container names a %d-bit key, not 256", c.KeySize)
	}
	decode := func(name, s string) ([]byte, error) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("Padlock %s is not base64", name)
		}
		return b, nil
	}
	salt, err := decode("salt", c.Salt)
	if err != nil {
		return nil, err
	}
	iv, err := decode("iv", c.IV)
	if err != nil {
		return nil, err
	}
	adata, err := decode("adata", c.AData)
	if err != nil {
		return nil, err
	}
	ct, err := decode("ct", c.CT)
	if err != nil {
		return nil, err
	}
	// An empty vault encrypts the two bytes "[]", which after the tag
	// leaves nothing to distinguish a right password from a wrong one
	// beyond the tag itself. Saying so beats letting a user wonder at the
	// false positives.
	if len(ct)-c.TagLen/8 == 2 {
		fmt.Fprintln(os.Stderr, "note: this Padlock vault is empty, so its ciphertext is the two bytes \"[]\" and false positives are likelier than usual")
	}
	return []string{fmt.Sprintf("$padlock$1$%d$%d$%d$%s$%s$%d$%s$%d$%s",
		c.Iterations, c.TagLen, len(salt), hex.EncodeToString(salt),
		hex.EncodeToString(iv), len(adata), hex.EncodeToString(adata),
		len(ct), hex.EncodeToString(ct))}, nil
}

// ── Enpass ────────────────────────────────────────────────────────────────────

func runExtractEnpass(args []string) error {
	return runFileRecordExtractor("enpass2smith", args, extractEnpassRecords)
}

const (
	enpass6Version    = 1
	enpass6Iterations = 100000
	enpassHeadBytes   = 1024
)

// extractEnpassRecords reads an Enpass 6 database header.
//
// The iteration count is NOT in the file. Enpass 6 fixed it at 100,000 and the
// database records nothing about it, so the count in the record is a constant
// this tool supplies rather than something it read — which is worth knowing,
// because a database written by a version that chose differently will produce
// a record that cannot crack no matter how good the wordlist.
func extractEnpassRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, enpassHeadBytes)
	n, err := io.ReadFull(f, head)
	if err != nil && n < enpassHeadBytes {
		return nil, errors.New("this file is shorter than an Enpass database header")
	}
	return []string{fmt.Sprintf("$enpass$%d$%d$%s",
		enpass6Version, enpass6Iterations, hex.EncodeToString(head))}, nil
}

// ── FreeBSD GELI ──────────────────────────────────────────────────────────────

func runExtractGELI(args []string) error {
	return runFileRecordExtractor("geli2smith", args, extractGELIRecords)
}

const geliMagic = "GEOM::ELI"

// extractGELIRecords reads a GELI provider's metadata block.
//
// The metadata sits in the LAST sector of the provider, not the first, because
// GELI encrypts from byte zero and leaves the tail for itself. Version 0 of the
// layout has no authentication-algorithm field, so every field after it moves
// by two bytes — which is the one place a reader that assumes the current
// layout silently produces a wrong salt rather than an error.
func extractGELIRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	tail := int64(1024)
	if info.Size() < tail {
		return nil, errors.New("this file is too short to hold a GELI metadata block")
	}
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, info.Size()-tail); err != nil {
		return nil, err
	}
	i := strings.Index(string(buf), geliMagic)
	if i < 0 {
		return nil, errors.New("no GELI magic in the last kilobyte of this file")
	}
	md := buf[i:]

	r := &leReader{b: md, pos: 16} // past md_magic
	version, err := r.uint32()
	if err != nil || version > 7 {
		return nil, fmt.Errorf("GELI metadata version %d is not supported", version)
	}
	if _, err := r.uint32(); err != nil { // md_flags
		return nil, err
	}
	ealgo, err := r.uint16()
	if err != nil {
		return nil, err
	}
	const cryptoAESCBC, cryptoAESXTS = 11, 22
	if ealgo != cryptoAESCBC && ealgo != cryptoAESXTS {
		return nil, fmt.Errorf("GELI encryption algorithm %d is not AES", ealgo)
	}
	keyLen, err := r.uint16()
	if err != nil {
		return nil, err
	}
	aalgo := uint16(0)
	if version != 0 {
		if aalgo, err = r.uint16(); err != nil {
			return nil, err
		}
	}
	if err := r.skip(8 + 4); err != nil { // md_provsize, md_sectorsize
		return nil, err
	}
	keys, err := r.byte()
	if err != nil {
		return nil, err
	}
	iterations, err := r.uint32()
	if err != nil {
		return nil, err
	}
	salt, err := r.take(64)
	if err != nil {
		return nil, err
	}
	mkeys, err := r.take(384)
	if err != nil {
		return nil, err
	}
	return []string{fmt.Sprintf("$geli$0$%d$%d$%d$%d$%d$%d$%s$%s",
		version, ealgo, keyLen, aalgo, keys, int32(iterations),
		hex.EncodeToString(salt), hex.EncodeToString(mkeys))}, nil
}

// ── OpenBSD softraid CRYPTO ───────────────────────────────────────────────────

func runExtractOpenBSDSoftraid(args []string) error {
	return runFileRecordExtractor("openbsd_softraid2smith", args, extractOpenBSDSoftraidRecords)
}

const (
	softraidMagic     = "marcCRAM"
	softraidSearch    = 0xaa0 + 81920
	softraidKDFPKCS5  = 1
	softraidKDFBcrypt = 3
)

// extractOpenBSDSoftraidRecords reads a softraid CRYPTO volume header.
//
// Every field here is at a fixed offset inside one struct, so the extractor is
// a list of numbers rather than a parser. The two checks that earn their keep
// are the RAID type and the KDF type: softraid also builds plain RAID volumes
// with the same magic and no password at all, and it supports a bcrypt-PBKDF
// variant alongside PKCS#5 that a record must name, because the two derive
// different keys from the same passphrase.
func extractOpenBSDSoftraidRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, softraidSearch)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	i := strings.Index(string(head), softraidMagic)
	if i < 0 {
		return nil, errors.New("no softraid magic found in this image")
	}
	h := head[i:]
	if len(h) < 2696 {
		return nil, errors.New("the softraid header is truncated")
	}
	if string(h[72:81]) != "SR CRYPTO" {
		return nil, errors.New("this softraid volume is not a CRYPTO volume, so it has no passphrase")
	}
	if h[260] != 1 {
		return nil, errors.New("unexpected softraid optional-header type")
	}
	if h[284] != 2 {
		return nil, errors.New("unexpected softraid encryption type")
	}
	kdf := binary.LittleEndian.Uint32(h[2416:2420])
	if kdf != softraidKDFPKCS5 && kdf != softraidKDFBcrypt {
		return nil, fmt.Errorf("softraid key derivation type %d is not supported", kdf)
	}
	iterations := binary.LittleEndian.Uint32(h[2420:2424])
	return []string{fmt.Sprintf("$openbsd-softraid$%d$%s$%s$%s$%d",
		iterations,
		hex.EncodeToString(h[2424:2552]),
		hex.EncodeToString(h[364:2412]),
		hex.EncodeToString(h[2676:2696]),
		kdf)}, nil
}

// ── FileZilla Server ──────────────────────────────────────────────────────────

func runExtractFileZilla(args []string) error {
	return runFileRecordExtractor("filezilla2smith", args, extractFileZillaRecords)
}

type filezillaServer struct {
	Users []struct {
		Name    string `xml:"Name,attr"`
		Options []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Option"`
	} `xml:"Users>User"`
}

// extractFileZillaRecords reads FileZilla Server's user database.
//
// FileZilla changed hashes mid-life without changing the file: an old server
// stores a bare MD5 of the password and a newer one stores SHA-512 of password
// then salt. Nothing names which; the digest's LENGTH is the only signal, so
// that is what decides. Both come out as dynamic expressions rather than
// formats of their own, and the salt goes in as hex because FileZilla's salts
// are printable junk that may contain a colon.
func extractFileZillaRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var doc filezillaServer
	if err := xml.NewDecoder(f).Decode(&doc); err != nil {
		return nil, errors.New("this file is not a FileZilla Server XML configuration")
	}
	var records []string
	for _, u := range doc.Users {
		var digest, salt string
		for _, o := range u.Options {
			switch o.Name {
			case "Pass":
				digest = strings.ToLower(strings.TrimSpace(o.Value))
			case "Salt":
				salt = o.Value
			}
		}
		switch {
		case len(digest) == 32 && salt == "" && isHex(digest):
			records = append(records, "$dynamic_0$"+digest)
		case len(digest) == 128 && salt != "" && isHex(digest):
			records = append(records, "$dynamic_82$"+digest+"$HEX$"+
				hex.EncodeToString([]byte(salt)))
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no FileZilla user with a stored password was found")
	}
	return records, nil
}

// ── McAfee ePolicy Orchestrator ───────────────────────────────────────────────

func runExtractMcAfeeEPO(args []string) error {
	return runFileRecordExtractor("mcafee_epo2smith", args, extractMcAfeeEPORecords)
}

const mcafeeEPOPrefix = "auth:pwd?pwd="

// extractMcAfeeEPORecords reads an ePO OrionUsers export.
//
// The stored value is a URL-encoded base64 blob of exactly 24 bytes: a 20-byte
// SHA-1 followed by a four-byte seed. The seed comes AFTER the digest in the
// blob and BEFORE the password in the hash, which is the one thing to get
// right here — the record is sha1($salt.$pass) with the salt read off the end.
func extractMcAfeeEPORecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(strings.TrimSpace(s.Text()), ",")
		if len(fields) < 2 || !strings.HasPrefix(fields[1], mcafeeEPOPrefix) {
			continue
		}
		unescaped, err := url.QueryUnescape(strings.TrimPrefix(fields[1], mcafeeEPOPrefix))
		if err != nil {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(unescaped)
		if err != nil || len(blob) != 24 {
			continue
		}
		records = append(records, fmt.Sprintf("$dynamic_24$%s$HEX$%s",
			hex.EncodeToString(blob[:20]), hex.EncodeToString(blob[20:])))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no ePO password blobs found in this export")
	}
	return records, nil
}

// ── StarOffice / OpenOffice documents ─────────────────────────────────────────

func runExtractStarOffice(args []string) error {
	return runFileRecordExtractor("staroffice2smith", args, extractStarOfficeRecords)
}

// extractStarOfficeRecords reads an encrypted StarOffice or OpenOffice 1.x
// document.
//
// The document is a ZIP whose META-INF/manifest.xml carries the salt, the IV
// and a checksum over the DECRYPTED content — so everything needed to check a
// password is in the manifest, in the clear, and the ciphertext is only there
// to be checksummed.
//
// Two numbers in the record are not the same number and the difference is the
// whole reason this format has both. The content is encrypted in whole
// Blowfish blocks, so the stored stream is padded; the checksum is over the
// UNPADDED length. A record that wrote one value twice would fail on every
// document whose content is not a multiple of eight bytes.
func extractStarOfficeRecords(path string) ([]string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, errors.New("this file is not a ZIP, so it is not a StarOffice document")
	}
	defer zr.Close()

	var manifest, content *zip.File
	for _, f := range zr.File {
		switch f.Name {
		case "META-INF/manifest.xml":
			manifest = f
		case "content.xml":
			content = f
		}
	}
	if manifest == nil || content == nil {
		return nil, errors.New("this ZIP has no META-INF/manifest.xml and content.xml pair")
	}

	mf, err := manifest.Open()
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	// The manifest's encryption data is nested inside the file-entry for
	// content.xml, so the decoder walks tokens rather than unmarshalling a
	// struct: it has to know WHICH entry it is inside when it meets the
	// checksum.
	var checksum, iv, salt, iterations string
	dec := xml.NewDecoder(mf)
	inTarget := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("META-INF/manifest.xml is not well-formed XML")
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			if end, ok := tok.(xml.EndElement); ok && end.Name.Local == "file-entry" {
				inTarget = false
			}
			continue
		}
		attr := func(name string) string {
			for _, a := range start.Attr {
				if a.Name.Local == name {
					return a.Value
				}
			}
			return ""
		}
		switch start.Name.Local {
		case "file-entry":
			inTarget = attr("full-path") == "content.xml"
		case "encryption-data":
			if inTarget {
				checksum = attr("checksum")
			}
		case "algorithm":
			if inTarget {
				iv = attr("initialisation-vector")
			}
		case "key-derivation":
			if inTarget {
				salt = attr("salt")
				iterations = attr("iteration-count")
			}
		}
	}
	if checksum == "" || iv == "" || salt == "" || iterations == "" {
		return nil, errors.New("this document is not encrypted: its manifest carries no checksum, IV and salt for content.xml")
	}

	unb64 := func(name, s string) ([]byte, error) {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("the manifest's %s is not base64", name)
		}
		return b, nil
	}
	checksumBytes, err := unb64("checksum", checksum)
	if err != nil {
		return nil, err
	}
	ivBytes, err := unb64("initialisation vector", iv)
	if err != nil {
		return nil, err
	}
	saltBytes, err := unb64("salt", salt)
	if err != nil {
		return nil, err
	}

	cf, err := content.Open()
	if err != nil {
		return nil, err
	}
	defer cf.Close()
	stream, err := io.ReadAll(io.LimitReader(cf, 1024))
	if err != nil {
		return nil, err
	}
	if len(stream) == 0 {
		return nil, errors.New("content.xml is empty")
	}

	// original is what the checksum covers; padded is what is stored.
	original := len(stream)
	padded := original
	if original < 1024 {
		if pad := original % 8; pad > 0 {
			stream = append(stream, []byte("00000000")[:pad]...)
			padded = len(stream)
		}
	}
	return []string{fmt.Sprintf("$sxc$*0*0*%s*16*%s*%d*%s*%d*%s*%d*%d*%s",
		iterations, hex.EncodeToString(checksumBytes),
		len(ivBytes), hex.EncodeToString(ivBytes),
		len(saltBytes), hex.EncodeToString(saltBytes),
		original, padded, hex.EncodeToString(stream))}, nil
}

// ── A little-endian reader ────────────────────────────────────────────────────

// leReader is byteReader's counterpart for the structures a C program wrote
// with no byte-order conversion, which on every platform GELI and softraid run
// on means little-endian.
type leReader struct {
	b   []byte
	pos int
}

func (r *leReader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *leReader) skip(n int) error {
	_, err := r.take(n)
	return err
}

func (r *leReader) byte() (byte, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *leReader) uint16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *leReader) uint32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
