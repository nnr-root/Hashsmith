package main

// Extractors for key stores, wallets and credential files — the containers a
// verifier here can already crack but that no *2smith could read out of the
// file a user actually holds.
//
// The gap analysis calls this John's real moat, and it is: a format nobody can
// convert into a record is a format nobody cracks, however good the verifier
// behind it is. Each of these mirrors a John converter and emits the same
// record syntax, so a record from either tool works in both.

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ── Java KeyStore (.jks) ──────────────────────────────────────────────────────

func runExtractKeystore(args []string) error {
	return runFileRecordExtractor("keystore2smith", args, extractKeystoreRecords)
}

const (
	jksMagic       = 0xfeedfeed
	jksEntryKey    = 1
	jksEntryTrust  = 2
	jksMaxEntries  = 1 << 16
	jksDigestBytes = 20
)

// extractKeystoreRecords walks a JKS file to find where the store body ends.
//
// The whole point of the walk is that offset. A keystore's password is checked
// by a SHA-1 over the password, a fixed whitener and EVERY byte of the body,
// with the trailing twenty-byte digest excluded — so a record needs to know
// exactly where the body stops, and nothing in the header says. The only way
// to find it is to parse each entry to its end, which means reading structures
// whose contents are irrelevant: certificates, chains, timestamps. They are
// skipped here, not decoded, but they still have to be walked.
func extractKeystoreRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := &byteReader{b: data}
	magic, err := r.uint32()
	if err != nil || magic != jksMagic {
		return nil, errors.New("not a Java keystore: the magic number is not 0xfeedfeed")
	}
	version, err := r.uint32()
	if err != nil || (version != 1 && version != 2) {
		return nil, errors.New("unsupported Java keystore version")
	}
	count, err := r.uint32()
	if err != nil || count > jksMaxEntries {
		return nil, errors.New("Java keystore entry count is implausible")
	}

	type jksKey struct {
		alias string
		blob  []byte
	}
	var keys []jksKey
	for i := uint32(0); i < count; i++ {
		tag, err := r.uint32()
		if err != nil {
			break
		}
		switch tag {
		case jksEntryKey:
			alias, err := r.utf()
			if err != nil {
				return nil, err
			}
			if err := r.skip(8); err != nil { // creation timestamp
				return nil, err
			}
			blob, err := r.blob32()
			if err != nil {
				return nil, err
			}
			chain, err := r.uint32()
			if err != nil || chain > jksMaxEntries {
				return nil, errors.New("Java keystore certificate chain is implausible")
			}
			for j := uint32(0); j < chain; j++ {
				// Version 2 names each certificate's type; version 1
				// does not, and reading the name anyway would consume
				// the first two bytes of the certificate.
				if version == 2 {
					if _, err := r.utf(); err != nil {
						return nil, err
					}
				}
				if _, err := r.blob32(); err != nil {
					return nil, err
				}
			}
			keys = append(keys, jksKey{alias: alias, blob: blob})
		case jksEntryTrust:
			if _, err := r.utf(); err != nil {
				return nil, err
			}
			if err := r.skip(8); err != nil {
				return nil, err
			}
			if version == 2 {
				if _, err := r.utf(); err != nil {
					return nil, err
				}
			}
			if _, err := r.blob32(); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unrecognised Java keystore entry type %d", tag)
		}
	}

	end := r.pos
	if end+jksDigestBytes > len(data) {
		return nil, errors.New("Java keystore ends before its digest")
	}
	digest := data[end : end+jksDigestBytes]

	keyCount, keySize, keyData := 0, 0, ""
	if len(keys) > 0 {
		keyCount, keySize = 1, len(keys[0].blob)
		keyData = hex.EncodeToString(keys[0].blob)
	}
	// Only the store password (target 0) is emitted. John also writes a
	// record per private key (target 1), which is a DIFFERENT password
	// checked a different way; emitting one here would hand back a record
	// no verifier in this tool answers.
	return []string{fmt.Sprintf("$keystore$0$%d$%s$%s$%d$%d$%s",
		end, hex.EncodeToString(data[:end]), hex.EncodeToString(digest),
		keyCount, keySize, keyData)}, nil
}

// ── Bouncy Castle keystore (.bks, .uber) ──────────────────────────────────────

func runExtractBKS(args []string) error {
	return runFileRecordExtractor("bks2smith", args, extractBKSRecords)
}

// extractBKSRecords reads both Bouncy Castle store shapes.
//
// BKS keeps its entries in the clear and MACs them; UBER encrypts the whole
// store and has no MAC at all, so the two records differ in what the trailing
// field means — a real HMAC for BKS, twenty zero bytes for UBER, where the
// check is instead that the decrypted store ends in its own SHA-1.
func extractBKSRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if rec, err := extractBKSStore(data); err == nil {
		return []string{rec}, nil
	}
	rec, err := extractUBERStore(data)
	if err != nil {
		return nil, errors.New("not a Bouncy Castle keystore in either the BKS or the UBER shape")
	}
	return []string{rec}, nil
}

func extractBKSStore(data []byte) (string, error) {
	r := &byteReader{b: data}
	version, err := r.uint32()
	if err != nil || (version != 1 && version != 2) {
		return "", errors.New("unsupported BKS version")
	}
	salt, err := r.blob32()
	if err != nil || len(salt) == 0 || len(salt) > 256 {
		return "", errors.New("implausible BKS salt")
	}
	iterations, err := r.uint32()
	if err != nil || iterations == 0 || iterations > 1<<24 {
		return "", errors.New("implausible BKS iteration count")
	}

	start := r.pos
	for r.pos < len(data) {
		entry, err := r.byte()
		if err != nil {
			return "", err
		}
		if entry == 0 {
			break
		}
		if _, err := r.utf(); err != nil { // alias
			return "", err
		}
		if err := r.skip(8); err != nil { // creation timestamp
			return "", err
		}
		chain, err := r.uint32()
		if err != nil || chain > jksMaxEntries {
			return "", errors.New("implausible BKS certificate chain")
		}
		for j := uint32(0); j < chain; j++ {
			if _, err := r.utf(); err != nil {
				return "", err
			}
			if _, err := r.blob32(); err != nil {
				return "", err
			}
		}
		switch entry {
		case 1: // certificate
			if _, err := r.utf(); err != nil {
				return "", err
			}
			if _, err := r.blob32(); err != nil {
				return "", err
			}
		case 2: // key
			if err := r.skip(1); err != nil { // key type
				return "", err
			}
			if _, err := r.utf(); err != nil { // format
				return "", err
			}
			if _, err := r.utf(); err != nil { // algorithm
				return "", err
			}
			if _, err := r.blob32(); err != nil { // encoded key
				return "", err
			}
		case 3: // secret key
			if _, err := r.blob32(); err != nil {
				return "", err
			}
		case 4: // sealed object
			if _, err := r.blob32(); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("unrecognised BKS entry type %d", entry)
		}
	}
	end := r.pos
	if end+jksDigestBytes > len(data) {
		return "", errors.New("BKS store ends before its MAC")
	}

	// Version 1 states the MAC key size in BYTES and version 2 in BITS, for
	// the same twenty-byte SHA-1 key. The record carries whichever the file
	// meant, because the derivation reads it as given.
	macKeySize := jksDigestBytes
	if version != 1 {
		macKeySize *= 8
	}
	return fmt.Sprintf("$bks$0$%d$%d$%d$%d$%s$%s$%s",
		version, macKeySize, iterations, len(salt), hex.EncodeToString(salt),
		hex.EncodeToString(data[start:end]),
		hex.EncodeToString(data[end:end+jksDigestBytes])), nil
}

func extractUBERStore(data []byte) (string, error) {
	r := &byteReader{b: data}
	version, err := r.uint32()
	if err != nil || version != 1 {
		return "", errors.New("unsupported UBER version")
	}
	salt, err := r.blob32()
	if err != nil || len(salt) == 0 || len(salt) > 256 {
		return "", errors.New("implausible UBER salt")
	}
	iterations, err := r.uint32()
	if err != nil || iterations == 0 || iterations > 1<<24 {
		return "", errors.New("implausible UBER iteration count")
	}
	store := data[r.pos:]
	if len(store) == 0 {
		return "", errors.New("UBER store carries no encrypted data")
	}
	return fmt.Sprintf("$bks$1$%d$%d$%d$%d$%s$%s$%s",
		version, jksDigestBytes, iterations, len(salt), hex.EncodeToString(salt),
		hex.EncodeToString(store), strings.Repeat("00", jksDigestBytes)), nil
}

// ── GNOME Keyring ─────────────────────────────────────────────────────────────

func runExtractKeyring(args []string) error {
	return runFileRecordExtractor("keyring2smith", args, extractKeyringRecords)
}

const gnomeKeyringMagic = "GnomeKeyring\n\r\x00\n"

// extractKeyringRecords reads a GNOME Keyring file's header.
//
// Only sixteen bytes of ciphertext are needed and only sixteen are taken. The
// encrypted region begins with an MD5 over everything that follows it, so with
// nothing following, a correct password is one whose key decrypts those
// sixteen bytes to the MD5 of the empty string. That is a full 128-bit check
// on a sixteen-byte record, which is why John's converter stops here too.
func extractKeyringRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(data), gnomeKeyringMagic) {
		return nil, errors.New("not a GNOME Keyring file")
	}
	r := &byteReader{b: data, pos: len(gnomeKeyringMagic)}
	if err := r.skip(2 + 1 + 1); err != nil { // version, crypto, hash
		return nil, err
	}
	nameLen, err := r.uint32()
	if err != nil || nameLen > 1<<16 {
		return nil, errors.New("implausible GNOME Keyring name length")
	}
	if err := r.skip(int(nameLen) + 8 + 8 + 4 + 4); err != nil { // name, ctime, mtime, flags, timeout
		return nil, errors.New("truncated GNOME Keyring header")
	}
	iterations, err := r.uint32()
	if err != nil || iterations == 0 || iterations > 1<<22 {
		return nil, errors.New("implausible GNOME Keyring iteration count")
	}
	salt, err := r.take(8)
	if err != nil {
		return nil, errors.New("truncated GNOME Keyring salt")
	}
	if err := r.skip(16 + 8); err != nil { // reserved, item count
		return nil, errors.New("truncated GNOME Keyring header")
	}
	ct, err := r.take(16)
	if err != nil {
		return nil, errors.New("GNOME Keyring file carries no encrypted data")
	}
	return []string{fmt.Sprintf("$keyring$%s*%d*%d*0*%s",
		hex.EncodeToString(salt), iterations, len(ct), hex.EncodeToString(ct))}, nil
}

// ── KDE KWallet ───────────────────────────────────────────────────────────────

func runExtractKWallet(args []string) error {
	return runFileRecordExtractor("kwallet2smith", args, extractKWalletRecords)
}

const (
	kwalletMagic = "KWALLET\n\r\x00\r\n"
	// kwalletPBKDF2Iterations is what KDE 4.13 and later use. It is not in
	// the wallet file: the file says only which hash was chosen, and the
	// count is a constant in KWallet's source.
	kwalletPBKDF2Iterations = 50000
	kwalletPrefixBytes      = 65
)

// extractKWalletRecords reads a .kwl wallet.
//
// A salted wallet keeps its salt in a SEPARATE file beside it, <name>.salt,
// which is why an extractor that only reads the wallet cannot produce a usable
// record for one. The sibling is looked for and its absence reported plainly
// rather than by emitting a saltless record that would never crack.
func extractKWalletRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(data), kwalletMagic) {
		return nil, errors.New("not a KDE KWallet file")
	}
	r := &byteReader{b: data, pos: len(kwalletMagic)}
	header, err := r.take(4)
	if err != nil {
		return nil, errors.New("truncated KWallet header")
	}
	major, minor, cipher, hashID := header[0], header[1], header[2], header[3]
	if major != 0 {
		return nil, fmt.Errorf("unknown KWallet major version %d", major)
	}
	if minor > 1 {
		return nil, fmt.Errorf("unknown KWallet minor version %d", minor)
	}
	// 0 is Blowfish-ECB under its old name and 3 is Blowfish-CBC; the 3DES
	// and GPG ciphers in between are not password-derived the same way.
	if cipher != 0 && cipher != 3 {
		return nil, fmt.Errorf("unsupported KWallet cipher %d", cipher)
	}
	if hashID != 0 && hashID != 2 {
		return nil, fmt.Errorf("unsupported KWallet hash %d", hashID)
	}

	folders, err := r.uint32()
	if err != nil || folders > 0xffff {
		return nil, errors.New("implausible KWallet folder count")
	}
	for i := uint32(0); i < folders; i++ {
		if err := r.skip(16); err != nil { // folder name hash
			return nil, errors.New("truncated KWallet folder table")
		}
		entries, err := r.uint32()
		if err != nil || entries > 1<<20 {
			return nil, errors.New("implausible KWallet entry count")
		}
		if err := r.skip(int(entries) * 16); err != nil {
			return nil, errors.New("truncated KWallet entry table")
		}
	}

	encrypted := data[r.pos:]
	if len(encrypted)%8 != 0 || len(encrypted) < 88 {
		return nil, errors.New("KWallet encrypted region is too short or not whole Blowfish blocks")
	}
	// The record carries the length of the WHOLE encrypted region — the
	// verifier needs it to know how much the wallet claims — but only the
	// leading bytes, because the check reads the first sixty-four.
	head := hex.EncodeToString(encrypted[:kwalletPrefixBytes])

	if minor == 0 {
		return []string{fmt.Sprintf("$kwallet$%d$%s", len(encrypted), head)}, nil
	}

	saltPath := strings.TrimSuffix(path, filepath.Ext(path)) + ".salt"
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		return nil, fmt.Errorf("this wallet is salted and its salt lives in %s, which could not be read: %w",
			filepath.Base(saltPath), err)
	}
	if len(salt) == 0 || len(salt) > 256 {
		return nil, errors.New("implausible KWallet salt file")
	}
	return []string{fmt.Sprintf("$kwallet$%d$%s$%d$%d$%s$%d",
		len(encrypted), head, minor, len(salt), hex.EncodeToString(salt),
		kwalletPBKDF2Iterations)}, nil
}

// ── OpenSSH known_hosts ───────────────────────────────────────────────────────

func runExtractKnownHosts(args []string) error {
	return runFileRecordExtractor("known_hosts2smith", args, extractKnownHostsRecords)
}

// extractKnownHostsRecords pulls the hashed host entries out of a known_hosts
// file.
//
// The thing being cracked here is not a password: it is the HOSTNAME. OpenSSH
// hashes host names so that a stolen known_hosts does not hand an attacker the
// list of machines its owner reaches, and an entry beginning "|1|" is such a
// hash. Entries that are NOT hashed are already the answer, so they are
// skipped rather than emitted — there is nothing to crack.
func extractKnownHostsRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, _, ok := strings.Cut(line, " ")
		if !ok || !strings.HasPrefix(host, "|1|") {
			continue
		}
		records = append(records, "$known_hosts$"+host)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("this known_hosts file holds no hashed entries; its host names are already in the clear")
	}
	return records, nil
}

// ── Apache htdigest ───────────────────────────────────────────────────────────

func runExtractHtdigest(args []string) error {
	return runFileRecordExtractor("htdigest2smith", args, extractHtdigestRecords)
}

// extractHtdigestRecords converts an htdigest file.
//
// Each line is user:realm:MD5(user:realm:password), which is md5($salt.$pass)
// with the salt spelled out — so the record is a dynamic expression rather
// than a format of its own. The salt goes in as HEX because a realm may hold
// a colon or a dollar sign, either of which would otherwise be read as
// structure.
func extractHtdigestRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimRight(s.Text(), "\r\n")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 || len(parts[2]) != 32 || !isHex(parts[2]) {
			continue
		}
		salt := parts[0] + ":" + parts[1] + ":"
		records = append(records, fmt.Sprintf("$dynamic_4$%s$HEX$%s",
			strings.ToLower(parts[2]), hex.EncodeToString([]byte(salt))))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no htdigest entries found")
	}
	return records, nil
}

// ── PuTTY private keys (.ppk) ─────────────────────────────────────────────────

func runExtractPutty(args []string) error {
	return runFileRecordExtractor("putty2smith", args, extractPuttyRecords)
}

// extractPuttyRecords reads a PPK version 2 file.
//
// Version 1 is refused because its record has no algorithm, cipher or comment
// field and the verifier needs all three to rebuild the MAC. Version 3 is
// refused for a better reason: it replaced PuTTY's unsalted double SHA-1 with
// Argon2, which is a real key derivation, and a record claiming otherwise
// would be answered wrongly rather than not at all.
func extractPuttyRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	headers, body, err := readPuttyFields(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	algorithm, ok := headers["PuTTY-User-Key-File-2"]
	if !ok {
		if _, three := headers["PuTTY-User-Key-File-3"]; three {
			return nil, errors.New("this is a PPK version 3 key, which derives its key with Argon2 rather than PuTTY's old SHA-1 pair; that format is not yet read here")
		}
		if _, one := headers["PuTTY-User-Key-File-1"]; one {
			return nil, errors.New("this is a PPK version 1 key, which carries no algorithm or comment field for the MAC to cover")
		}
		return nil, errors.New("not a PuTTY private key file")
	}
	encryption := headers["Encryption"]
	if encryption != "aes256-cbc" {
		return nil, fmt.Errorf("this key names encryption %q, so it has no passphrase to find", encryption)
	}
	mac, ok := headers["Private-MAC"]
	if !ok || len(mac) != 40 || !isHex(mac) {
		return nil, errors.New("this PPK file carries no Private-MAC line")
	}
	public, ok := body["Public-Lines"]
	if !ok {
		return nil, errors.New("this PPK file carries no public blob")
	}
	private, ok := body["Private-Lines"]
	if !ok {
		return nil, errors.New("this PPK file carries no private blob")
	}
	comment := headers["Comment"]

	// The first four fields are the cipher (1 for aes256-cbc), its block
	// size, whether the file MACs rather than hashes, and whether it is the
	// old format. They are fixed for a version 2 encrypted key and the
	// verifier ignores them, but the record's shape is John's and keeping
	// them means a record works in either tool.
	return []string{fmt.Sprintf("$putty$1*16*1*0*%s*%d*%s*%d*%s*%s*%s*%s",
		strings.ToLower(mac),
		len(public), hex.EncodeToString(public),
		len(private), hex.EncodeToString(private),
		algorithm, encryption, comment)}, nil
}

// readPuttyFields splits a PPK into its "Key: value" headers and the two
// base64 blocks, each introduced by a line giving how many lines it spans.
func readPuttyFields(r *bufio.Reader) (map[string]string, map[string][]byte, error) {
	headers := map[string]string{}
	blocks := map[string][]byte{}
	for {
		line, err := r.ReadString('\n')
		if line == "" && err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			if err != nil {
				break
			}
			continue
		}
		if !strings.HasSuffix(key, "-Lines") {
			headers[key] = value
			if err != nil {
				break
			}
			continue
		}
		n, convErr := strconv.Atoi(value)
		if convErr != nil || n < 0 || n > 1<<16 {
			return nil, nil, fmt.Errorf("implausible %s count in this PPK file", key)
		}
		var b64 strings.Builder
		for i := 0; i < n; i++ {
			l, lerr := r.ReadString('\n')
			b64.WriteString(strings.TrimRight(l, "\r\n"))
			if lerr != nil && i < n-1 {
				return nil, nil, io.ErrUnexpectedEOF
			}
		}
		raw, decErr := base64.StdEncoding.DecodeString(b64.String())
		if decErr != nil {
			return nil, nil, fmt.Errorf("the %s block is not valid base64", key)
		}
		blocks[key] = raw
		if err != nil {
			break
		}
	}
	if len(headers) == 0 {
		return nil, nil, errors.New("this file has no PPK headers")
	}
	return headers, blocks, nil
}

// ── A reader for length-prefixed Java structures ──────────────────────────────

// byteReader walks a buffer the way Java's DataInputStream does: big-endian
// throughout, with strings written as a two-byte length and blobs as four.
// Every method reports rather than panics, because these buffers are files
// someone else wrote and a truncated one must produce an error, not a crash.
type byteReader struct {
	b   []byte
	pos int
}

func (r *byteReader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *byteReader) skip(n int) error {
	_, err := r.take(n)
	return err
}

func (r *byteReader) byte() (byte, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *byteReader) uint32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *byteReader) utf() (string, error) {
	b, err := r.take(2)
	if err != nil {
		return "", err
	}
	s, err := r.take(int(binary.BigEndian.Uint16(b)))
	if err != nil {
		return "", err
	}
	return string(s), nil
}

func (r *byteReader) blob32() ([]byte, error) {
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if n > uint32(len(r.b)) {
		return nil, io.ErrUnexpectedEOF
	}
	return r.take(int(n))
}
