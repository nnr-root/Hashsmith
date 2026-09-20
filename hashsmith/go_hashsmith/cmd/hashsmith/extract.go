package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
)

// ── ZIP constants ────────────────────────────────────────────────────────────

const (
	zipLocalSig uint32 = 0x04034b50 // "PK\x03\x04"
	aesExtraID  uint16 = 0x9901     // WinZip AES extra-field header ID
)

// zipCRC32Tab is the IEEE CRC-32 table used by the ZipCrypto key schedule.
// It is the same polynomial used in standard ZIP CRC-32 checksums.
var zipCRC32Tab = crc32.MakeTable(crc32.IEEE)

// ── Local file header (fixed portion, after the 4-byte signature) ────────────

type localFileHeader struct {
	VersionNeeded    uint16
	Flags            uint16
	ComprMethod      uint16
	ModTime          uint16
	ModDate          uint16
	CRC32            uint32
	CompressedSize   uint32
	UncompressedSize uint32
	FilenameLen      uint16
	ExtraLen         uint16
}

// ── AES extra-field descriptor ───────────────────────────────────────────────

type aesExtraField struct {
	VendorVersion uint16
	VendorID      [2]byte
	Strength      uint8  // 1=AES-128, 2=AES-192, 3=AES-256
	ComprMethod   uint16 // actual compression method (method field is 99 for AES)
}

// ── Result type ──────────────────────────────────────────────────────────────

// zipHashResult carries everything the crack module needs.
type zipHashResult struct {
	hashType string // "zipcrypto" | "zipaes128" | "zipaes192" | "zipaes256"
	hash     string // Hashsmith-format hash string
	filename string // name of the encrypted file inside the ZIP
	encLabel string // human-readable encryption label
}

// ── CLI entry ─────────────────────────────────────────────────────────────────

func runExtractHash(args []string) error {
	fs := flag.NewFlagSet("extract-hash", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "ZIP file path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *filePath == "" {
		return errors.New("extract-hash requires -f <zip-file>")
	}
	res, err := extractZipHash(*filePath)
	if err != nil {
		return err
	}
	printExtractResult(res)
	return outputResult(res.hash, *outFile, *copyRes)
}

// ── Public extraction API ─────────────────────────────────────────────────────

// extractZipHash opens a ZIP file, finds the first encrypted entry, and
// returns a Hashsmith-compatible hash string ready for the crack module.
func extractZipHash(path string) (*zipHashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", path, err)
	}
	defer f.Close()
	return scanForEncryptedEntry(f)
}

func printExtractResult(res *zipHashResult) {
	acFn := accentSprint
	fmt.Fprintf(os.Stderr, "\n%s %s\n", acFn("File:      "), res.filename)
	fmt.Fprintf(os.Stderr, "%s %s\n", acFn("Encryption:"), res.encLabel)
	fmt.Fprintf(os.Stderr, "%s %s\n\n", acFn("Hash:      "), res.hash)
}

// ── Binary ZIP parser ─────────────────────────────────────────────────────────

// scanForEncryptedEntry reads sequential local file headers until it finds
// one that has the encrypted flag set, then extracts the hash metadata.
func scanForEncryptedEntry(r io.ReadSeeker) (*zipHashResult, error) {
	sigBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, sigBuf); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, err
		}

		if binary.LittleEndian.Uint32(sigBuf) != zipLocalSig {
			// Slide one byte forward and retry (handles self-extracting archives).
			if _, err := r.Seek(-3, io.SeekCurrent); err != nil {
				return nil, err
			}
			continue
		}

		// Read the 26 fixed bytes of the local file header.
		var lh localFileHeader
		if err := binary.Read(r, binary.LittleEndian, &lh); err != nil {
			return nil, fmt.Errorf("truncated local file header: %w", err)
		}

		filename := make([]byte, lh.FilenameLen)
		if _, err := io.ReadFull(r, filename); err != nil {
			return nil, fmt.Errorf("truncated filename field: %w", err)
		}

		extra := make([]byte, lh.ExtraLen)
		if _, err := io.ReadFull(r, extra); err != nil {
			return nil, fmt.Errorf("truncated extra field: %w", err)
		}

		if lh.Flags&0x01 == 0 {
			// Not encrypted — skip compressed data and try the next entry.
			if _, err := r.Seek(int64(lh.CompressedSize), io.SeekCurrent); err != nil {
				return nil, err
			}
			continue
		}

		fname := strings.TrimRight(string(filename), "\x00")

		// WinZip AES?
		if ae := findAESExtra(extra); ae != nil {
			return parseWinZipAES(r, fname, ae, lh)
		}

		// Fall through to ZipCrypto.
		return parseZipCrypto(r, lh, fname)
	}
	return nil, errors.New("no encrypted entries found in ZIP file")
}

// findAESExtra scans the extra-field blob for a WinZip AES descriptor (0x9901).
func findAESExtra(extra []byte) *aesExtraField {
	for i := 0; i+4 <= len(extra); {
		hdrID := binary.LittleEndian.Uint16(extra[i:])
		dataSize := int(binary.LittleEndian.Uint16(extra[i+2:]))
		i += 4
		if i+dataSize > len(extra) {
			break
		}
		if hdrID == aesExtraID && dataSize == 7 {
			ae := &aesExtraField{}
			ae.VendorVersion = binary.LittleEndian.Uint16(extra[i:])
			ae.VendorID[0] = extra[i+2]
			ae.VendorID[1] = extra[i+3]
			ae.Strength = extra[i+4]
			ae.ComprMethod = binary.LittleEndian.Uint16(extra[i+5:])
			return ae
		}
		i += dataSize
	}
	return nil
}

// aesKeySaltLen returns (keyLen, saltLen) for a WinZip AES strength value.
func aesKeySaltLen(strength uint8) (keyLen, saltLen int, err error) {
	switch strength {
	case 1:
		return 16, 8, nil // AES-128
	case 2:
		return 24, 12, nil // AES-192
	case 3:
		return 32, 16, nil // AES-256
	}
	return 0, 0, fmt.Errorf("unknown WinZip AES strength %d (want 1/2/3)", strength)
}

// parseWinZipAES reads the AES salt + verifier bytes from the start of the
// encrypted data stream and builds the Hashsmith hash string.
//
// WinZip AES data layout (RFC / APPNOTE §7.2):
//
//	[salt_length bytes] [2 bytes password verifier] [encrypted payload] [10 bytes HMAC-SHA1]
//
// maxWinZipEmbeddedData bounds how much ciphertext goes into a record. The
// record is a line in a hash file, and a WinZip entry can be gigabytes.
const maxWinZipEmbeddedData = 1 << 20

// maxZipCryptoEmbeddedData bounds the ZipCrypto payload a record carries, for
// the same reason: the record is a line in a hash file and a ZIP entry can be
// gigabytes.
const maxZipCryptoEmbeddedData = 1 << 20

// parseWinZipAES reads a WinZip AES entry and builds the strongest record the
// entry actually supports.
//
// The entry's encrypted blob is laid out as
//
//	[salt] [2-byte password verifier] [ciphertext] [10-byte authentication code]
//
// and the short $zipaes<bits>$ record keeps only the first two of those. That
// is enough to attack and not enough to be sure: the verifier is two bytes, so
// one wrong password in 65,536 passes it. Over a rockyou-sized run that is
// thousands of reported passwords that do not open the archive, and the user
// has no way to tell which.
//
// So when the entry's size is known and its ciphertext is small enough to
// carry, the record written is zip2john's $zip2$ form, which includes the
// authentication code — ten bytes of HMAC-SHA1 over the ciphertext, taking the
// false-accept rate to one in 2^80. That record is also what hashcat reads as
// -m 13600, so it travels.
//
// Two cases fall back to the short form, and both say so rather than failing:
// an entry whose local header declares no size (bit 3 of the flags puts the
// sizes in a trailing data descriptor instead) and an entry too large to
// embed.
func parseWinZipAES(r io.Reader, filename string, ae *aesExtraField, lh localFileHeader) (*zipHashResult, error) {
	keyLen, saltLen, err := aesKeySaltLen(ae.Strength)
	_ = keyLen
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("cannot read AES salt: %w", err)
	}

	verif := make([]byte, 2)
	if _, err := io.ReadFull(r, verif); err != nil {
		return nil, fmt.Errorf("cannot read AES password verifier: %w", err)
	}

	bits := int(ae.Strength)*64 + 64 // 1→128, 2→192, 3→256

	// overhead is everything in the blob that is not ciphertext.
	//
	// The arithmetic is int64 because CompressedSize is a uint32 that reaches
	// 4 GiB, which overflows a 32-bit int — and 0xFFFFFFFF is ZIP64's "the
	// real size is in the extra field" sentinel, which would then read as a
	// negative length. At int64 it simply exceeds the embedding cap and falls
	// through to the short form, which is the right answer for a ZIP64 entry
	// anyway.
	overhead := int64(saltLen) + 2 + 10
	sizeKnown := lh.Flags&0x08 == 0 && int64(lh.CompressedSize) >= overhead
	if sizeKnown {
		dataLen := int64(lh.CompressedSize) - overhead
		if dataLen <= maxWinZipEmbeddedData {
			data := make([]byte, dataLen)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("cannot read AES ciphertext: %w", err)
			}
			auth := make([]byte, 10)
			if _, err := io.ReadFull(r, auth); err != nil {
				return nil, fmt.Errorf("cannot read AES authentication code: %w", err)
			}
			hash := fmt.Sprintf("$zip2$*0*%d*0*%s*%s*%x*%s*%s*$/zip2$",
				ae.Strength,
				hex.EncodeToString(salt),
				hex.EncodeToString(verif),
				dataLen,
				hex.EncodeToString(data),
				hex.EncodeToString(auth))
			return &zipHashResult{
				hashType: "winzip",
				hash:     hash,
				filename: filename,
				encLabel: fmt.Sprintf("WinZip AES-%d (authentication-code checked, hashcat -m 13600)", bits),
			}, nil
		}
	}

	hashType := fmt.Sprintf("zipaes%d", bits)
	hash := fmt.Sprintf("$%s$%s$%s",
		hashType,
		hex.EncodeToString(salt),
		hex.EncodeToString(verif))
	why := "its entry is larger than this record can carry"
	if !sizeKnown {
		why = "its local header declares no size"
	}
	label := fmt.Sprintf("WinZip AES-%d (password-verifier only, because %s — "+
		"roughly 1 wrong password in 65,536 will be reported as correct)", bits, why)

	return &zipHashResult{
		hashType: hashType,
		hash:     hash,
		filename: filename,
		encLabel: label,
	}, nil
}

// parseZipCrypto reads the 12-byte ZipCrypto encryption header and builds
// the Hashsmith hash string.
//
// Verification byte selection (PKWARE APPNOTE §6.1.5):
//   - Bit 3 of flags set (data descriptor present): use high byte of ModTime.
//   - Bit 3 clear: use high byte of CRC-32.
func parseZipCrypto(r io.ReadSeeker, lh localFileHeader, filename string) (*zipHashResult, error) {
	encHeader := make([]byte, 12)
	if _, err := io.ReadFull(r, encHeader); err != nil {
		return nil, fmt.Errorf("cannot read ZipCrypto encryption header: %w", err)
	}

	var checkByte byte
	if lh.Flags&0x08 != 0 {
		checkByte = byte(lh.ModTime >> 8) // high byte of 16-bit ModTime
	} else {
		checkByte = byte(lh.CRC32 >> 24) // high byte of 32-bit CRC-32
	}

	// The check byte is ONE byte, so it accepts one wrong password in 256.
	// That is not a rounding error: a rockyou-sized run reports thousands of
	// passwords that do not open the archive, and nothing distinguishes them
	// from the real one. The entry itself carries what settles it — its
	// CRC-32 and its payload — so when the local header declares a size and
	// the payload is small enough to carry, both go into the record and the
	// check byte becomes the cheap gate in front of an exact test.
	//
	// The cost of that exact test is paid on one candidate in 256, because
	// the gate rejects the rest, so the amortised cost of decrypting and
	// inflating is about a 256th of doing it every time.
	// Sizes and CRC come from the local header when it has them, and from the
	// central directory when bit 3 says it does not.
	crc, compressed, method := lh.CRC32, uint64(lh.CompressedSize), lh.ComprMethod
	haveSizes := lh.Flags&0x08 == 0
	if !haveSizes {
		if ce, ok := lookupZipCentralEntry(r, filename); ok {
			crc, compressed, method = ce.crc32, ce.compressedSize, ce.method
			haveSizes = true
			// The check byte for a bit-3 entry is the high byte of ModTime,
			// not of the CRC, and that stays true: the archive was WRITTEN
			// that way, so the encrypted header contains the ModTime byte
			// whatever the central directory later reveals.
		}
	}

	overhead := int64(len(encHeader))
	if haveSizes && int64(compressed) > overhead {
		dataLen := int64(compressed) - overhead
		if dataLen <= maxZipCryptoEmbeddedData {
			data := make([]byte, dataLen)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("cannot read ZipCrypto payload: %w", err)
			}
			hash := fmt.Sprintf("$zipcrypto$%02x$%s$%d$%08x$%s",
				checkByte, hex.EncodeToString(encHeader),
				method, crc, hex.EncodeToString(data))
			return &zipHashResult{
				hashType: "zipcrypto",
				hash:     hash,
				filename: filename,
				encLabel: "ZipCrypto (CRC-verified)",
			}, nil
		}
	}

	hash := fmt.Sprintf("$zipcrypto$%02x$%s", checkByte, hex.EncodeToString(encHeader))

	return &zipHashResult{
		hashType: "zipcrypto",
		hash:     hash,
		filename: filename,
		encLabel: "ZipCrypto (Traditional PKWARE)",
	}, nil
}

// ── ZipCrypto key schedule ────────────────────────────────────────────────────
//
// Implements the PKWARE traditional encryption cipher (ZipCrypto).
// Reference: PKWARE APPNOTE §6.1, Info-ZIP source.

type zipCryptoState struct {
	k0, k1, k2 uint32
}

// zipCRC32Step performs one raw CRC-32 table step (no ^0xFFFFFFFF XOR —
// this is the ZipCrypto internal usage, distinct from standard CRC checksums).
func zipCRC32Step(crc uint32, b byte) uint32 {
	return (*zipCRC32Tab)[byte(crc)^b] ^ (crc >> 8)
}

// newZipCryptoState initialises the three keys from a password.
func newZipCryptoState(password string) zipCryptoState {
	s := zipCryptoState{0x12345678, 0x23456789, 0x34567890}
	for _, b := range []byte(password) {
		s.k0 = zipCRC32Step(s.k0, b)
		s.k1 = (s.k1+(s.k0&0xFF))*0x08088405 + 1
		s.k2 = zipCRC32Step(s.k2, byte(s.k1>>24))
	}
	return s
}

// keyStreamByte returns the next pseudo-random key-stream byte.
func (s *zipCryptoState) keyStreamByte() byte {
	t := uint16(s.k2) | 2
	return byte((uint32(t) * uint32(t^1)) >> 8)
}

// decryptByte decrypts one ciphertext byte and advances the key state.
func (s *zipCryptoState) decryptByte(c byte) byte {
	plain := c ^ s.keyStreamByte()
	s.k0 = zipCRC32Step(s.k0, plain)
	s.k1 = (s.k1+(s.k0&0xFF))*0x08088405 + 1
	s.k2 = zipCRC32Step(s.k2, byte(s.k1>>24))
	return plain
}

// decryptZipCryptoHeader decrypts the 12-byte ZipCrypto encryption header
// using the given password and returns the plaintext header bytes.
func decryptZipCryptoHeader(encHeader []byte, password string) []byte {
	s := newZipCryptoState(password)
	out := make([]byte, len(encHeader))
	for i, b := range encHeader {
		out[i] = s.decryptByte(b)
	}
	return out
}

// ── Central directory lookup ─────────────────────────────────────────────────

// zipCentralSig and zipEOCDSig are the central-directory and end-of-central-
// directory record signatures.
const (
	zipCentralSig = 0x02014b50
	zipEOCDSig    = 0x06054b50
)

// zipCentralEntry is the size and checksum metadata for one entry, read from
// the central directory rather than from its local header.
type zipCentralEntry struct {
	crc32          uint32
	compressedSize uint64
	method         uint16
}

// lookupZipCentralEntry finds an entry's CRC-32 and compressed size in the
// archive's central directory, and restores the reader's position.
//
// It exists because of bit 3 of an entry's flags. When that bit is set the
// local header carries ZEROES for the CRC and both sizes, and the real values
// follow the compressed data in a trailing descriptor — which cannot be found
// without already knowing the size. Info-ZIP's `zip`, the single most common
// producer of ZipCrypto archives, sets that bit on every entry.
//
// Without this, exactly the common case fell back to the one-byte check and
// its one-false-accept-in-256, while archives from 7-Zip (which clears the
// bit) got the exact check. The central directory has what the local header
// withholds, so it is read.
func lookupZipCentralEntry(r io.ReadSeeker, name string) (zipCentralEntry, bool) {
	var out zipCentralEntry
	here, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return out, false
	}
	defer func() { _, _ = r.Seek(here, io.SeekStart) }()

	size, err := r.Seek(0, io.SeekEnd)
	if err != nil || size < 22 {
		return out, false
	}
	// The end-of-central-directory record is last, but a ZIP comment may
	// follow it, so scan back over the largest comment the format allows.
	tailLen := int64(22 + 65535)
	if tailLen > size {
		tailLen = size
	}
	if _, err := r.Seek(size-tailLen, io.SeekStart); err != nil {
		return out, false
	}
	tail := make([]byte, tailLen)
	if _, err := io.ReadFull(r, tail); err != nil {
		return out, false
	}
	eocd := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == zipEOCDSig {
			eocd = i
			break
		}
	}
	if eocd < 0 {
		return out, false
	}
	cdOffset := int64(binary.LittleEndian.Uint32(tail[eocd+16:]))
	entries := int(binary.LittleEndian.Uint16(tail[eocd+10:]))
	if cdOffset < 0 || cdOffset >= size {
		return out, false
	}
	if _, err := r.Seek(cdOffset, io.SeekStart); err != nil {
		return out, false
	}

	hdr := make([]byte, 46)
	for i := 0; i < entries && i < maxZipCentralEntries; i++ {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return out, false
		}
		if binary.LittleEndian.Uint32(hdr) != zipCentralSig {
			return out, false
		}
		nameLen := int(binary.LittleEndian.Uint16(hdr[28:]))
		extraLen := int(binary.LittleEndian.Uint16(hdr[30:]))
		commentLen := int(binary.LittleEndian.Uint16(hdr[32:]))
		nameBuf := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			return out, false
		}
		if _, err := r.Seek(int64(extraLen+commentLen), io.SeekCurrent); err != nil {
			return out, false
		}
		if string(nameBuf) != name {
			continue
		}
		return zipCentralEntry{
			method:         binary.LittleEndian.Uint16(hdr[10:]),
			crc32:          binary.LittleEndian.Uint32(hdr[16:]),
			compressedSize: uint64(binary.LittleEndian.Uint32(hdr[20:])),
		}, true
	}
	return out, false
}

// maxZipCentralEntries bounds the central-directory walk, so a crafted archive
// claiming a huge entry count cannot spin here.
const maxZipCentralEntries = 1 << 16
