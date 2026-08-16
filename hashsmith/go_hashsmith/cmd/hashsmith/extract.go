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
			return parseWinZipAES(r, fname, ae)
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
//   [salt_length bytes] [2 bytes password verifier] [encrypted payload] [10 bytes HMAC-SHA1]
func parseWinZipAES(r io.Reader, filename string, ae *aesExtraField) (*zipHashResult, error) {
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
	hashType := fmt.Sprintf("zipaes%d", bits)
	hash := fmt.Sprintf("$%s$%s$%s",
		hashType,
		hex.EncodeToString(salt),
		hex.EncodeToString(verif))
	label := fmt.Sprintf("WinZip AES-%d", bits)

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
func parseZipCrypto(r io.Reader, lh localFileHeader, filename string) (*zipHashResult, error) {
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
		s.k1 = (s.k1 + (s.k0 & 0xFF)) * 0x08088405 + 1
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
	s.k1 = (s.k1 + (s.k0 & 0xFF)) * 0x08088405 + 1
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
