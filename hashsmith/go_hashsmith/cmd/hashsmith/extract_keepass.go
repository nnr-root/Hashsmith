package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// ── KeePass .kdbx extraction (keepass2smith) ───────────────────────────────────
//
// Parses a KeePass 2 database file and emits the $keepass$ hash the crack module
// understands. KDBX 3.1 (AES-KDF) is fully supported and produces the
// version-2 hash string ($keepass$*2*…). KDBX 4 (Argon2) is detected and
// reported as not-yet-supported by the extractor.

const (
	kdbxSig1 uint32 = 0x9AA2D903
	kdbxSig2 uint32 = 0xB54BFB67
)

// KDBX dynamic header field IDs (KDBX 3/4).
const (
	kdbxHdrEnd            = 0
	kdbxHdrCipherID       = 2
	kdbxHdrMasterSeed     = 4
	kdbxHdrTransformSeed  = 5
	kdbxHdrTransformRounds = 6
	kdbxHdrEncryptionIV   = 7
	kdbxHdrStreamStart    = 9
	kdbxHdrKdfParameters  = 11
)

// AES256-CBC cipher UUID used by KDBX AES databases.
var kdbxAESCipher = []byte{
	0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
	0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
}

func extractKeePass(path string) (*zipHashResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	if len(data) < 12 {
		return nil, errors.New("file too small to be a KDBX database")
	}
	if binary.LittleEndian.Uint32(data[0:4]) != kdbxSig1 ||
		binary.LittleEndian.Uint32(data[4:8]) != kdbxSig2 {
		return nil, errors.New("not a KeePass KDBX file (bad signature)")
	}
	major := binary.LittleEndian.Uint16(data[10:12]) // version = [minor uint16][major uint16]

	fields, headerEnd, err := parseKDBXHeader(data, int(major))
	if err != nil {
		return nil, err
	}

	if major >= 4 {
		return extractKeePass4(data, fields, headerEnd, path)
	}

	if cipher := fields[kdbxHdrCipherID]; len(cipher) == 16 && !bytesEqual(cipher, kdbxAESCipher) {
		return nil, errors.New("unsupported KDBX cipher (only AES is supported)")
	}
	masterSeed := fields[kdbxHdrMasterSeed]
	transformSeed := fields[kdbxHdrTransformSeed]
	roundsRaw := fields[kdbxHdrTransformRounds]
	encIV := fields[kdbxHdrEncryptionIV]
	streamStart := fields[kdbxHdrStreamStart]
	if len(masterSeed) != 32 || len(transformSeed) != 32 || len(roundsRaw) != 8 ||
		len(encIV) < 16 || len(streamStart) != 32 {
		return nil, errors.New("KDBX 3 header missing required fields")
	}
	rounds := binary.LittleEndian.Uint64(roundsRaw)

	if headerEnd+32 > len(data) {
		return nil, errors.New("KDBX payload too short")
	}
	firstEnc := data[headerEnd : headerEnd+32]

	hash := fmt.Sprintf("$keepass$*2*%d*%d*%s*%s*%s*%s*%s",
		rounds, headerEnd,
		hex.EncodeToString(masterSeed),
		hex.EncodeToString(transformSeed),
		hex.EncodeToString(encIV[:16]),
		hex.EncodeToString(streamStart),
		hex.EncodeToString(firstEnc))
	return &zipHashResult{
		hashType: "keepass",
		hash:     hash,
		filename: path,
		encLabel: fmt.Sprintf("KeePass KDBX 3.1 (AES-KDF, %d rounds)", rounds),
	}, nil
}

// parseKDBXHeader reads the dynamic header TLV fields and returns them by ID plus
// the byte offset where the encrypted payload begins.
func parseKDBXHeader(data []byte, major int) (map[int][]byte, int, error) {
	fields := make(map[int][]byte)
	pos := 12 // after sig1, sig2, version
	for {
		if pos+1 > len(data) {
			return nil, 0, errors.New("truncated KDBX header")
		}
		id := int(data[pos])
		pos++

		var length int
		if major >= 4 {
			if pos+4 > len(data) {
				return nil, 0, errors.New("truncated KDBX4 header field length")
			}
			length = int(binary.LittleEndian.Uint32(data[pos:]))
			pos += 4
		} else {
			if pos+2 > len(data) {
				return nil, 0, errors.New("truncated KDBX3 header field length")
			}
			length = int(binary.LittleEndian.Uint16(data[pos:]))
			pos += 2
		}
		if pos+length > len(data) {
			return nil, 0, errors.New("KDBX header field exceeds file")
		}
		fields[id] = data[pos : pos+length]
		pos += length
		if id == kdbxHdrEnd {
			break
		}
	}
	return fields, pos, nil
}

// Argon2 KDF UUIDs used in KDBX4 KdfParameters.
var (
	kdbxArgon2dUUID  = []byte{0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C}
	kdbxArgon2idUUID = []byte{0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6}
)

// extractKeePass4 builds a KDBX4 (Argon2) hash from the parsed header. KDBX4 is
// verified via the header HMAC, so the hash carries the KDF parameters, the
// master seed, the raw header bytes, and the stored header HMAC.
//
// Format: $keepass$*4*<argon: d|id>*<t>*<m_bytes>*<p>*<v>*<salt>*<masterSeed>*<header>*<headerHMAC>
func extractKeePass4(data []byte, fields map[int][]byte, headerEnd int, path string) (*zipHashResult, error) {
	kdf := fields[kdbxHdrKdfParameters]
	if kdf == nil {
		return nil, errors.New("KDBX4 header missing KDF parameters")
	}
	vd, err := parseVariantDict(kdf)
	if err != nil {
		return nil, err
	}

	uuid := vd["$UUID"]
	var argon string
	switch {
	case bytesEqual(uuid, kdbxArgon2dUUID):
		argon = "d"
	case bytesEqual(uuid, kdbxArgon2idUUID):
		argon = "id"
	default:
		return nil, errors.New("KDBX4 uses a non-Argon2 KDF (AES-KDF KDBX4 not supported)")
	}

	salt := vd["S"]
	iters := leU64(vd["I"])
	mem := leU64(vd["M"]) // memory in bytes
	par := leU32(vd["P"])
	ver := leU32(vd["V"])
	masterSeed := fields[kdbxHdrMasterSeed]
	if len(salt) == 0 || len(masterSeed) != 32 || iters == 0 || mem == 0 || par == 0 {
		return nil, errors.New("KDBX4 KDF parameters incomplete")
	}

	if headerEnd+64 > len(data) {
		return nil, errors.New("KDBX4 file truncated before header HMAC")
	}
	header := data[:headerEnd]
	headerHMAC := data[headerEnd+32 : headerEnd+64] // after SHA-256(header)

	hash := fmt.Sprintf("$keepass$*4*%s*%d*%d*%d*%d*%s*%s*%s*%s",
		argon, iters, mem, par, ver,
		hex.EncodeToString(salt),
		hex.EncodeToString(masterSeed),
		hex.EncodeToString(header),
		hex.EncodeToString(headerHMAC))
	return &zipHashResult{
		hashType: "keepass",
		hash:     hash,
		filename: path,
		encLabel: fmt.Sprintf("KeePass KDBX 4 (Argon2%s, t=%d, m=%dKiB, p=%d)", argon, iters, mem/1024, par),
	}, nil
}

// parseVariantDict parses a KeePass VariantDictionary (KDBX4 KdfParameters).
func parseVariantDict(b []byte) (map[string][]byte, error) {
	if len(b) < 2 {
		return nil, errors.New("truncated VariantDictionary")
	}
	out := make(map[string][]byte)
	pos := 2 // skip version uint16
	for pos < len(b) {
		typ := b[pos]
		pos++
		if typ == 0 {
			break
		}
		if pos+4 > len(b) {
			return nil, errors.New("truncated VariantDictionary key length")
		}
		klen := int(leU32(b[pos:]))
		pos += 4
		if pos+klen+4 > len(b) {
			return nil, errors.New("truncated VariantDictionary entry")
		}
		key := string(b[pos : pos+klen])
		pos += klen
		vlen := int(leU32(b[pos:]))
		pos += 4
		if pos+vlen > len(b) {
			return nil, errors.New("truncated VariantDictionary value")
		}
		out[key] = b[pos : pos+vlen]
		pos += vlen
	}
	return out, nil
}

func leU32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func leU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
