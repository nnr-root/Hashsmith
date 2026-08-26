package main

// VeraCrypt / TrueCrypt volume cracking.
//
// The first 512 bytes of a volume are the header: 64 bytes of salt followed by
// 448 bytes encrypted with AES-256-XTS. The header key is PBKDF2(passphrase,
// salt, iterations, 64) — the hash and iteration count identify the mode. Once
// decrypted, a correct passphrase is proven by the "VERA"/"TRUE" magic and two
// CRC-32 checks embedded in the header, so nothing needs to be mounted.
//
// Covered ciphers/KDFs: AES, Serpent and Twofish in their single-, two- and
// three-cipher XTS layouts, with PBKDF2-HMAC-SHA512 / SHA256 / RIPEMD160 /
// Whirlpool / Streebog-512. Both standard and system/boot iteration schedules
// are supported.
//
// Input: the raw 512-byte header as hex, optionally prefixed "veracrypt:" /
// "truecrypt:".

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xts"
)

// vcKDF describes one PBKDF2 configuration VeraCrypt/TrueCrypt uses.
type vcKDF struct {
	newHash func() hash.Hash
	iter    int
}

type cryptCascadeMode struct {
	kdf        string
	bits       int
	vera, boot bool
}

var cryptCascadeModes = map[string]cryptCascadeMode{
	"truecrypt-ripemd160-xts1024":        {"ripemd160", 1024, false, false},
	"truecrypt-ripemd160-xts1536":        {"ripemd160", 1536, false, false},
	"truecrypt-sha512-xts1024":           {"sha512", 1024, false, false},
	"truecrypt-sha512-xts1536":           {"sha512", 1536, false, false},
	"truecrypt-whirlpool-xts1024":        {"whirlpool", 1024, false, false},
	"truecrypt-whirlpool-xts1536":        {"whirlpool", 1536, false, false},
	"truecrypt-whirlpool":                {"whirlpool", 512, false, false},
	"truecrypt-ripemd160-boot-xts512":    {"ripemd160", 512, false, true},
	"truecrypt-ripemd160-boot-xts1024":   {"ripemd160", 1024, false, true},
	"truecrypt-ripemd160-boot-xts1536":   {"ripemd160", 1536, false, true},
	"veracrypt-ripemd160-xts1024":        {"ripemd160", 1024, true, false},
	"veracrypt-ripemd160-xts1536":        {"ripemd160", 1536, true, false},
	"veracrypt-sha512-xts1024":           {"sha512", 1024, true, false},
	"veracrypt-sha512-xts1536":           {"sha512", 1536, true, false},
	"veracrypt-whirlpool-xts1024":        {"whirlpool", 1024, true, false},
	"veracrypt-whirlpool-xts1536":        {"whirlpool", 1536, true, false},
	"veracrypt-whirlpool":                {"whirlpool", 512, true, false},
	"veracrypt-ripemd160-boot-xts512":    {"ripemd160", 512, true, true},
	"veracrypt-ripemd160-boot-xts1024":   {"ripemd160", 1024, true, true},
	"veracrypt-ripemd160-boot-xts1536":   {"ripemd160", 1536, true, true},
	"veracrypt-sha256-xts1024":           {"sha256", 1024, true, false},
	"veracrypt-sha256-xts1536":           {"sha256", 1536, true, false},
	"veracrypt-sha256-boot-xts512":       {"sha256", 512, true, true},
	"veracrypt-sha256-boot-xts1024":      {"sha256", 1024, true, true},
	"veracrypt-sha256-boot-xts1536":      {"sha256", 1536, true, true},
	"veracrypt-streebog512":              {"streebog512", 512, true, false},
	"veracrypt-streebog512-xts1024":      {"streebog512", 1024, true, false},
	"veracrypt-streebog512-xts1536":      {"streebog512", 1536, true, false},
	"veracrypt-streebog512-boot-xts512":  {"streebog512", 512, true, true},
	"veracrypt-streebog512-boot-xts1024": {"streebog512", 1024, true, true},
	"veracrypt-streebog512-boot-xts1536": {"streebog512", 1536, true, true},
}

// vcKDFs are tried in order for a bare header (no explicit KDF given). VeraCrypt
// standard non-system volumes: SHA-512 / SHA-256 = 500000, RIPEMD-160 = 655331;
// TrueCrypt used 2000 (RIPEMD-160) / 1000 (SHA-512, called "SHA-1" historically
// but modern TrueCrypt is RIPEMD-160 at 2000). We cover the common ones.
var vcKDFs = []vcKDF{
	{sha512.New, 500000},           // VeraCrypt SHA-512
	{sha256.New, 500000},           // VeraCrypt SHA-256
	{newWhirlpool, 500000},         // VeraCrypt Whirlpool
	{newStreebog512Native, 500000}, // VeraCrypt Streebog-512
	{ripemd160.New, 655331},        // VeraCrypt RIPEMD-160
	{ripemd160.New, 327661},        // VeraCrypt boot RIPEMD-160
	{sha256.New, 200000},           // VeraCrypt boot SHA-256
	{newStreebog512Native, 200000}, // VeraCrypt boot Streebog-512
	{ripemd160.New, 2000},          // TrueCrypt RIPEMD-160
	{ripemd160.New, 1000},          // TrueCrypt boot RIPEMD-160
}

var tcKDFs = []vcKDF{
	{ripemd160.New, 2000}, // TrueCrypt RIPEMD-160
	{sha512.New, 1000},    // TrueCrypt SHA-512
	{newWhirlpool, 1000},  // TrueCrypt Whirlpool
	{ripemd160.New, 1000}, // TrueCrypt boot RIPEMD-160
}

// verifyVeraCrypt checks a passphrase against a 512-byte volume header (hex).
func verifyVeraCrypt(targetHash, candidate string) (bool, error) {
	return verifyCryptHeader(targetHash, candidate, vcKDFs)
}

// verifyTrueCrypt limits the KDF search to TrueCrypt's published iteration
// counts. Besides avoiding expensive VeraCrypt work, this keeps the two named
// formats independently testable even though their 512-byte headers coincide.
func verifyTrueCrypt(targetHash, candidate string) (bool, error) {
	return verifyCryptHeader(targetHash, candidate, tcKDFs)
}

func verifyTrueCryptMode(targetHash, candidate, kdf string) (bool, error) {
	return verifyCryptCascadeMode(targetHash, candidate, kdf, 512, false, false)
}

func verifyVeraCryptMode(targetHash, candidate, kdf string) (bool, error) {
	return verifyCryptCascadeMode(targetHash, candidate, kdf, 512, true, false)
}

// verifyCryptCascadeMode implements Hashcat's post-2024 split modes. bits is
// the maximum XTS key width advertised by the mode: 512 tries single ciphers,
// 1024 additionally tries the three supported two-cipher cascades, and 1536
// additionally tries both supported three-cipher cascades. Hashcat's kernels
// intentionally retain the lower-width checks in the wider modes.
func verifyCryptCascadeMode(targetHash, candidate, kdf string, bits int, vera, boot bool) (bool, error) {
	var newHash func() hash.Hash
	var iter int
	switch kdf {
	case "ripemd160":
		newHash = ripemd160.New
		if vera {
			iter = 655331
			if boot {
				iter = 327661
			}
		} else if boot {
			iter = 1000
		} else {
			iter = 2000
		}
	case "sha512":
		newHash = sha512.New
		if vera {
			iter = 500000
		} else {
			iter = 1000
		}
	case "whirlpool":
		newHash = newWhirlpool
		if vera {
			iter = 500000
		} else {
			iter = 1000
		}
	case "sha256":
		if !vera {
			return false, errors.New("TrueCrypt does not support the SHA-256 KDF")
		}
		newHash = sha256.New
		iter = 500000
		if boot {
			iter = 200000
		}
	case "streebog512":
		if !vera {
			return false, errors.New("TrueCrypt does not support the Streebog-512 KDF")
		}
		newHash = newStreebog512Native
		iter = 500000
		if boot {
			iter = 200000
		}
	default:
		return false, errors.New("unsupported TrueCrypt/VeraCrypt KDF")
	}
	if bits != 512 && bits != 1024 && bits != 1536 {
		return false, errors.New("unsupported TrueCrypt/VeraCrypt XTS key width")
	}

	header, err := parseCryptHeader(targetHash)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), header[:64], iter, bits/8, newHash)
	return vcHeaderValidThroughWidth(key, header[64:512], bits), nil
}

func parseCryptHeader(targetHash string) ([]byte, error) {
	t := strings.TrimSpace(targetHash)
	if strings.HasPrefix(t, "$truecrypt$") || strings.HasPrefix(t, "$veracrypt$") {
		parts := strings.Split(t, "$")
		if len(parts) != 4 || len(parts[2]) != 128 || len(parts[3]) != 896 ||
			!isHex(parts[2]) || !isHex(parts[3]) {
			return nil, errors.New("invalid Hashcat TrueCrypt/VeraCrypt header")
		}
		t = parts[2] + parts[3]
	}
	t = strings.TrimPrefix(t, "veracrypt:")
	t = strings.TrimPrefix(t, "truecrypt:")
	return decodeHexHeader(t)
}

func verifyCryptHeader(targetHash, candidate string, kdfs []vcKDF) (bool, error) {
	header, err := parseCryptHeader(targetHash)
	if err != nil {
		return false, err
	}
	salt := header[:64]
	encrypted := header[64:512]

	for _, kdf := range kdfs {
		// Most real-world headers are single-cipher. Test the 64-byte PBKDF2
		// prefix first so that ordinary auto-detection does not pay for all six
		// cascade key blocks. Derive the full key only after that fast path fails.
		singleKey := pbkdf2.Key([]byte(candidate), salt, kdf.iter, 64, kdf.newHash)
		if vcHeaderValidCipherRange(singleKey, encrypted, 1, 1) {
			return true, nil
		}
		cascadeKey := pbkdf2.Key([]byte(candidate), salt, kdf.iter, 192, kdf.newHash)
		if vcHeaderValidCipherRange(cascadeKey, encrypted, 2, 3) {
			return true, nil
		}
	}
	return false, nil
}

var vcCascadeOrders = [][][]func([]byte) (cipher.Block, error){
	{
		{aes.NewCipher},
		{newSerpentCipher},
		{func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }},
	},
	{
		{aes.NewCipher, newSerpentCipher},
		{newSerpentCipher, func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }},
		{func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }, aes.NewCipher},
	},
	{
		{aes.NewCipher, func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }, newSerpentCipher},
		{newSerpentCipher, func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }, aes.NewCipher},
	},
}

func vcHeaderValidThroughWidth(key, encrypted []byte, bits int) bool {
	return vcHeaderValidCipherRange(key, encrypted, 1, bits/512)
}

func vcHeaderValidCipherRange(key, encrypted []byte, minCiphers, maxCiphers int) bool {
	for cipherCount := minCiphers; cipherCount <= maxCiphers; cipherCount++ {
		needed := cipherCount * 64
		if len(key) < needed {
			continue
		}
		for _, order := range vcCascadeOrders[cipherCount-1] {
			if vcHeaderValidCascade(order, key[:needed], encrypted) {
				return true
			}
		}
	}
	return false
}

func vcHeaderValidCascade(order []func([]byte) (cipher.Block, error), key, encrypted []byte) bool {
	count := len(order)
	dec := append([]byte(nil), encrypted...)
	for i := count - 1; i >= 0; i-- {
		xtsKey := make([]byte, 64)
		copy(xtsKey[:32], key[i*32:(i+1)*32])
		copy(xtsKey[32:], key[(count+i)*32:(count+i+1)*32])
		c, err := xts.NewCipher(order[i], xtsKey)
		if err != nil {
			return false
		}
		out := make([]byte, len(dec))
		c.Decrypt(out, dec, 0)
		dec = out
	}
	return vcDecryptedHeaderValid(dec)
}

// vcCiphers are the single (non-cascade) XTS ciphers VeraCrypt/TrueCrypt use that
// Go can build. Serpent and Twofish cascades are not attempted.
var vcCiphers = []func([]byte) (cipher.Block, error){
	aes.NewCipher,
	newSerpentCipher,
	func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) },
}

// vcHeaderValid decrypts the header with an XTS key and checks the magic and
// CRC-32 fields.
func vcHeaderValid(newCipher func([]byte) (cipher.Block, error), key, encrypted []byte) bool {
	c, err := xts.NewCipher(newCipher, key)
	if err != nil {
		return false
	}
	dec := make([]byte, len(encrypted))
	c.Decrypt(dec, encrypted, 0) // header is data unit 0

	return vcDecryptedHeaderValid(dec)
}

func vcDecryptedHeaderValid(dec []byte) bool {
	if len(dec) < 448 || (string(dec[0:4]) != "VERA" && string(dec[0:4]) != "TRUE") {
		return false
	}
	// CRC-32 of the 256-byte master-key area (decrypted 192..448).
	if crc32.ChecksumIEEE(dec[192:448]) != binary.BigEndian.Uint32(dec[8:12]) {
		return false
	}
	// CRC-32 of the header fields (decrypted 0..188).
	if crc32.ChecksumIEEE(dec[0:188]) != binary.BigEndian.Uint32(dec[188:192]) {
		return false
	}
	return true
}

// decodeHexHeader hex-decodes a header and requires at least 512 bytes.
func decodeHexHeader(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("invalid VeraCrypt header (must be hex)")
	}
	if len(b) < 512 {
		return nil, errors.New("VeraCrypt header must be at least 512 bytes")
	}
	return b, nil
}

// looksLikeVeraCrypt reports whether s could be a VeraCrypt/TrueCrypt header: an
// explicit prefix, or a long even-length hex string of at least 512 bytes.
func looksLikeVeraCrypt(s string) bool {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "veracrypt:") || strings.HasPrefix(t, "truecrypt:") ||
		strings.HasPrefix(t, "$veracrypt$") || strings.HasPrefix(t, "$truecrypt$") {
		return true
	}
	if len(t) < 1024 || len(t)%2 != 0 {
		return false
	}
	return isHex(t)
}
