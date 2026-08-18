package main

// VeraCrypt / TrueCrypt volume cracking.
//
// The first 512 bytes of a volume are the header: 64 bytes of salt followed by
// 448 bytes encrypted with AES-256-XTS. The header key is PBKDF2(passphrase,
// salt, iterations, 64) — the hash and iteration count identify the mode. Once
// decrypted, a correct passphrase is proven by the "VERA"/"TRUE" magic and two
// CRC-32 checks embedded in the header, so nothing needs to be mounted.
//
// Covered ciphers/KDFs: AES-XTS with PBKDF2-HMAC-SHA512 / SHA256 / RIPEMD160
// (the common non-cascade configurations). Serpent/Twofish cascades and the
// Whirlpool/Streebog KDFs use primitives outside the Go crypto libraries and are
// not attempted here (a wrong guess would silently never match).
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

// vcKDFs are tried in order for a bare header (no explicit KDF given). VeraCrypt
// standard non-system volumes: SHA-512 / SHA-256 = 500000, RIPEMD-160 = 655331;
// TrueCrypt used 2000 (RIPEMD-160) / 1000 (SHA-512, called "SHA-1" historically
// but modern TrueCrypt is RIPEMD-160 at 2000). We cover the common ones.
var vcKDFs = []vcKDF{
	{sha512.New, 500000},     // VeraCrypt SHA-512
	{sha256.New, 500000},     // VeraCrypt SHA-256
	{newWhirlpool, 500000},   // VeraCrypt Whirlpool
	{newStreebog512, 500000}, // VeraCrypt Streebog-512
	{ripemd160.New, 655331},  // VeraCrypt RIPEMD-160
	{ripemd160.New, 2000},    // TrueCrypt RIPEMD-160
}

// verifyVeraCrypt checks a passphrase against a 512-byte volume header (hex).
func verifyVeraCrypt(targetHash, candidate string) (bool, error) {
	t := strings.TrimSpace(targetHash)
	t = strings.TrimPrefix(t, "veracrypt:")
	t = strings.TrimPrefix(t, "truecrypt:")
	header, err := decodeHexHeader(t)
	if err != nil {
		return false, err
	}
	salt := header[:64]
	encrypted := header[64:512]

	for _, kdf := range vcKDFs {
		key := pbkdf2.Key([]byte(candidate), salt, kdf.iter, 64, kdf.newHash)
		for _, newCipher := range vcCiphers {
			if vcHeaderValid(newCipher, key, encrypted) {
				return true, nil
			}
		}
	}
	return false, nil
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

	if string(dec[0:4]) != "VERA" && string(dec[0:4]) != "TRUE" {
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
	if strings.HasPrefix(t, "veracrypt:") || strings.HasPrefix(t, "truecrypt:") {
		return true
	}
	if len(t) < 1024 || len(t)%2 != 0 {
		return false
	}
	return isHex(t)
}
