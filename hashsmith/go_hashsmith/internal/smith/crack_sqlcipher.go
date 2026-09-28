package smith

// SQLCipher databases — Hashcat 24600.
//
//	SQLCIPHER*<version>*<iterations>*<salt>*<iv>*<ciphertext>
//
// PBKDF2-HMAC-SHA1 to a 256-bit key, then one AES-256-CBC block off the end of
// the database's first page. SQLCipher reserves the tail of each page, so the
// block decrypts to zeros; Hashcat checks the first twelve bytes of that and
// leaves the last four alone, which is a 96-bit test and plenty.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// sqlCipherZeroBytes is how much of the decrypted block must be zero.
const sqlCipherZeroBytes = 12

func verifySQLCipher(target, candidate string) (bool, error) {
	p := strings.Split(strings.TrimSpace(target), "*")
	if len(p) != 6 || !strings.EqualFold(p[0], "SQLCIPHER") {
		return false, errors.New("not a SQLCipher record")
	}
	iterations, err := strconv.Atoi(p[2])
	if err != nil || iterations < 1 {
		return false, errors.New("SQLCipher iterations must be a positive integer")
	}
	salt, err := hex.DecodeString(p[3])
	if err != nil || len(salt) == 0 {
		return false, errors.New("SQLCipher salt is not hex")
	}
	iv, err := hex.DecodeString(p[4])
	if err != nil || len(iv) != aes.BlockSize {
		return false, errors.New("SQLCipher IV must be 16 hex-encoded bytes")
	}
	ct, err := hex.DecodeString(p[5])
	if err != nil || len(ct) != aes.BlockSize {
		return false, errors.New("SQLCipher ciphertext must be 16 hex-encoded bytes")
	}

	key := pbkdf2.Key([]byte(candidate), salt, iterations, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	for _, b := range plain[:sqlCipherZeroBytes] {
		if b != 0 {
			return false, nil
		}
	}
	return true, nil
}
