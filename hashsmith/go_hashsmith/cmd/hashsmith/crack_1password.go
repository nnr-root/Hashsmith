package main

// 1Password Agile Keychain:
//
//	<iterations>:<salt>:<data>
//
//	key = PBKDF2-HMAC-SHA1(password, salt, iterations, 16)
//
// The data is AES-128-CBC ciphertext; a correct password decrypts the final
// block to a full block of PKCS#7 padding (0x10 × 16).

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

func verify1Password(targetHash, candidate string) (bool, error) {
	f := strings.Split(targetHash, ":")
	if len(f) != 3 {
		return false, errors.New("invalid 1Password hash (need iter:salt:data)")
	}
	iter, err := strconv.Atoi(f[0])
	if err != nil || iter < 1 {
		return false, errors.New("invalid 1Password iteration count")
	}
	salt, err := hex.DecodeString(f[1])
	if err != nil {
		return false, errors.New("invalid 1Password salt")
	}
	data, err := hex.DecodeString(f[2])
	if err != nil || len(data) < 32 || len(data)%16 != 0 {
		return false, errors.New("invalid 1Password data")
	}

	key := pbkdf2.Key([]byte(candidate), salt, iter, 16, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	n := len(data)
	out := make([]byte, 16)
	cipher.NewCBCDecrypter(block, data[n-32:n-16]).CryptBlocks(out, data[n-16:n])
	for _, b := range out {
		if b != 0x10 {
			return false, nil
		}
	}
	return true, nil
}

// isOnePassword: <digits>:<16-hex salt>:<hex data, whole 16-byte blocks>.
func isOnePassword(s string) bool {
	f := strings.Split(s, ":")
	if len(f) != 3 {
		return false
	}
	if _, err := strconv.Atoi(f[0]); err != nil {
		return false
	}
	if len(f[1]) != 16 || !isHex(f[1]) {
		return false
	}
	return len(f[2]) >= 64 && len(f[2])%32 == 0 && isHex(f[2])
}
