package main

// Electrum wallet (salt-type 1–3) cracking.
//
// Old Electrum wallets encrypt the seed with AES-256-CBC under a key that is a
// double SHA-256 of the password. The seed is a hex string, so a correct
// password is proven when the decrypted block is entirely ASCII hex digits.
//
//	key = SHA256(SHA256(password))
//	plaintext = AES-256-CBC-decrypt(key, iv, ciphertext)   (no padding)
//	valid ⇔ plaintext matches /^[0-9a-f]+$/
//
// Accepted format:  $electrum$<type>*<iv>*<ciphertext>

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// verifyElectrum checks a passphrase against a $electrum$ (salt-type 1–3) target.
func verifyElectrum(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$electrum$") {
		return false, errors.New("invalid electrum hash (missing $electrum$ prefix)")
	}
	f := strings.Split(targetHash[len("$electrum$"):], "*")
	if len(f) < 3 {
		return false, errors.New("invalid electrum hash (need type*iv*ciphertext)")
	}
	switch f[0] {
	case "1", "2", "3":
	default:
		return false, errors.New("unsupported electrum salt-type " + f[0] + " (want 1, 2, or 3)")
	}
	iv, err := hex.DecodeString(f[1])
	if err != nil || len(iv) != 16 {
		return false, errors.New("invalid electrum IV (need 16 bytes)")
	}
	ct, err := hex.DecodeString(f[2])
	if err != nil || len(ct) == 0 || len(ct)%16 != 0 {
		return false, errors.New("invalid electrum ciphertext")
	}

	first := sha256.Sum256([]byte(candidate))
	key := sha256.Sum256(first[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	return allHexASCII(plain), nil
}

// allHexASCII reports whether every byte is an ASCII hex digit (0-9, a-f).
func allHexASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
