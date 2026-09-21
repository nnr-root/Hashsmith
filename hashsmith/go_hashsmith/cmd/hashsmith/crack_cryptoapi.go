package main

// Linux Kernel Crypto API (2.4-era loop-AES style) — Hashcat 14500.
//
//	$cryptoapi$<cipher>$<key size>$<iv>$<unused>$<ciphertext>
//
// The key is RIPEMD-160 of the password, and for anything wider than 128 bits
// the remaining material comes from RIPEMD-160 of the password with a literal
// 'A' prepended. Twenty bytes plus twenty bytes, taken from the front:
//
//	AES-128  RIPEMD160(pw)[0:16]
//	AES-192  RIPEMD160(pw)[0:20] || RIPEMD160("A"+pw)[0:4]
//	AES-256  RIPEMD160(pw)[0:20] || RIPEMD160("A"+pw)[0:12]
//
// No salt and no iterations: the salt field is the IV, which is encrypted
// rather than used for chaining, so a guess is settled by one AES block.
//
// The key size is stored as an INDEX, not a bit count. Hashcat computes it as
// (n << 6) + 128, so 0, 1 and 2 mean 128, 192 and 256 — and 2 means 256, not
// the 128 that reading the field as a multiplier would suggest.

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const cryptoAPIMaxKeyIndex = 2

func verifyCryptoAPI(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$cryptoapi$") {
		return false, errors.New("not a Linux Crypto API record")
	}
	p := strings.Split(t, "$")
	// ["", "cryptoapi", cipher, keysize, iv, unused, data]
	if len(p) != 7 {
		return false, errors.New("Linux Crypto API record must have 5 fields")
	}
	idx, err := strconv.Atoi(p[3])
	if err != nil || idx < 0 || idx > cryptoAPIMaxKeyIndex {
		return false, errors.New("Linux Crypto API key size index must be 0, 1 or 2")
	}
	keyLen := (idx*64 + 128) / 8
	iv, err := hex.DecodeString(p[4])
	if err != nil || len(iv) != aes.BlockSize {
		return false, errors.New("Linux Crypto API IV must be 16 hex-encoded bytes")
	}
	want, err := hex.DecodeString(p[6])
	if err != nil || len(want) != aes.BlockSize {
		return false, errors.New("Linux Crypto API ciphertext must be 16 hex-encoded bytes")
	}

	h := newRIPEMD160()
	_, _ = h.Write([]byte(candidate))
	key := h.Sum(nil)
	if keyLen > len(key) {
		h2 := newRIPEMD160()
		_, _ = h2.Write([]byte("A"))
		_, _ = h2.Write([]byte(candidate))
		key = append(key, h2.Sum(nil)...)
	}
	block, err := aes.NewCipher(key[:keyLen])
	if err != nil {
		return false, err
	}
	got := make([]byte, aes.BlockSize)
	block.Encrypt(got, iv)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
