package main

// Apple iWork documents — Hashcat 23300.
//
//	$iwork$<version>$<a>$<b>$<iterations>$<salt>$<iv>$<blob>
//
// PBKDF2-HMAC-SHA1 to an AES-128 key, then AES-128-CBC over the blob. The
// document carries its own verifier inside that plaintext: the first 32 bytes
// are the unwrapped key material and the 16 bytes after them are the first
// half of its SHA-256. So the check needs no stored digest and no padding
// oracle — it recomputes the hash from what it just decrypted and compares.
//
// Only 48 of the blob's 64 bytes are decrypted, because the remaining block
// contributes nothing to that comparison.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const iworkCheckedBytes = 48

func verifyIWork(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$iwork$") {
		return false, errors.New("not an Apple iWork record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$iwork$"), "$")
	if len(p) != 7 {
		return false, errors.New("Apple iWork record must have 7 fields")
	}
	iterations, err := strconv.Atoi(p[3])
	if err != nil || iterations < 1 {
		return false, errors.New("Apple iWork iterations must be a positive integer")
	}
	salt, err := hex.DecodeString(p[4])
	if err != nil || len(salt) == 0 {
		return false, errors.New("Apple iWork salt is not hex")
	}
	iv, err := hex.DecodeString(p[5])
	if err != nil || len(iv) != aes.BlockSize {
		return false, errors.New("Apple iWork IV must be 16 hex-encoded bytes")
	}
	blob, err := hex.DecodeString(p[6])
	if err != nil || len(blob) < iworkCheckedBytes {
		return false, errors.New("Apple iWork blob is too short or not hex")
	}

	key := pbkdf2.Key([]byte(candidate), salt, iterations, 16, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, iworkCheckedBytes)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, blob[:iworkCheckedBytes])

	sum := sha256.Sum256(plain[:32])
	return bytes.Equal(sum[:16], plain[32:48]), nil
}
