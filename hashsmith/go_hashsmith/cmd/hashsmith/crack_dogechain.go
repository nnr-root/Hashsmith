package main

// Dogechain.info wallet — Hashcat 32500.
//
//	$dogechain$0*<iterations>*<payload, base64>*<salt, base64>
//
// The payload is an AES-256-CBC blob whose first block is the IV. What makes
// this one worth a comment is the key derivation: the password is NOT what
// PBKDF2 sees. Dogechain hashes it with SHA-256, base64-encodes that digest,
// and hands the resulting 44-character TEXT to PBKDF2-HMAC-SHA256 as the
// password. Feeding PBKDF2 the password, or the raw digest, both derive the
// wrong key.
//
// The wallet plaintext is JSON, so a guess is judged by every decrypted byte
// having its high bit clear. The final block is left out of that test: it
// carries PKCS#7 padding, which is not ASCII and would fail a check it has no
// business being part of.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyDogechain(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$dogechain$") {
		return false, errors.New("not a Dogechain wallet record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$dogechain$"), "*")
	if len(p) != 4 {
		return false, errors.New("Dogechain record must be $dogechain$<v>*<iter>*<payload>*<salt>")
	}
	iterations, err := strconv.Atoi(p[1])
	if err != nil || iterations < 1 {
		return false, errors.New("Dogechain iterations must be a positive integer")
	}
	payload, err := base64.StdEncoding.DecodeString(p[2])
	if err != nil {
		return false, errors.New("Dogechain payload must be base64")
	}
	salt, err := base64.StdEncoding.DecodeString(p[3])
	if err != nil || len(salt) == 0 {
		return false, errors.New("Dogechain salt must be base64")
	}
	// The IV, at least one block to judge, and a padding block to leave out.
	if len(payload) < 3*aes.BlockSize || len(payload)%aes.BlockSize != 0 {
		return false, errors.New("Dogechain payload is not a whole number of AES blocks")
	}

	digest := sha256.Sum256([]byte(candidate))
	pwText := base64.StdEncoding.EncodeToString(digest[:])
	key := pbkdf2.Key([]byte(pwText), salt, iterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}

	body := payload[aes.BlockSize : len(payload)-aes.BlockSize]
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, payload[:aes.BlockSize]).CryptBlocks(plain, body)
	for _, c := range plain {
		if c&0x80 != 0 {
			return false, nil
		}
	}
	return true, nil
}
