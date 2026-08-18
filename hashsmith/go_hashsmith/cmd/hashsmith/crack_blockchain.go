package main

// Blockchain.info "My Wallet" v2:
//
//	$blockchain$v2$<iterations>$<datalen>$<data>
//
//	salt = data[:16];  key = PBKDF2-HMAC-SHA1(password, salt, iterations, 32)
//	plaintext = AES-256-CBC-decrypt(key, iv=salt, data[16:])
//	valid ⇔ plaintext is the wallet JSON ('{' … "guid" …)

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyBlockchain(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$blockchain$v2$") {
		return false, errors.New("invalid Blockchain hash (missing $blockchain$v2$ prefix)")
	}
	f := strings.Split(targetHash[len("$blockchain$v2$"):], "$")
	if len(f) != 3 {
		return false, errors.New("invalid Blockchain hash (need iter$len$data)")
	}
	iter, err := strconv.Atoi(f[0])
	if err != nil || iter < 1 {
		return false, errors.New("invalid Blockchain iteration count")
	}
	data, err := hex.DecodeString(f[2])
	if err != nil || len(data) < 32 || (len(data)-16)%16 != 0 {
		return false, errors.New("invalid Blockchain data")
	}
	salt := data[:16]
	key := pbkdf2.Key([]byte(candidate), salt, iter, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	pt := make([]byte, len(data)-16)
	cipher.NewCBCDecrypter(block, salt).CryptBlocks(pt, data[16:])
	return pt[0] == '{' && bytes.Contains(pt, []byte(`"guid"`)), nil
}
