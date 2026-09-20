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
	if !strings.HasPrefix(targetHash, "$blockchain$") {
		return false, errors.New("invalid Blockchain hash (missing $blockchain$ prefix)")
	}
	// Two record shapes, distinguished by the "v2$" marker:
	//
	//   $blockchain$v2$<iter>$<len>$<data>   the later wallet format
	//   $blockchain$<len>$<data>             the original, which hashcat
	//                                        -m 12700 still publishes
	//
	// The original leaves the iteration count implicit at 10; only the later
	// format made it configurable. Requiring the v2 marker rejected every
	// -m 12700 record outright, though the crypto for both is the same.
	var f []string
	iter := 10
	if rest, ok := strings.CutPrefix(targetHash, "$blockchain$v2$"); ok {
		f = strings.Split(rest, "$")
		if len(f) != 3 {
			return false, errors.New("invalid Blockchain v2 hash (need iter$len$data)")
		}
		var err error
		if iter, err = strconv.Atoi(f[0]); err != nil || iter < 1 || iter > maxKDFIterations {
			return false, errors.New("invalid Blockchain iteration count")
		}
	} else {
		parts := strings.Split(targetHash[len("$blockchain$"):], "$")
		if len(parts) != 2 {
			return false, errors.New("invalid Blockchain hash (need len$data)")
		}
		f = []string{"10", parts[0], parts[1]}
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
