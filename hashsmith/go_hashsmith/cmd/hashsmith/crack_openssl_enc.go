package main

// Files written by `openssl enc`.
//
//	$openssl$<key length>$<digest>$<salt length>$<salt>$<sample>$<last>$<hint>
//
// `openssl enc` derives the key and IV from the password and an eight-byte
// salt with EVP_BytesToKey — one pass of a digest by default, no iteration
// count at all — and then encrypts with no authentication of any kind. There
// is nothing in the file that says whether a password was right.
//
// So the check is circumstantial, and this is the one format here where that
// is worth stating plainly. The last block of a CBC file ends in PKCS#7
// padding, and a wrong key produces valid-looking padding about once in every
// 256 tries. That is not a check: a ten-million-candidate run would stop on a
// wrong answer with near certainty.
//
// Hashsmith therefore requires the padding AND that what precedes it is
// printable text, which takes the false-positive rate to roughly one in a
// hundred million. The cost is real and is the honest trade: an encrypted
// file whose first bytes are binary will not be recovered from a record this
// short. Reporting a wrong password instead would be worse.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"
)

const opensslEncPrefix = "$openssl$"

// evpBytesToKey is OpenSSL's own derivation: the digest of the previous
// block, the password and the salt, repeated until there are enough bytes for
// a key and an IV.
func evpBytesToKey(newHash func() hash.Hash, password, salt []byte, count, keyLen, ivLen int) (key, iv []byte) {
	var out, prev []byte
	for len(out) < keyLen+ivLen {
		h := newHash()
		_, _ = h.Write(prev)
		_, _ = h.Write(password)
		_, _ = h.Write(salt)
		prev = h.Sum(nil)
		for i := 1; i < count; i++ {
			h2 := newHash()
			_, _ = h2.Write(prev)
			prev = h2.Sum(nil)
		}
		out = append(out, prev...)
	}
	return out[:keyLen], out[keyLen : keyLen+ivLen]
}

type opensslEnc struct {
	newHash func() hash.Hash
	keyLen  int
	salt    []byte
	sample  []byte
}

func parseOpenSSLEnc(target string) (*opensslEnc, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, opensslEncPrefix) {
		return nil, errors.New("not an openssl enc record")
	}
	f := strings.Split(t[len(opensslEncPrefix):], "$")
	if len(f) < 5 {
		return nil, errors.New("an openssl enc record needs a key size, a digest, a salt and a sample")
	}
	r := &opensslEnc{}
	switch f[0] {
	case "1":
		r.keyLen = 16
	case "2":
		r.keyLen = 24
	case "3":
		r.keyLen = 32
	default:
		return nil, errors.New("unsupported openssl enc key size " + f[0])
	}
	switch f[1] {
	case "0":
		r.newHash = md5.New
	case "1":
		r.newHash = sha1.New
	case "2":
		r.newHash = sha256.New
	default:
		return nil, errors.New("unsupported openssl enc digest " + f[1])
	}
	saltLen, err := strconv.Atoi(f[2])
	if err != nil || saltLen < 1 || saltLen > 64 {
		return nil, errors.New("invalid openssl enc salt length")
	}
	if r.salt, err = hex.DecodeString(f[3]); err != nil || len(r.salt) != saltLen {
		return nil, errors.New("invalid openssl enc salt")
	}
	if r.sample, err = hex.DecodeString(f[4]); err != nil ||
		len(r.sample) == 0 || len(r.sample)%aes.BlockSize != 0 {
		return nil, errors.New("invalid openssl enc sample")
	}
	return r, nil
}

// printableForOpenSSL reports whether every byte could be part of a text file.
func printableForOpenSSL(b []byte) bool {
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// verifyOpenSSLEnc checks a password against an `openssl enc` sample.
func verifyOpenSSLEnc(target, candidate string) (bool, error) {
	r, err := parseOpenSSLEnc(target)
	if err != nil {
		return false, err
	}
	key, iv := evpBytesToKey(r.newHash, []byte(candidate), r.salt, 1, r.keyLen, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plain := make([]byte, len(r.sample))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, r.sample)

	n := int(plain[len(plain)-1])
	if n < 1 || n > aes.BlockSize || n > len(plain) {
		return false, nil
	}
	for _, c := range plain[len(plain)-n:] {
		if int(c) != n {
			return false, nil
		}
	}
	// Padding alone is one chance in 256. See the note at the top of this
	// file for why that is not enough on its own.
	return printableForOpenSSL(plain[:len(plain)-n]), nil
}

func isOpenSSLEnc(target string) bool {
	_, err := parseOpenSSLEnc(target)
	return err == nil
}
