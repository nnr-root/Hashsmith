package main

// Padlock, a browser password manager built on SJCL.
//
//	$padlock$<version>$<iterations>$<tag bits>$<salt len>$<salt>$<iv>$<aad len>$<aad>$<ct len>$<ct>
//
// The key is PBKDF2-HMAC-SHA256 and the container is AES-CCM. What is not
// checked is the CCM tag, and the reason is a bug rather than a shortcut:
// Padlock hands its additional authenticated data to SJCL still base64
// encoded, so the tag is computed over the wrong bytes and no independent
// implementation reproduces it. John says so in its own source and checks the
// plaintext instead; this does the same.
//
// That leaves CCM's confidentiality half, which is plain counter mode. The
// nonce is thirteen bytes of the stored sixteen, so the length field is two
// bytes and the counter block is 0x01, the nonce, then a big-endian counter
// starting at one. No tag, no CBC-MAC, nothing else needed to read the
// plaintext out.
//
// The plaintext is Padlock's JSON store. An empty vault is the two characters
// "[]" and anything else is an array whose records carry an "updated" field,
// so those are the two things a correct password produces. Two characters is
// thin evidence and the code should not pretend otherwise — but a two-byte
// vault is an empty one, and an empty one is all the record has to offer.

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	padlockPrefix   = "$padlock$"
	padlockNonceLen = 13
)

type padlockRecord struct {
	iterations int
	tagLen     int
	salt       []byte
	iv         []byte
	ct         []byte
}

func padlockFields(target string) (padlockRecord, error) {
	var r padlockRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, padlockPrefix) {
		return r, errors.New("not a Padlock record")
	}
	f := strings.Split(t[len(padlockPrefix):], "$")
	if len(f) != 10 {
		return r, errors.New("a Padlock record has ten fields")
	}
	if f[0] != "1" {
		return r, errors.New("unsupported Padlock record version")
	}
	var err error
	if r.iterations, err = boundedPositiveInt(f[1], "Padlock iteration count", 1<<22); err != nil {
		return r, err
	}
	tagBits, err := boundedPositiveInt(f[2], "Padlock tag length", 128)
	if err != nil {
		return r, err
	}
	r.tagLen = tagBits / 8
	saltLen, err := boundedPositiveInt(f[3], "Padlock salt length", 64)
	if err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[4], saltLen, "Padlock salt"); err != nil {
		return r, err
	}
	if r.iv, err = decodeExactHex(f[5], 16, "Padlock IV"); err != nil {
		return r, err
	}
	// The additional data is read past and not used: it is the field Padlock
	// hands to SJCL still encoded, which is what breaks the tag.
	ctLen, err := boundedPositiveInt(f[8], "Padlock ciphertext length", 1<<20)
	if err != nil {
		return r, err
	}
	if r.ct, err = hex.DecodeString(f[9]); err != nil || len(r.ct) != ctLen {
		return r, errors.New("the Padlock ciphertext does not match its stated length")
	}
	if ctLen <= r.tagLen {
		return r, errors.New("a Padlock record carries no ciphertext beyond its tag")
	}
	return r, nil
}

// ccmDecryptNoTag runs CCM's counter mode over the payload and returns the
// plaintext, without computing or checking the authentication tag.
func ccmDecryptNoTag(key, nonce, payload []byte) ([]byte, error) {
	if len(nonce) != padlockNonceLen {
		return nil, errors.New("this CCM reader expects a 13-byte nonce")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(payload))
	var ctr, stream [aes.BlockSize]byte
	ctr[0] = byte(15 - len(nonce) - 1) // the length field's width, less one
	copy(ctr[1:], nonce)
	for off := 0; off < len(payload); off += aes.BlockSize {
		binary.BigEndian.PutUint16(ctr[14:], uint16(off/aes.BlockSize)+1)
		block.Encrypt(stream[:], ctr[:])
		n := copy(out[off:], stream[:])
		for i := 0; i < n; i++ {
			out[off+i] ^= payload[off+i]
		}
	}
	return out, nil
}

func verifyPadlock(target, candidate string) (bool, error) {
	r, err := padlockFields(target)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), r.salt, r.iterations, 32, sha256.New)
	plain, err := ccmDecryptNoTag(key, r.iv[:padlockNonceLen], r.ct[:len(r.ct)-r.tagLen])
	if err != nil {
		return false, err
	}
	if len(plain) == 2 {
		return string(plain) == "[]", nil
	}
	return plain[0] == '[' && bytes.Contains(plain, []byte(`"updated"`)), nil
}

func isPadlock(target string) bool {
	_, err := padlockFields(target)
	return err == nil
}
