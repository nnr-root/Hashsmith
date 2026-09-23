package main

// PGP's Self-Decrypting Archive.
//
//	$pgpsda$<version>*<iterations>*<8-byte salt>*<8-byte verifier>
//
// The key derivation is OpenPGP's iterated-and-salted S2K written the wrong
// way round. The specification hashes a stream of salt-then-password repeated
// until a byte count is reached; PGP's SDA code hashes the salt once and then
// the password followed by a COUNTER BYTE, once per iteration — and the
// counter is an eight-bit value, so it wraps every 256 rounds and contributes
// nothing after the first pass.
//
// The verifier is the derived key encrypting itself: CAST5 keyed on the first
// sixteen bytes of the SHA-1, applied to the first eight bytes of that same
// SHA-1. Eight bytes have to agree.
//
// Sixteen thousand iterations of a SHA-1 update over a short password is not a
// work factor by any modern reading — the whole derivation is one SHA-1
// context fed a few hundred kilobytes — and an SDA is a file someone emailed.

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"strings"

	"golang.org/x/crypto/cast5"
)

const pgpSDAPrefix = "$pgpsda$"

type pgpSDARecord struct {
	iterations int
	salt       []byte
	verifier   []byte
}

func pgpSDAFields(target string) (pgpSDARecord, error) {
	var r pgpSDARecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, pgpSDAPrefix) {
		return r, errors.New("not a PGP SDA record")
	}
	f := strings.Split(t[len(pgpSDAPrefix):], "*")
	if len(f) != 4 || f[0] != "0" {
		return r, errors.New("a PGP SDA record is $pgpsda$0*<iterations>*<salt>*<verifier>")
	}
	var err error
	if r.iterations, err = boundedPositiveInt(f[1], "PGP SDA iteration count", 1<<24); err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[2], 8, "PGP SDA salt"); err != nil {
		return r, err
	}
	if r.verifier, err = decodeExactHex(f[3], 8, "PGP SDA verifier"); err != nil {
		return r, err
	}
	return r, nil
}

func verifyPGPSDA(target, candidate string) (bool, error) {
	r, err := pgpSDAFields(target)
	if err != nil {
		return false, err
	}
	h := sha1.New()
	_, _ = h.Write(r.salt)
	pw := []byte(candidate)
	for j := 0; j < r.iterations; j++ {
		_, _ = h.Write(pw)
		// One byte of the counter, which is why the count above 255 adds only
		// length and not variety.
		_, _ = h.Write([]byte{byte(j)})
	}
	key := h.Sum(nil)

	c, err := cast5.NewCipher(key[:16])
	if err != nil {
		return false, err
	}
	var out [8]byte
	c.Encrypt(out[:], key[:8])
	return hmac.Equal(out[:], r.verifier), nil
}

func isPGPSDA(target string) bool {
	_, err := pgpSDAFields(target)
	return err == nil
}
