package main

// PKCS#12 / PFX keystores (.p12, .pfx) — John's "pfx" format.
//
// A PKCS#12 file carries a MAC over its own contents, keyed by a password
// through the PKCS#12 key-derivation function of RFC 7292 appendix B.2.  That
// MAC is what makes the password recoverable offline: derive the MAC key from a
// candidate, HMAC the authenticated safe, and compare.  Recovering it does not
// require touching the encrypted key material at all.
//
// Record: $pfx$*<mac algorithm>*<iterations>*<salt hex>*<mac hex>*<data hex>

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"
)

// pkcs12MACAlgorithms are the digests PKCS#12 files are MACed with in practice.
var pkcs12MACAlgorithms = map[string]func() hash.Hash{
	"sha1":   sha1.New,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

// PKCS#12 key-derivation IDs from RFC 7292 B.3.
const (
	pkcs12IDKey = 1
	pkcs12IDIV  = 2
	pkcs12IDMAC = 3
)

// pkcs12KDF implements the RFC 7292 appendix B.2 derivation.
//
// The password is a BMPString: UTF-16BE with a two-byte null terminator.  Both
// the salt and the password are repeated — not zero-padded — up to a whole
// number of hash blocks, which is the step implementations most often get
// wrong.
func pkcs12KDF(password string, salt []byte, iterations, id, size int, newHash func() hash.Hash) []byte {
	h := newHash()
	u, v := h.Size(), h.BlockSize()

	diversifier := make([]byte, v)
	for i := range diversifier {
		diversifier[i] = byte(id)
	}

	i := append(pkcs12Fill(salt, v), pkcs12Fill(pkcs12BMPString(password), v)...)

	var out []byte
	for len(out) < size {
		a := append(append([]byte(nil), diversifier...), i...)
		for n := 0; n < iterations; n++ {
			h.Reset()
			_, _ = h.Write(a)
			a = h.Sum(nil)
		}
		out = append(out, a...)

		// I is advanced by adding B+1 to each of its v-byte blocks, treating
		// each block as a big-endian integer and discarding the carry out.
		b := pkcs12Fill(a, v)[:v]
		for j := 0; j < len(i); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(i[j+k]) + int(b[k]) + carry
				i[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	_ = u
	return out[:size]
}

// pkcs12Fill repeats b until it fills a whole number of v-byte blocks.
func pkcs12Fill(b []byte, v int) []byte {
	if len(b) == 0 {
		return nil
	}
	size := v * ((len(b) + v - 1) / v)
	out := make([]byte, size)
	for n := 0; n < size; n += len(b) {
		copy(out[n:], b)
	}
	return out
}

// pkcs12BMPString encodes a password the way PKCS#12 expects: UTF-16BE with a
// trailing null character.
func pkcs12BMPString(s string) []byte {
	utf16be := utf16le(s)
	for i := 0; i+1 < len(utf16be); i += 2 {
		utf16be[i], utf16be[i+1] = utf16be[i+1], utf16be[i]
	}
	return append(utf16be, 0, 0)
}

type pkcs12Hash struct {
	algorithm  string
	iterations int
	salt       []byte
	mac        []byte
	data       []byte
}

func parsePKCS12Hash(target string) (*pkcs12Hash, error) {
	if !strings.HasPrefix(target, "$pfx$*") {
		return nil, errors.New("invalid PKCS#12 hash (missing $pfx$ prefix)")
	}
	f := strings.Split(target[len("$pfx$*"):], "*")
	if len(f) != 5 {
		return nil, errors.New("invalid PKCS#12 hash (need alg*iter*salt*mac*data)")
	}
	out := &pkcs12Hash{algorithm: strings.ToLower(f[0])}
	if _, ok := pkcs12MACAlgorithms[out.algorithm]; !ok {
		return nil, errors.New("unsupported PKCS#12 MAC algorithm: " + out.algorithm)
	}
	var err error
	if out.iterations, err = strconv.Atoi(f[1]); err != nil || out.iterations < 1 || out.iterations > maxKDFIterations {
		return nil, errors.New("invalid PKCS#12 iteration count")
	}
	if out.salt, err = hex.DecodeString(f[2]); err != nil || len(out.salt) == 0 || len(out.salt) > maxKDFFieldSize {
		return nil, errors.New("invalid PKCS#12 salt")
	}
	if out.mac, err = hex.DecodeString(f[3]); err != nil || len(out.mac) == 0 {
		return nil, errors.New("invalid PKCS#12 MAC")
	}
	if out.data, err = hex.DecodeString(f[4]); err != nil || len(out.data) == 0 {
		return nil, errors.New("invalid PKCS#12 authenticated-safe data")
	}
	newHash := pkcs12MACAlgorithms[out.algorithm]
	if len(out.mac) != newHash().Size() {
		return nil, errors.New("PKCS#12 MAC length does not match " + out.algorithm)
	}
	return out, nil
}

func verifyPKCS12(targetHash, candidate string) (bool, error) {
	p, err := parsePKCS12Hash(targetHash)
	if err != nil {
		return false, err
	}
	newHash := pkcs12MACAlgorithms[p.algorithm]
	key := pkcs12KDF(candidate, p.salt, p.iterations, pkcs12IDMAC, newHash().Size(), newHash)
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(p.data)
	return hmac.Equal(mac.Sum(nil), p.mac), nil
}

func isPKCS12(s string) bool {
	_, err := parsePKCS12Hash(s)
	return err == nil
}
