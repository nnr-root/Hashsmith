package main

// AIX smd5-style PBKDF2 hashes:
//
//	{ssha256}<NN>$<salt>$<hash>   PBKDF2-HMAC-SHA256, iterations = 1<<NN
//	{ssha512}<NN>$<salt>$<hash>   PBKDF2-HMAC-SHA512, iterations = 1<<NN
//
// The derived key is encoded with the crypt-64 alphabet in 3-byte groups
// (MSB-packed, characters emitted low 6 bits first).

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// aixB64 encodes bytes with the AIX crypt-64 variant.
func aixB64(b []byte) string {
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		g := uint32(b[i]) << 16
		if i+1 < len(b) {
			g |= uint32(b[i+1]) << 8
		}
		if i+2 < len(b) {
			g |= uint32(b[i+2])
		}
		n := 4
		if i+2 >= len(b) {
			n = 3
		}
		for k := 0; k < n; k++ {
			out.WriteByte(itoa64[(g>>(6*uint(k)))&0x3f])
		}
	}
	return out.String()
}

func verifyAIX(targetHash, candidate string) (bool, error) {
	var newHash func() hash.Hash
	var dLen int
	var rest string
	switch {
	case strings.HasPrefix(targetHash, "{ssha256}"):
		newHash, dLen, rest = sha256.New, 32, targetHash[len("{ssha256}"):]
	case strings.HasPrefix(targetHash, "{ssha512}"):
		newHash, dLen, rest = sha512.New, 64, targetHash[len("{ssha512}"):]
	default:
		return false, errors.New("invalid AIX hash (need {ssha256}/{ssha512})")
	}
	f := strings.Split(rest, "$")
	if len(f) != 3 {
		return false, errors.New("invalid AIX hash (need NN$salt$hash)")
	}
	nn, err := strconv.Atoi(f[0])
	if err != nil || nn < 0 || nn > 30 {
		return false, errors.New("invalid AIX iteration exponent")
	}
	dk := pbkdf2.Key([]byte(candidate), []byte(f[1]), 1<<uint(nn), dLen, newHash)
	got := aixB64(dk)
	return got[:len(f[2])] == f[2], nil
}

func isAIX(s string) bool {
	return strings.HasPrefix(s, "{ssha256}") || strings.HasPrefix(s, "{ssha512}")
}
