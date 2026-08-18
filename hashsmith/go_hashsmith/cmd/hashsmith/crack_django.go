package main

// Django PBKDF2 password hashes (the default Django/Werkzeug/passlib format):
//
//	pbkdf2_sha256$<iterations>$<salt>$<base64(dk)>
//	pbkdf2_sha1$<iterations>$<salt>$<base64(dk)>
//
// The derived-key length is taken from the stored digest, and the salt is used
// verbatim (not decoded). Verification recomputes PBKDF2 and compares.

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// verifyDjango checks a candidate against a pbkdf2_sha256/sha1 Django hash.
func verifyDjango(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	if len(parts) != 4 {
		return false, errors.New("invalid Django hash (need algo$iter$salt$hash)")
	}
	var newHash func() hash.Hash
	switch parts[0] {
	case "pbkdf2_sha256":
		newHash = sha256.New
	case "pbkdf2_sha1":
		newHash = sha1.New
	default:
		return false, errors.New("unsupported Django algorithm " + parts[0])
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, errors.New("invalid Django iteration count")
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false, errors.New("invalid Django base64 digest")
	}
	got := pbkdf2.Key([]byte(candidate), []byte(parts[2]), iter, len(want), newHash)
	return bytesEqualCT(got, want), nil
}

// isDjangoHash reports whether s is a supported Django PBKDF2 hash.
func isDjangoHash(s string) bool {
	return strings.HasPrefix(s, "pbkdf2_sha256$") || strings.HasPrefix(s, "pbkdf2_sha1$")
}
