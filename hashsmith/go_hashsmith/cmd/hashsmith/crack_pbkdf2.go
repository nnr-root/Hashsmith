package main

// Generic PBKDF2 hashes in the common colon-delimited form:
//
//	<algo>:<iterations>:<base64(salt)>:<base64(dk)>
//
// where algo is one of sha1, sha256, sha512, md5. The derived-key length is
// taken from the stored digest.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// verifyPBKDF2 checks a candidate against a generic PBKDF2 hash.
func verifyPBKDF2(targetHash, candidate string) (bool, error) {
	f := strings.Split(targetHash, ":")
	if len(f) != 4 {
		return false, errors.New("invalid PBKDF2 hash (need algo:iter:salt:dk)")
	}
	var newHash func() hash.Hash
	switch strings.ToLower(f[0]) {
	case "sha1":
		newHash = sha1.New
	case "sha256":
		newHash = sha256.New
	case "sha512":
		newHash = sha512.New
	case "md5":
		newHash = md5.New
	default:
		return false, errors.New("unsupported PBKDF2 algorithm " + f[0])
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 {
		return false, errors.New("invalid PBKDF2 iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil {
		return false, errors.New("invalid PBKDF2 salt (base64)")
	}
	want, err := base64.StdEncoding.DecodeString(f[3])
	if err != nil || len(want) == 0 {
		return false, errors.New("invalid PBKDF2 digest (base64)")
	}
	got := pbkdf2.Key([]byte(candidate), salt, iter, len(want), newHash)
	return bytesEqualCT(got, want), nil
}

// isGenericPBKDF2 reports whether s matches "<algo>:<iter>:<b64>:<b64>".
func isGenericPBKDF2(s string) bool {
	f := strings.Split(s, ":")
	if len(f) != 4 {
		return false
	}
	switch strings.ToLower(f[0]) {
	case "sha1", "sha256", "sha512", "md5":
	default:
		return false
	}
	if _, err := strconv.Atoi(f[1]); err != nil {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(f[2]); err != nil {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(f[3]); err != nil {
		return false
	}
	return true
}
