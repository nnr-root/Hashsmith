package main

// Generic PBKDF2 hashes in the common colon-delimited form:
//
//	<algo>:<iterations>:<base64(salt)>:<base64(dk)>
//
// where algo is one of md5, sha1, sha224, sha256, sha384, or sha512. The
// derived-key length is taken from the stored digest.

import (
	"errors"
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
	newHash, ok := pbkdf2HashFactory(f[0])
	if !ok {
		return false, errors.New("unsupported PBKDF2 algorithm " + f[0])
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 || iter > maxKDFIterations {
		return false, errors.New("invalid PBKDF2 iteration count")
	}
	salt, err := decodeBase64Flexible(f[2], false)
	if err != nil || len(salt) > maxKDFFieldSize {
		return false, errors.New("invalid PBKDF2 salt (base64)")
	}
	want, err := decodeBase64Flexible(f[3], false)
	if err != nil || len(want) == 0 || len(want) > maxKDFFieldSize {
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
	if _, ok := pbkdf2HashFactory(f[0]); !ok {
		return false
	}
	iterations, err := strconv.Atoi(f[1])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false
	}
	salt, err := decodeBase64Flexible(f[2], false)
	if err != nil || len(salt) > maxKDFFieldSize {
		return false
	}
	digest, err := decodeBase64Flexible(f[3], false)
	if err != nil || len(digest) == 0 || len(digest) > maxKDFFieldSize {
		return false
	}
	return true
}
