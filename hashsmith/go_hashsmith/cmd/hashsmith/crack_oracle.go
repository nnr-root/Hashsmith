package main

// Oracle 11g/12c (the "S:" verifier):
//
//	<40-hex sha1><20-hex salt>   — sha1(password . salt), salt = 10 bytes
//
// (60 hex chars total: the SHA-1 digest followed by the salt.)

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyOracle11g(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 60 || !isHex(targetHash) {
		return false, errors.New("invalid Oracle 11g hash (need 60 hex chars)")
	}
	salt, err := hex.DecodeString(targetHash[40:])
	if err != nil {
		return false, errors.New("invalid Oracle 11g salt")
	}
	h := sha1.New()
	h.Write([]byte(candidate))
	h.Write(salt)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), targetHash[:40]), nil
}

func isOracle11g(s string) bool { return len(s) == 60 && isHex(s) }

// verifyOracle12c checks a candidate against an Oracle 12c "T:" verifier (160
// hex = 64-byte SHA-512 digest + 16-byte salt):
//
//	key = PBKDF2-HMAC-SHA512(password, salt . "AUTH_PBKDF2_SPEEDY_KEY", 4096, 64)
//	H   = SHA-512(key . salt)   (compared against the first 128 hex chars)
func verifyOracle12c(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 160 || !isHex(targetHash) {
		return false, errors.New("invalid Oracle 12c hash (need 160 hex chars)")
	}
	salt, err := hex.DecodeString(targetHash[128:])
	if err != nil {
		return false, errors.New("invalid Oracle 12c salt")
	}
	key := pbkdf2Sha512(candidate, append(salt, []byte("AUTH_PBKDF2_SPEEDY_KEY")...))
	h := sha512.Sum512(append(key, salt...))
	return strings.EqualFold(hex.EncodeToString(h[:]), targetHash[:128]), nil
}

func pbkdf2Sha512(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 4096, 64, sha512.New)
}

func isOracle12c(s string) bool { return len(s) == 160 && isHex(s) }
