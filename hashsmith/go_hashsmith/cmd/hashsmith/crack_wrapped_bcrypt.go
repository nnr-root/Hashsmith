package main

// Hashcat modes 25600, 25800, 28400, and 30600 feed the lowercase hexadecimal
// representation of a digest into bcrypt rather than the password itself.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func verifyWrappedBcrypt(target, candidate, digestName string) (bool, error) {
	var digest []byte
	switch digestName {
	case "md5":
		sum := md5.Sum([]byte(candidate))
		digest = sum[:]
	case "sha1":
		sum := sha1.Sum([]byte(candidate))
		digest = sum[:]
	case "sha256":
		sum := sha256.Sum256([]byte(candidate))
		digest = sum[:]
	case "sha512":
		sum := sha512.Sum512([]byte(candidate))
		digest = sum[:]
	default:
		return false, errors.New("unsupported bcrypt digest wrapper: " + digestName)
	}
	password := []byte(hex.EncodeToString(digest))
	return bcrypt.CompareHashAndPassword([]byte(target), password) == nil, nil
}
