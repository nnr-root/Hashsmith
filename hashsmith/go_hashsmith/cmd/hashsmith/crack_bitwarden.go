package main

// Bitwarden vault master-password hash:
//
//	$bitwarden$2*<iterations>*<b64 email>*<b64 hash>
//
//	masterKey = PBKDF2-SHA256(password, email, iterations, 32)
//	hash      = PBKDF2-SHA256(masterKey, password, 1, 32)

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyBitwarden(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$bitwarden$") {
		return false, errors.New("invalid Bitwarden hash (missing $bitwarden$ prefix)")
	}
	f := strings.Split(targetHash[len("$bitwarden$"):], "*")
	if len(f) != 4 {
		return false, errors.New("invalid Bitwarden hash (need type*iter*email*hash)")
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 {
		return false, errors.New("invalid Bitwarden iteration count")
	}
	email, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil {
		return false, errors.New("invalid Bitwarden email")
	}
	want, err := base64.StdEncoding.DecodeString(f[3])
	if err != nil || len(want) == 0 {
		return false, errors.New("invalid Bitwarden hash")
	}
	masterKey := pbkdf2.Key([]byte(candidate), email, iter, 32, sha256.New)
	got := pbkdf2.Key(masterKey, []byte(candidate), 1, 32, sha256.New)
	return bytesEqualCT(got, want), nil
}
