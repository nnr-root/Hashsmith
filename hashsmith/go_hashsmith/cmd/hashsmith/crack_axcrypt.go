package main

// AxCrypt 1 in-memory SHA-1:  $axcrypt_sha1$<sha1(password)>
// (The in-memory key is simply the SHA-1 of the passphrase.)

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

func verifyAxCryptSHA1(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$axcrypt_sha1$") {
		return false, errors.New("invalid AxCrypt-SHA1 hash (missing prefix)")
	}
	want := targetHash[len("$axcrypt_sha1$"):]
	if len(want) != 40 || !isHex(want) {
		return false, errors.New("invalid AxCrypt-SHA1 digest")
	}
	d := sha1.Sum([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(d[:]), want), nil
}
