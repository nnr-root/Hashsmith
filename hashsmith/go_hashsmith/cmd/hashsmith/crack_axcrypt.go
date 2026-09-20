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
	// AxCrypt 1 keeps the in-memory SHA-1 truncated to its first 16 bytes, and
	// that is the form hashcat -m 13300 publishes (32 hex characters). The full
	// 40-character digest is accepted too, so a record from either source works.
	if (len(want) != 40 && len(want) != 32) || !isHex(want) {
		return false, errors.New("invalid AxCrypt-SHA1 digest (need 32 or 40 hex chars)")
	}
	d := sha1.Sum([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(d[:])[:len(want)], want), nil
}
