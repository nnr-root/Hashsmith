package main

// SolarWinds Orion:
//
//	$solarwinds$0$<salt>$<b64 digest>
//
//	effSalt = (salt . "1244352345234")[:8]
//	dk      = PBKDF2-HMAC-SHA1(password, effSalt, 1000, 1024)
//	digest  = SHA-512(dk)   (base64-encoded in the hash)

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifySolarWinds(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$solarwinds$0$") {
		return false, errors.New("invalid SolarWinds hash (missing $solarwinds$0$ prefix)")
	}
	rest := targetHash[len("$solarwinds$0$"):]
	i := strings.LastIndexByte(rest, '$')
	if i < 0 {
		return false, errors.New("invalid SolarWinds hash (missing digest)")
	}
	saltField := rest[:i]
	want, err := base64.StdEncoding.DecodeString(rest[i+1:])
	if err != nil || len(want) != 64 {
		return false, errors.New("invalid SolarWinds digest")
	}
	effSalt := []byte((saltField + "1244352345234")[:8])
	dk := pbkdf2.Key([]byte(candidate), effSalt, 1000, 1024, sha1.New)
	got := sha512.Sum512(dk)
	return bytesEqualCT(got[:], want), nil
}
