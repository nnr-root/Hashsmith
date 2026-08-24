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
	version := ""
	switch {
	case strings.HasPrefix(targetHash, "$solarwinds$0$"):
		version = "0"
	case strings.HasPrefix(targetHash, "$solarwinds$1$"):
		version = "1"
	default:
		return false, errors.New("invalid SolarWinds hash (need $solarwinds$0$ or $solarwinds$1$)")
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
	var effSalt []byte
	if version == "0" {
		if len(saltField) == 0 || len(saltField) > maxKDFFieldSize {
			return false, errors.New("invalid SolarWinds salt")
		}
		effSalt = []byte((saltField + "1244352345234")[:8])
	} else {
		effSalt, err = base64.StdEncoding.DecodeString(saltField)
		if err != nil || len(effSalt) != 16 {
			return false, errors.New("invalid SolarWinds v2 salt")
		}
	}
	dk := pbkdf2.Key([]byte(candidate), effSalt, 1000, 1024, sha1.New)
	got := sha512.Sum512(dk)
	return bytesEqualCT(got[:], want), nil
}
