package smith

// The two password hashes macOS used before it moved to PBKDF2.
//
//	xsha     OS X 10.4 through 10.6, in /var/db/shadow/hash: a four-byte salt
//	         and SHA-1 of that salt followed by the password. Hashcat -m 122.
//	xsha512  OS X 10.7, in the ShadowHashData plist: the same shape with
//	         SHA-512. Hashcat -m 1722.
//
// Both are written as one uninterrupted hex string — the salt and the digest
// with nothing between them — which is what makes them identifiable at all:
// forty-eight hex characters is not the length of any bare digest, and
// neither is a hundred and thirty-six.
//
// 10.8 replaced both with the salted PBKDF2 record Hashsmith reads as "macos",
// so these two are what a dump from an older machine, or from a backup of
// one, still holds.

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	macOSLegacySaltHex = 8
	xshaHexLen         = macOSLegacySaltHex + 2*sha1.Size
	xsha512HexLen      = macOSLegacySaltHex + 2*sha512.Size
)

// macOSLegacyFields splits the record into its salt and digest.
func macOSLegacyFields(target string, want int) (salt []byte, digest string, err error) {
	t := strings.TrimSpace(target)
	if len(t) != want || !isHex(t) {
		return nil, "", errors.New("invalid macOS hash (need a salt and digest run together as hex)")
	}
	salt, err = hex.DecodeString(t[:macOSLegacySaltHex])
	if err != nil {
		return nil, "", errors.New("invalid macOS salt")
	}
	return salt, t[macOSLegacySaltHex:], nil
}

// verifyXSHA checks an OS X 10.4-10.6 hash: SHA-1(salt || password).
func verifyXSHA(target, candidate string) (bool, error) {
	salt, digest, err := macOSLegacyFields(target, xshaHexLen)
	if err != nil {
		return false, err
	}
	sum := sha1.Sum(append(salt, candidate...))
	return strings.EqualFold(hex.EncodeToString(sum[:]), digest), nil
}

// verifyXSHA512 checks an OS X 10.7 hash: SHA-512(salt || password).
func verifyXSHA512(target, candidate string) (bool, error) {
	salt, digest, err := macOSLegacyFields(target, xsha512HexLen)
	if err != nil {
		return false, err
	}
	sum := sha512.Sum512(append(salt, candidate...))
	return strings.EqualFold(hex.EncodeToString(sum[:]), digest), nil
}

func isXSHA(target string) bool {
	_, _, err := macOSLegacyFields(target, xshaHexLen)
	return err == nil
}

func isXSHA512(target string) bool {
	_, _, err := macOSLegacyFields(target, xsha512HexLen)
	return err == nil
}
