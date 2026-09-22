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
	want := strings.TrimSpace(targetHash)
	if strings.HasPrefix(want, "$axcrypt_sha1$") {
		want = want[len("$axcrypt_sha1$"):]
	} else if !isBareAxCryptSHA1(want) {
		return false, errors.New("invalid AxCrypt-SHA1 hash (missing prefix)")
	}
	// John writes the truncated digest in a forty-character field, padded
	// with zeros. Comparing all forty would then fail against a real SHA-1,
	// so the padding is dropped and the sixteen bytes that are there are what
	// is compared — which is all AxCrypt keeps.
	if len(want) == 40 && strings.HasSuffix(want, "00000000") {
		want = want[:32]
	}
	// AxCrypt 1 keeps the in-memory SHA-1 truncated to its first 16 bytes, and
	// that is the form hashcat -m 13300 publishes (32 hex characters). The full
	// 40-character digest is accepted too, so a record from either source works.
	if (len(want) != 40 && len(want) != 32) || !isHex(want) {
		return false, errors.New("invalid AxCrypt-SHA1 digest (need 32 or 40 hex chars)")
	}
	d := sha1.Sum([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(d[:])[:len(want)], want), nil
}

// isBareAxCryptSHA1 reports whether a bare digest is one AxCrypt wrote: the
// first sixteen bytes of a SHA-1 in a forty-character field, so the last
// eight characters are zeros. A real SHA-1 ends that way once in four
// billion, which is what makes the shape worth claiming.
func isBareAxCryptSHA1(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) == 40 && isHex(s) && strings.HasSuffix(s, "00000000")
}

// verifySHA1LinkedIn checks a SHA-1 from the 2012 LinkedIn dump, in which the
// first five hex digits of every cracked hash were overwritten with zeros.
// Twenty fewer bits still leaves a hundred and forty, so the comparison is as
// good as any other — but it has to start at the sixth digit.
func verifySHA1LinkedIn(targetHash, candidate string) (bool, error) {
	want := strings.TrimSpace(targetHash)
	if len(want) != 40 || !isHex(want) {
		return false, errors.New("a LinkedIn SHA-1 is forty hex characters")
	}
	d := sha1.Sum([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(d[:])[5:], want[5:]), nil
}

// isSHA1LinkedIn reports the shape that dump has.
func isSHA1LinkedIn(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) == 40 && isHex(s) && strings.HasPrefix(s, "00000")
}
