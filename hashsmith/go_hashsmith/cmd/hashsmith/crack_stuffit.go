package main

// StuffIt5 archives — Hashcat 24700.
//
// The stored value is five bytes: MD5 of the password, truncated to five
// bytes, MD5'd again, truncated to five bytes. No salt, no iterations, and a
// 40-bit result — so collisions are not a theoretical concern here, they are
// the expected outcome of any sizeable run. That is the format, not a choice.

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
)

const stuffitDigestLen = 5

func verifyStuffit5(target, candidate string) (bool, error) {
	want := strings.TrimSpace(target)
	if len(want) != stuffitDigestLen*2 || !isHex(want) {
		return false, errors.New("StuffIt5 hash must be 10 hex characters")
	}
	first := md5.Sum([]byte(candidate))
	second := md5.Sum(first[:stuffitDigestLen])
	return strings.EqualFold(hex.EncodeToString(second[:stuffitDigestLen]), want), nil
}
