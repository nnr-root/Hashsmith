package main

// Sybase ASE:  0xc007<salt><hash>
//
//	hash = sha256( utf16be(password) . zero-pad-to-510-bytes . salt[8] )

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"
)

// utf16be encodes a string as big-endian UTF-16.
func utf16be(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}

func verifySybaseASE(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "0xc007") || len(targetHash) != 6+16+64 {
		return false, errors.New("invalid Sybase ASE hash (need 0xc007 + 8-byte salt + 32-byte sha256)")
	}
	salt, err := hex.DecodeString(targetHash[6:22])
	if err != nil {
		return false, errors.New("invalid Sybase ASE salt")
	}
	want := targetHash[22:]

	pw := utf16be(candidate)
	if len(pw) > 510 {
		return false, nil
	}
	buf := make([]byte, 518)
	copy(buf, pw) // remainder up to offset 510 stays zero
	copy(buf[510:], salt)
	got := sha256.Sum256(buf)
	return strings.EqualFold(hex.EncodeToString(got[:]), want), nil
}

func isSybaseASE(s string) bool {
	return strings.HasPrefix(s, "0xc007") && len(s) == 86 && isHex(s[2:])
}
