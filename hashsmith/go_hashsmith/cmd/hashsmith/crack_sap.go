package main

// SAP CODVN F/G (PASSCODE / iSSHA-1):
//
//	salt    = uppercase(username)
//	key     = sha1(password . salt)
//	length  = Σ(key[0..9] % 6) + 0x20
//	offset  = Σ(key[10..19] % 8)
//	digest  = sha1(password . magicArray[offset:offset+length] . salt)
//	hash    = "<UPPER-USER>$<UPPER-HEX-DIGEST>"

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

func verifySAPCodvnFG(targetHash, candidate string) (bool, error) {
	i := strings.LastIndexByte(targetHash, '$')
	if i < 0 {
		return false, errors.New("invalid SAP CODVN F/G hash (need user$sha1)")
	}
	user := targetHash[:i]
	want := targetHash[i+1:]
	if len(want) != 40 || !isHex(want) {
		return false, errors.New("invalid SAP CODVN F/G hash (need 40-hex digest)")
	}
	salt := []byte(strings.ToUpper(user))
	pw := []byte(candidate)

	first := sha1.New()
	first.Write(pw)
	first.Write(salt)
	key := first.Sum(nil)

	length := 0x20
	for j := 0; j < 10; j++ {
		length += int(key[j]) % 6
	}
	offset := 0
	for j := 10; j < 20; j++ {
		offset += int(key[j]) % 8
	}
	if offset+length > len(sapMagicArray) {
		return false, nil
	}

	final := sha1.New()
	final.Write(pw)
	final.Write(sapMagicArray[offset : offset+length])
	final.Write(salt)
	got := strings.ToUpper(hex.EncodeToString(final.Sum(nil)))
	return got == strings.ToUpper(want), nil
}

// isSAPCodvnFG: <username>$<40-char sha1 hex>.
func isSAPCodvnFG(s string) bool {
	i := strings.LastIndexByte(s, '$')
	if i <= 0 {
		return false
	}
	return len(s[i+1:]) == 40 && isHex(s[i+1:]) && !strings.Contains(s[:i], "$")
}
