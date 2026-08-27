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
	got, ok := sapCodvnFGDigest(user, candidate)
	if !ok {
		return false, nil
	}
	return strings.EqualFold(hex.EncodeToString(got), want), nil
}

func verifySAPCodvnFGRFCReadTable(targetHash, candidate string) (bool, error) {
	i := strings.LastIndexByte(targetHash, '$')
	if i <= 0 {
		return false, errors.New("invalid SAP RFC_READ_TABLE PASSCODE hash (need user$hash)")
	}
	user, want := targetHash[:i], targetHash[i+1:]
	if len(want) != 40 || !isHex(want) || !strings.EqualFold(want[20:], "00000000000000000000") {
		return false, errors.New("invalid SAP RFC_READ_TABLE PASSCODE digest")
	}
	got, ok := sapCodvnFGDigest(user, candidate)
	if !ok {
		return false, nil
	}
	return strings.EqualFold(hex.EncodeToString(got[:10]), want[:20]), nil
}

func sapCodvnFGDigest(user, candidate string) ([]byte, bool) {
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
		return nil, false
	}

	final := sha1.New()
	final.Write(pw)
	final.Write(sapMagicArray[offset : offset+length])
	final.Write(salt)
	return final.Sum(nil), true
}

// isSAPCodvnFG: <username>$<40-char sha1 hex>.
func isSAPCodvnFG(s string) bool {
	i := strings.LastIndexByte(s, '$')
	if i <= 0 {
		return false
	}
	return len(s[i+1:]) == 40 && isHex(s[i+1:]) && !strings.Contains(s[:i], "$")
}

func isSAPCodvnFGRFCReadTable(s string) bool {
	i := strings.LastIndexByte(s, '$')
	return i > 0 && len(s[i+1:]) == 40 && isHex(s[i+1:]) &&
		strings.EqualFold(s[i+21:], "00000000000000000000") && !strings.Contains(s[:i], "$")
}
