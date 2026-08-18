package main

// SAP CODVN B (BCODE, mode 7700):
//
//	pw   = transtable(password)  (truncated to 8)
//	salt = transtable(username)  (truncated to 12)
//	tk   = md5(pw . salt)
//	dest = bcodeWalk(tk, pw, salt)           (the BCODE magic walk)
//	fk   = md5(dest[:len])
//	hash = fk[i] ^ fk[i+8]  for i in 0..7

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
)

// sapTrans maps a string through the BCODE character transition table.
func sapTrans(s string, maxLen int) []byte {
	b := []byte(s)
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = sapTransTable[c]
	}
	return out
}

// bcodeWalk builds the dest buffer and returns its meaningful length.
func bcodeWalk(tempKey, key, salt []byte) ([]byte, int) {
	sum20 := int(tempKey[0]&3) + int(tempKey[1]&3) + int(tempKey[2]&3) + int(tempKey[3]&3) +
		((int(tempKey[5] & 3)) | 0x20)

	dest := make([]byte, sum20+16) // headroom for the trailing writes
	const off = 15
	I1, I2, I3 := 0, 0, 0
	for I2 < sum20 {
		if I1 < len(key) {
			if tempKey[off-I1]&0x01 != 0 {
				dest[I2] = sapBcodeArr[48-I1-1]
				I2++
			}
			dest[I2] = key[I1]
			I2++
			I1++
		}
		if I3 < len(salt) {
			dest[I2] = salt[I3]
			I2++
			I3++
		}
		idx := I2 - I1 - I3
		if idx >= 0 && idx < len(sapBcodeArr) {
			dest[I2] = sapBcodeArr[idx]
		}
		I2++
		dest[I2] = 0
		I2++
	}
	return dest, sum20
}

func verifySAPCodvnB(targetHash, candidate string) (bool, error) {
	i := strings.LastIndexByte(targetHash, '$')
	if i <= 0 {
		return false, errors.New("invalid SAP CODVN B hash (need user$hash)")
	}
	user := targetHash[:i]
	want := targetHash[i+1:]
	if len(want) != 16 || !isHex(want) {
		return false, errors.New("invalid SAP CODVN B hash (need 16-hex digest)")
	}
	pw := sapTrans(candidate, 8)
	salt := sapTrans(user, 12)

	tk := md5.New()
	tk.Write(pw)
	tk.Write(salt)
	tempKey := tk.Sum(nil)

	dest, n := bcodeWalk(tempKey, pw, salt)
	fkSum := md5.Sum(dest[:n])
	out := make([]byte, 8)
	for j := 0; j < 8; j++ {
		out[j] = fkSum[j] ^ fkSum[j+8]
	}
	return strings.EqualFold(hex.EncodeToString(out), want), nil
}

func isSAPCodvnB(s string) bool {
	i := strings.LastIndexByte(s, '$')
	if i <= 0 {
		return false
	}
	return len(s[i+1:]) == 16 && isHex(s[i+1:]) && !strings.Contains(s[:i], "$")
}
