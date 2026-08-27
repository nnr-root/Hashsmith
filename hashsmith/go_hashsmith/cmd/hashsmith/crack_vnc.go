package main

import (
	"crypto/des"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/bits"
	"strings"
)

// verifyVNC implements the classic RFB VNC Authentication challenge-response
// used by vncpcap2john. VNC uses the first eight password bytes as a DES key
// after reversing the bit order within each byte.
func verifyVNC(target, candidate string) (bool, error) {
	if !strings.HasPrefix(target, "$vnc$*") {
		return false, errors.New("invalid VNC authentication record")
	}
	f := strings.Split(strings.TrimPrefix(target, "$vnc$*"), "*")
	if len(f) != 2 {
		return false, errors.New("invalid VNC authentication record")
	}
	challenge, e1 := hex.DecodeString(f[0])
	response, e2 := hex.DecodeString(f[1])
	if e1 != nil || e2 != nil || len(challenge) != 16 || len(response) != 16 {
		return false, errors.New("VNC challenge and response must each be 16 bytes")
	}
	key := make([]byte, 8)
	copy(key, []byte(candidate))
	for i := range key {
		key[i] = bits.Reverse8(key[i])
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return false, err
	}
	got := make([]byte, 16)
	block.Encrypt(got[:8], challenge[:8])
	block.Encrypt(got[8:], challenge[8:])
	return subtle.ConstantTimeCompare(got, response) == 1, nil
}
