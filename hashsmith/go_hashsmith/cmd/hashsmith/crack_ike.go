package main

// IKE aggressive-mode pre-shared-key (IKE-PSK), MD5 and SHA-1:
//
//	<g^xr>:<g^xi>:<CKY-R>:<CKY-I>:<SAi_b>:<IDir_b>:<Ni_b>:<Nr_b>:<HASH_R>
//
//	SKEYID = prf(psk, Ni_b . Nr_b)
//	HASH_R = prf(SKEYID, g^xr . g^xi . CKY-R . CKY-I . SAi_b . IDir_b)
//
// prf is HMAC-MD5 (16-byte HASH_R) or HMAC-SHA1 (20-byte HASH_R); the length of
// the final field selects it.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

func verifyIKE(targetHash, candidate string) (bool, error) {
	f := strings.Split(targetHash, ":")
	if len(f) != 9 {
		return false, errors.New("invalid IKE-PSK hash (need 9 colon-separated fields)")
	}
	fields := make([][]byte, 9)
	for i, s := range f {
		b, err := hex.DecodeString(s)
		if err != nil {
			return false, errors.New("invalid IKE-PSK field " + s)
		}
		fields[i] = b
	}
	var newHash func() hash.Hash
	switch len(fields[8]) {
	case 16:
		newHash = md5.New
	case 20:
		newHash = sha1.New
	default:
		return false, errors.New("invalid IKE-PSK HASH_R length (need MD5 or SHA-1)")
	}

	// SKEYID = prf(psk, Ni . Nr).
	sk := hmac.New(newHash, []byte(candidate))
	sk.Write(fields[6])
	sk.Write(fields[7])
	skeyid := sk.Sum(nil)

	// HASH_R = prf(SKEYID, g^xr . g^xi . CKY-R . CKY-I . SAi_b . IDir_b).
	hr := hmac.New(newHash, skeyid)
	for _, i := range []int{0, 1, 2, 3, 4, 5} {
		hr.Write(fields[i])
	}
	return hmac.Equal(hr.Sum(nil), fields[8]), nil
}

// isIKE: 9 hex fields with a 16- or 20-byte final HASH_R.
func isIKE(s string) bool {
	f := strings.Split(s, ":")
	if len(f) != 9 {
		return false
	}
	for _, x := range f {
		if x == "" || len(x)%2 != 0 || !isHex(x) {
			return false
		}
	}
	return len(f[8]) == 32 || len(f[8]) == 40
}
