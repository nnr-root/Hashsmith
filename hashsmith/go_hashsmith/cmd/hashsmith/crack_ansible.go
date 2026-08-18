package main

// Ansible Vault (AES256):
//
//	$ansible$0*0*<salt>*<hmac>*<ciphertext>
//
//	dk      = PBKDF2-HMAC-SHA256(password, salt, 10000, 80)
//	hmacKey = dk[32:64]
//	valid  ⇔ HMAC-SHA256(hmacKey, ciphertext) == stored hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyAnsible(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$ansible$") {
		return false, errors.New("invalid Ansible Vault hash (missing $ansible$ prefix)")
	}
	f := strings.Split(targetHash[len("$ansible$"):], "*")
	if len(f) != 5 {
		return false, errors.New("invalid Ansible Vault hash (need type*cipher*salt*hmac*data)")
	}
	salt, err := hex.DecodeString(f[2])
	if err != nil {
		return false, errors.New("invalid Ansible salt")
	}
	want, err := hex.DecodeString(f[3])
	if err != nil || len(want) != 32 {
		return false, errors.New("invalid Ansible HMAC")
	}
	data, err := hex.DecodeString(f[4])
	if err != nil {
		return false, errors.New("invalid Ansible ciphertext")
	}
	dk := pbkdf2.Key([]byte(candidate), salt, 10000, 80, sha256.New)
	mac := hmac.New(sha256.New, dk[32:64])
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), want), nil
}
