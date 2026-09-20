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
		return false, errors.New("invalid Ansible Vault hash (need type*cipher*salt*ciphertext*hmac)")
	}
	salt, err := hex.DecodeString(f[2])
	if err != nil {
		return false, errors.New("invalid Ansible salt")
	}
	a, errA := hex.DecodeString(f[3])
	b, errB := hex.DecodeString(f[4])
	if errA != nil || errB != nil {
		return false, errors.New("invalid Ansible ciphertext or HMAC")
	}

	// Two field orders exist for the same record, and the HMAC's fixed
	// 32-byte length tells them apart.
	//
	// An Ansible Vault file stores salt, HMAC, ciphertext in that order, and
	// Hashsmith used to pass them straight through. Both john's ansible2john
	// and hashcat's -m 16900 REORDER them to salt, ciphertext, HMAC — so
	// Hashsmith's records were readable by neither tool, and neither tool's
	// records were readable by Hashsmith.
	//
	// The portable order wins for anything Hashsmith now emits, and the older
	// spelling is still read so existing records do not break.
	data, want := a, b
	if len(b) != sha256.Size && len(a) == sha256.Size {
		data, want = b, a // the old salt*hmac*ciphertext spelling
	}
	if len(want) != sha256.Size {
		return false, errors.New("invalid Ansible HMAC (need 32 bytes)")
	}
	dk := pbkdf2.Key([]byte(candidate), salt, 10000, 80, sha256.New)
	mac := hmac.New(sha256.New, dk[32:64])
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), want), nil
}
