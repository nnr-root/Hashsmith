package main

// SAP's Personal Security Environment file.
//
//	$pse$<version>$<iterations>$<salt size>$<salt>$<?>$<?>$<pin size>$<pin>
//
// A PSE holds an SAP system's private keys and certificates, and the "PIN"
// protecting it is checked in a way worth describing plainly: the file stores
// the PIN ENCRYPTED UNDER A KEY DERIVED FROM THE PIN. So a candidate is
// checked by deriving the key, encrypting the candidate with it, and seeing
// whether that is what the file holds.
//
// That makes the verifier exactly as long as the password — eight bytes of
// ciphertext for a password of eight or fewer — and it means the check is a
// single 3DES block for short passwords rather than a decryption of anything.
// It also means a password of eight characters and a password of nine cannot
// collide, because the stored length differs.
//
// The derivation is PKCS#12's, from RFC 7292 appendix B: the same one a .p12
// file uses, run twice — once with the key diversifier and once with the IV's.

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

const sapPSEPrefix = "$pse$"

type sapPSERecord struct {
	iterations int
	salt       []byte
	pin        []byte
}

func sapPSEFields(target string) (sapPSERecord, error) {
	var r sapPSERecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, sapPSEPrefix) {
		return r, errors.New("not a SAP PSE record")
	}
	f := strings.Split(t[len(sapPSEPrefix):], "$")
	if len(f) != 8 {
		return r, errors.New("a SAP PSE record has eight fields")
	}
	var err error
	if r.iterations, err = boundedPositiveInt(f[1], "SAP PSE iteration count", 1<<24); err != nil {
		return r, err
	}
	saltSize, err := boundedPositiveInt(f[2], "SAP PSE salt size", 64)
	if err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[3], saltSize, "SAP PSE salt"); err != nil {
		return r, err
	}
	pinSize, err := boundedPositiveInt(f[6], "SAP PSE encrypted PIN size", 256)
	if err != nil {
		return r, err
	}
	if r.pin, err = hex.DecodeString(f[7]); err != nil || len(r.pin) != pinSize {
		return r, errors.New("the SAP PSE encrypted PIN does not match its stated length")
	}
	if len(r.pin) < des.BlockSize {
		return r, errors.New("a SAP PSE encrypted PIN is at least one block")
	}
	return r, nil
}

func verifySAPPSE(target, candidate string) (bool, error) {
	r, err := sapPSEFields(target)
	if err != nil {
		return false, err
	}
	key := pkcs12KDF(candidate, r.salt, r.iterations, 1, 24, sha1.New)
	iv := pkcs12KDF(candidate, r.salt, r.iterations, 2, des.BlockSize, sha1.New)

	// The candidate is padded the PKCS#7 way to a whole block, then encrypted.
	// Only the first block is compared, which is all John compares and all a
	// short password produces.
	input := make([]byte, des.BlockSize)
	if len(candidate) >= des.BlockSize {
		copy(input, candidate)
	} else {
		copy(input, candidate)
		pad := byte(des.BlockSize - len(candidate))
		for i := len(candidate); i < des.BlockSize; i++ {
			input[i] = pad
		}
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return false, err
	}
	var out [des.BlockSize]byte
	// One block of CBC is the IV XORed in and then encrypted.
	var xored [des.BlockSize]byte
	for i := range xored {
		xored[i] = input[i] ^ iv[i]
	}
	block.Encrypt(out[:], xored[:])
	return hmac.Equal(out[:], r.pin[:des.BlockSize]), nil
}

func isSAPPSE(target string) bool {
	_, err := sapPSEFields(target)
	return err == nil
}
