package main

import (
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

// MS Office 97-2003 verifier records produced by office2john and accepted by
// Hashcat modes 9700/9800:
//
//	$oldoffice$0/1*salt*encryptedVerifier*encryptedMD5
//	$oldoffice$3/4*salt*encryptedVerifier*encryptedSHA1[*secondBlock]
func verifyOldOffice(targetHash, candidate, expectedFamily string) (bool, error) {
	parts := strings.Split(targetHash, "*")
	if len(parts) < 4 || len(parts) > 5 || !strings.HasPrefix(parts[0], "$oldoffice$") {
		return false, errors.New("invalid oldoffice hash format")
	}
	version := strings.TrimPrefix(parts[0], "$oldoffice$")
	salt, err := decodeOldOfficeField("salt", parts[1], 16)
	if err != nil {
		return false, err
	}
	encVerifier, err := decodeOldOfficeField("encrypted verifier", parts[2], 16)
	if err != nil {
		return false, err
	}

	switch version {
	case "0", "1":
		if expectedFamily == "sha1" {
			return false, errors.New("oldoffice record does not match selected SHA-1 mode")
		}
		if len(parts) != 4 {
			return false, errors.New("invalid MD5 oldoffice field count")
		}
		encHash, err := decodeOldOfficeField("encrypted MD5 verifier hash", parts[3], md5.Size)
		if err != nil {
			return false, err
		}
		return verifyOldOfficeMD5(candidate, salt, encVerifier, encHash)

	case "3", "4":
		if expectedFamily == "md5" {
			return false, errors.New("oldoffice record does not match selected MD5 mode")
		}
		encHash, err := decodeOldOfficeField("encrypted SHA-1 verifier hash", parts[3], sha1.Size)
		if err != nil {
			return false, err
		}
		var secondBlock []byte
		if len(parts) == 5 {
			if version != "3" {
				return false, errors.New("oldoffice second block is only valid for version 3")
			}
			secondBlock, err = decodeOldOfficeField("encrypted second block", parts[4], 32)
			if err != nil {
				return false, err
			}
		}
		return verifyOldOfficeSHA1(candidate, salt, encVerifier, encHash, secondBlock, version == "3")
	}

	return false, errors.New("unsupported oldoffice version")
}

func decodeOldOfficeField(name, value string, size int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != size {
		return nil, errors.New("invalid oldoffice " + name)
	}
	return b, nil
}

func verifyOldOfficeMD5(candidate string, salt, encVerifier, encHash []byte) (bool, error) {
	first := md5.Sum(utf16le(candidate))
	seed := first[:5]
	repeated := make([]byte, 0, 16*(len(seed)+len(salt)))
	for i := 0; i < 16; i++ {
		repeated = append(repeated, seed...)
		repeated = append(repeated, salt...)
	}
	second := md5.Sum(repeated)
	keyInput := append(append([]byte{}, second[:5]...), 0, 0, 0, 0)
	key := md5.Sum(keyInput)

	plain, err := oldOfficeRC4(key[:], append(append([]byte{}, encVerifier...), encHash...))
	if err != nil {
		return false, err
	}
	verifier := plain[:len(encVerifier)]
	verifierHash := plain[len(encVerifier):]
	want := md5.Sum(verifier)
	return equalConst(want[:], verifierHash), nil
}

func verifyOldOfficeSHA1(candidate string, salt, encVerifier, encHash, secondBlock []byte, version3 bool) (bool, error) {
	h := sha1.New()
	h.Write(salt)
	h.Write(utf16le(candidate))
	base := h.Sum(nil)

	key := oldOfficeSHA1Key(base, 0, version3)
	plain, err := oldOfficeRC4(key, append(append([]byte{}, encVerifier...), encHash...))
	if err != nil {
		return false, err
	}
	verifier := plain[:len(encVerifier)]
	verifierHash := plain[len(encVerifier):]
	want := sha1.Sum(verifier)
	if !equalConst(want[:], verifierHash) {
		return false, nil
	}

	if len(secondBlock) != 0 {
		plain, err := oldOfficeRC4(oldOfficeSHA1Key(base, 1, true), secondBlock)
		if err != nil {
			return false, err
		}
		zeros := 0
		for _, b := range plain {
			if b == 0 {
				zeros++
			}
		}
		if zeros < 10 {
			return false, nil
		}
	}
	return true, nil
}

func oldOfficeSHA1Key(base []byte, block uint32, version3 bool) []byte {
	h := sha1.New()
	h.Write(base)
	h.Write([]byte{byte(block), byte(block >> 8), byte(block >> 16), byte(block >> 24)})
	key := h.Sum(nil)[:16]
	if version3 {
		padded := make([]byte, 16)
		copy(padded, key[:5])
		return padded
	}
	return key
}

func oldOfficeRC4(key, input []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(input))
	c.XORKeyStream(out, input)
	return out, nil
}
