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
	// John writes the record on a line of its own fields: a username before
	// it, and after it the five-byte RC4 key that opens the document outright.
	// Neither belongs to the record.
	if rewritten, ok := johnOldOfficeRecord(targetHash); ok {
		targetHash = rewritten
	}
	targetHash, collider, err := splitColliderAnswer(targetHash)
	if err != nil {
		return false, err
	}
	parts := strings.Split(targetHash, "*")
	if len(parts) < 4 || len(parts) > 5 || !strings.HasPrefix(parts[0], "$oldoffice$") {
		return false, errors.New("invalid oldoffice hash format")
	}
	version := strings.TrimPrefix(parts[0], "$oldoffice$")
	salt, err2 := decodeOldOfficeField("salt", parts[1], 16)
	if err2 != nil {
		return false, err2
	}
	encVerifier, err2 := decodeOldOfficeField("encrypted verifier", parts[2], 16)
	if err2 != nil {
		return false, err2
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
		return verifyOldOfficeMD5(candidate, salt, encVerifier, encHash, collider)

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
		return verifyOldOfficeSHA1(candidate, salt, encVerifier, encHash, secondBlock, version == "3", collider)
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

func verifyOldOfficeMD5(candidate string, salt, encVerifier, encHash, collider []byte) (bool, error) {
	first := md5.Sum(utf16le(candidate))
	seed := first[:5]
	repeated := make([]byte, 0, 16*(len(seed)+len(salt)))
	for i := 0; i < 16; i++ {
		repeated = append(repeated, seed...)
		repeated = append(repeated, salt...)
	}
	second := md5.Sum(repeated)
	// Hashcat's -m 9710 recovers exactly these five bytes, and -m 9720 then
	// searches for a password that produces them. When a record carries that
	// answer, checking it here settles the candidate after two MD5s instead of
	// three plus an RC4 stream — the same shortcut, for the same reason.
	if len(collider) > 0 && !equalConst(second[:len(collider)], collider) {
		return false, nil
	}
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

func verifyOldOfficeSHA1(candidate string, salt, encVerifier, encHash, secondBlock []byte, version3 bool, collider []byte) (bool, error) {
	h := sha1.New()
	h.Write(salt)
	h.Write(utf16le(candidate))
	base := h.Sum(nil)

	key := oldOfficeSHA1Key(base, 0, version3)
	// The SHA-1 collider's answer is the RC4 key itself, not the value one
	// step earlier as in the MD5 form — measured against hashcat's own
	// examples rather than assumed symmetric.
	if len(collider) > 0 && !equalConst(key[:len(collider)], collider) {
		return false, nil
	}
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

// splitColliderAnswer separates a record from the trailing answer that
// hashcat's "collider #1" modes produce. It lives here beside the MS Office
// verifier but serves the PDF one too, because hashcat spells the split the
// same way in both.
//
// Hashcat splits this format in two. -m 9710 and -m 9810 recover a five-byte
// intermediate — for MD5 the value one step before the RC4 key, for SHA-1 the
// RC4 key itself — and -m 9720 and -m 9820 take that answer, appended to the
// record after a colon, and find the password behind it.
//
// Hashsmith does not need the two stages: it recovers the password from the
// bare record in one pass, which is why 9710 and 9810 are not offered as modes
// at all rather than being pointed at a password cracker that would answer a
// different question. What it does accept is the RECORD those modes produce,
// so a 9720 or 9820 record from an existing hashcat workflow runs here
// unchanged — and the appended answer is not discarded but used, as the
// cheap pre-filter it is.
func splitColliderAnswer(target string) (string, []byte, error) {
	i := strings.LastIndexByte(target, ':')
	if i < 0 {
		return target, nil, nil
	}
	tail := target[i+1:]
	// Five bytes is what both collider modes emit. Anything else after a
	// colon is not a collider answer — a username prefix would come BEFORE
	// the record, not after it — so the record is left whole and fails its
	// own field checks with a message about the field, not about colliders.
	if len(tail) != 10 {
		return target, nil, nil
	}
	b, err := hex.DecodeString(tail)
	if err != nil {
		return target, nil, nil
	}
	return target[:i], b, nil
}
