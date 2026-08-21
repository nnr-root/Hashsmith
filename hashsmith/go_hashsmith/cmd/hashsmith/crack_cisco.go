package main

// Cisco IOS password hashes:
//
//	<hash>             type 4 — raw SHA-256 with Cisco crypt-64 encoding
//	$8$<salt>$<hash>   type 8 — PBKDF2-HMAC-SHA256, 20000 iterations
//	$9$<salt>$<hash>   type 9 — scrypt (N=16384, r=1, p=1)
//
// Both derive 32 bytes and encode them with the crypt-64 alphabet in MSB-first
// 3-byte groups, keeping 43 characters. The salt is the literal 14-char string.

import (
	"crypto/sha256"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// verifyCiscoType4 checks the unsalted 43-character IOS type 4 value.
func verifyCiscoType4(targetHash, candidate string) (bool, error) {
	target := strings.TrimPrefix(targetHash, "$4$")
	if len(target) != 43 {
		return false, errors.New("invalid Cisco type 4 hash length")
	}
	for i := range target {
		if strings.IndexByte(itoa64, target[i]) < 0 {
			return false, errors.New("invalid Cisco type 4 character")
		}
	}
	digest := sha256.Sum256([]byte(candidate))
	return cryptB64MSB(digest[:])[:43] == target, nil
}

func isCiscoType4(target string) bool {
	target = strings.TrimPrefix(target, "$4$")
	if len(target) != 43 {
		return false
	}
	for i := range target {
		if strings.IndexByte(itoa64, target[i]) < 0 {
			return false
		}
	}
	return true
}

// cryptB64MSB encodes bytes with the crypt-64 alphabet, MSB-first per 3-byte
// group (as used by Cisco type 8/9, distinct from the LSB-first crypt output).
func cryptB64MSB(b []byte) string {
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		g := uint32(b[i]) << 16
		if i+1 < len(b) {
			g |= uint32(b[i+1]) << 8
		}
		if i+2 < len(b) {
			g |= uint32(b[i+2])
		}
		out.WriteByte(itoa64[(g>>18)&0x3f])
		out.WriteByte(itoa64[(g>>12)&0x3f])
		out.WriteByte(itoa64[(g>>6)&0x3f])
		out.WriteByte(itoa64[g&0x3f])
	}
	return out.String()
}

// verifyCiscoType8 checks a candidate against a $8$ hash.
func verifyCiscoType8(targetHash, candidate string) (bool, error) {
	salt, want, err := parseCisco(targetHash, "$8$")
	if err != nil {
		return false, err
	}
	dk := pbkdf2.Key([]byte(candidate), []byte(salt), 20000, 32, sha256.New)
	return cryptB64MSB(dk)[:43] == want, nil
}

// verifyCiscoType9 checks a candidate against a $9$ hash.
func verifyCiscoType9(targetHash, candidate string) (bool, error) {
	salt, want, err := parseCisco(targetHash, "$9$")
	if err != nil {
		return false, err
	}
	dk, err := scrypt.Key([]byte(candidate), []byte(salt), 16384, 1, 1, 32)
	if err != nil {
		return false, err
	}
	return cryptB64MSB(dk)[:43] == want, nil
}

// parseCisco splits "$8$<salt>$<hash>" (or $9$) into salt and hash.
func parseCisco(target, prefix string) (salt, hash string, err error) {
	if !strings.HasPrefix(target, prefix) {
		return "", "", errors.New("invalid Cisco hash (wrong prefix)")
	}
	parts := strings.Split(target[len(prefix):], "$")
	if len(parts) != 2 || len(parts[1]) != 43 {
		return "", "", errors.New("invalid Cisco hash (need salt$hash, 43-char hash)")
	}
	return parts[0], parts[1], nil
}
