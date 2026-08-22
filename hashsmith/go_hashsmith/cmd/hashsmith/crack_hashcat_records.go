package main

// Compact application records added for Hashcat/John interoperability. These
// are kept together because they are all self-contained digest/KDF envelopes
// rather than encrypted containers.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyDANESHA256(target, candidate string) (bool, error) {
	if len(target) != 56 || !isHex(target) {
		return false, errors.New("invalid DANE SHA2-256 digest (need 56 hex chars)")
	}
	sum := sha256.Sum256([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(sum[:28]), target), nil
}

func verifySamsungAndroid(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 || len(parts[0]) != 40 || !isHex(parts[0]) ||
		len(parts[1]) == 0 || len(parts[1]) > 16 {
		return false, errors.New("invalid Samsung Android password/PIN record")
	}
	salt := parts[1]
	first := sha1.Sum([]byte("0" + candidate + salt))
	digest := first[:]
	for i := 1; i < 1024; i++ {
		h := sha1.New()
		_, _ = h.Write(digest)
		_, _ = fmt.Fprintf(h, "%d%s%s", i, candidate, salt)
		digest = h.Sum(nil)
	}
	return strings.EqualFold(hex.EncodeToString(digest), parts[0]), nil
}

func verifySSPR(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "sspr" {
		return false, errors.New("invalid NetIQ/Adobe SSPR record")
	}
	version, err := strconv.Atoi(parts[2])
	if err != nil || version < 0 || version > 4 {
		return false, errors.New("unsupported SSPR version")
	}
	iterations, err := strconv.Atoi(parts[3])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid SSPR iteration count")
	}
	if len(parts[4]) == 0 || len(parts[4]) > maxKDFFieldSize {
		return false, errors.New("invalid SSPR salt")
	}
	var newHash func() hash.Hash
	switch version {
	case 0:
		newHash = md5.New
	case 1, 2:
		newHash = sha1.New
	case 3:
		newHash = sha256.New
	case 4:
		newHash = sha512.New
	}
	if (version < 2 && parts[4] != "NONE") || (version >= 2 && parts[4] == "NONE") {
		return false, errors.New("invalid SSPR salt for version")
	}
	want, err := hex.DecodeString(parts[5])
	if err != nil || len(want) != newHash().Size() {
		return false, errors.New("invalid SSPR checksum")
	}
	initial := candidate
	if version >= 2 {
		// NetIQ hashes the serialized Base64 salt text; Adobe AEM hashes its
		// serialized hexadecimal salt. In both records that is parts[4].
		initial = parts[4] + candidate
	}
	h := newHash()
	_, _ = h.Write([]byte(initial))
	digest := h.Sum(nil)
	for i := 1; i < iterations; i++ {
		h = newHash()
		_, _ = h.Write(digest)
		digest = h.Sum(nil)
	}
	return bytesEqualCT(digest, want), nil
}

func isSSPR(target string) bool {
	return strings.HasPrefix(target, "$sspr$")
}

func verifyNetIQPBKDF2(target, candidate string) (bool, error) {
	var newHash func() hash.Hash
	var iterations int
	var salt, want []byte
	var err error
	switch {
	case strings.HasPrefix(target, "$pbkdf2-hmac-sha1$"):
		parts := strings.Split(target, "$")
		if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-hmac-sha1" {
			return false, errors.New("invalid NetIQ PBKDF2-SHA1 record")
		}
		iterations, err = strconv.Atoi(parts[2])
		if err == nil {
			salt, err = hex.DecodeString(parts[3])
		}
		if err == nil {
			want, err = hex.DecodeString(parts[4])
		}
		newHash = sha1.New
	case strings.HasPrefix(target, "$pbkdf2-hmac-sha512$"):
		body := strings.TrimPrefix(target, "$pbkdf2-hmac-sha512$")
		parts := strings.Split(body, ".")
		if len(parts) != 3 {
			return false, errors.New("invalid NetIQ PBKDF2-SHA512 record")
		}
		iterations, err = strconv.Atoi(parts[0])
		if err == nil {
			salt, err = hex.DecodeString(parts[1])
		}
		if err == nil {
			want, err = hex.DecodeString(parts[2])
		}
		newHash = sha512.New
	default:
		return false, errors.New("invalid NetIQ PBKDF2 record")
	}
	if err != nil || iterations < 1 || iterations > maxKDFIterations ||
		len(salt) == 0 || len(salt) > maxKDFFieldSize || len(want) != newHash().Size() {
		return false, errors.New("invalid NetIQ PBKDF2 parameters")
	}
	got := pbkdf2.Key([]byte(candidate), salt, iterations, len(want), newHash)
	return bytesEqualCT(got, want), nil
}

func isNetIQPBKDF2(target string) bool {
	return strings.HasPrefix(target, "$pbkdf2-hmac-sha1$") ||
		strings.HasPrefix(target, "$pbkdf2-hmac-sha512$")
}

func verifyAS400SSHA1(target, candidate string) (bool, error) {
	const prefix = "$as400$ssha1$*"
	if !strings.HasPrefix(target, prefix) {
		return false, errors.New("invalid AS/400 SSHA1 record")
	}
	parts := strings.Split(strings.TrimPrefix(target, prefix), "*")
	if len(parts) != 2 || parts[0] == "" || len([]rune(parts[0])) > 10 ||
		len(parts[1]) != 40 || !isHex(parts[1]) {
		return false, errors.New("invalid AS/400 username or checksum")
	}
	username := []rune(strings.ToUpper(parts[0]))
	for len(username) < 10 {
		username = append(username, ' ')
	}
	input := append(utf16be(string(username[:10])), utf16be(candidate)...)
	sum := sha1.Sum(input)
	return strings.EqualFold(hex.EncodeToString(sum[:]), parts[1]), nil
}

func isAS400SSHA1(target string) bool {
	return strings.HasPrefix(target, "$as400$ssha1$*")
}

func verifyAuthMeSHA256(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "SHA" ||
		len(parts[2]) != 16 || len(parts[3]) != 64 || !isHex(parts[3]) {
		return false, errors.New("invalid AuthMe SHA256 record")
	}
	inner := sha256.Sum256([]byte(candidate))
	outer := sha256.Sum256([]byte(hex.EncodeToString(inner[:]) + parts[2]))
	return strings.EqualFold(hex.EncodeToString(outer[:]), parts[3]), nil
}

func isAuthMeSHA256(target string) bool {
	return strings.HasPrefix(target, "$SHA$")
}

func verifyPHPS(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "PHPS" ||
		len(parts[2]) == 0 || len(parts[2]) > maxKDFFieldSize*2 ||
		len(parts[3]) != 32 || !isHex(parts[3]) {
		return false, errors.New("invalid PHPS record")
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false, errors.New("invalid PHPS hexadecimal salt")
	}
	inner := md5.Sum([]byte(candidate))
	h := md5.New()
	_, _ = h.Write([]byte(hex.EncodeToString(inner[:])))
	_, _ = h.Write(salt)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), parts[3]), nil
}

func isPHPS(target string) bool {
	return strings.HasPrefix(target, "$PHPS$")
}
