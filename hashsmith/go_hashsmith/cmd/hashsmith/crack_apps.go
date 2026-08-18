package main

// Assorted application password formats sharing PBKDF2/HMAC machinery:
//
//	$ml$<iter>$<salt_hex>$<entropy_hex>   macOS 10.8+ (PBKDF2-HMAC-SHA512)
//	{PKCS5S2}<base64>                      Atlassian (PBKDF2-HMAC-SHA1, 10000)
//	<header>.<payload>.<signature>         JWT (HMAC-SHA256/384/512)

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ── macOS 10.8+ ($ml$) ──

func verifyMacOS(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$ml$") {
		return false, errors.New("invalid macOS hash (missing $ml$ prefix)")
	}
	f := strings.Split(targetHash[len("$ml$"):], "$")
	if len(f) != 3 {
		return false, errors.New("invalid macOS hash (need iter$salt$entropy)")
	}
	iter, err := strconv.Atoi(f[0])
	if err != nil || iter < 1 {
		return false, errors.New("invalid macOS iteration count")
	}
	salt, err := hex.DecodeString(f[1])
	if err != nil {
		return false, errors.New("invalid macOS salt")
	}
	want, err := hex.DecodeString(f[2])
	if err != nil || len(want) == 0 {
		return false, errors.New("invalid macOS entropy")
	}
	got := pbkdf2.Key([]byte(candidate), salt, iter, len(want), sha512.New)
	return bytesEqualCT(got, want), nil
}

// ── Atlassian ({PKCS5S2}) ──

func verifyAtlassian(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "{PKCS5S2}") {
		return false, errors.New("invalid Atlassian hash (missing {PKCS5S2} prefix)")
	}
	raw, err := base64.StdEncoding.DecodeString(targetHash[len("{PKCS5S2}"):])
	if err != nil || len(raw) != 48 {
		return false, errors.New("invalid Atlassian hash (need base64 of 48 bytes)")
	}
	salt, want := raw[:16], raw[16:48]
	got := pbkdf2.Key([]byte(candidate), salt, 10000, 32, sha1.New)
	return bytesEqualCT(got, want), nil
}

// ── JWT (HMAC) ──

func verifyJWT(targetHash, candidate string) (bool, error) {
	parts := strings.Split(strings.TrimSpace(targetHash), ".")
	if len(parts) != 3 {
		return false, errors.New("invalid JWT (need header.payload.signature)")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, errors.New("invalid JWT header")
	}
	var newHash func() hash.Hash
	switch {
	case strings.Contains(string(headerJSON), "HS256"):
		newHash = sha256.New
	case strings.Contains(string(headerJSON), "HS384"):
		newHash = sha512.New384
	case strings.Contains(string(headerJSON), "HS512"):
		newHash = sha512.New
	default:
		return false, errors.New("unsupported JWT alg (only HS256/384/512)")
	}
	mac := hmac.New(newHash, []byte(candidate))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	got := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return got == parts[2], nil
}

// isJWT reports whether s has the three-part HS-signed JWT shape.
func isJWT(s string) bool {
	if !reJWT.MatchString(strings.TrimSpace(s)) {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(strings.SplitN(s, ".", 2)[0])
	if err != nil {
		return false
	}
	h := string(header)
	return strings.Contains(h, "HS256") || strings.Contains(h, "HS384") || strings.Contains(h, "HS512")
}
