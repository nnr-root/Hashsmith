package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// isBase62Only returns true when s uses only Base62 chars AND contains at least
// one char that is not in the Base58 alphabet (0, O, I, l), confirming it is
// not merely a Base58-encoded value.  Used to guard the normalisation path so
// we don't double-decode strings that are already handled by the Base58 branch.
func isBase62Only(s string) bool {
	if !reBase62Pat.MatchString(s) || strings.ContainsAny(s, "+/=_-") {
		return false
	}
	return hasBase62OnlyChar(s)
}

// hashByteLengths maps raw digest byte-length to the algorithm names that
// produce that output size.  Single source of truth for both speculative
// identify and automatic crack normalisation.
var hashByteLengths = map[int][]string{
	8:  {"MySQL 3.x"},
	16: {"MD5", "NTLM", "MD4"},
	20: {"SHA-1", "RIPEMD-160"},
	28: {"SHA-224"},
	32: {"SHA-256", "SHA3-256", "BLAKE2s"},
	48: {"SHA-384"},
	64: {"SHA-512", "SHA3-512", "BLAKE2b"},
}

// normalizeHashInput detects whether target is a Base58- or Base64-encoded
// hash digest, decodes it to raw bytes, and returns the lowercase hex string.
// format is "Base58", "Base64", or "Base64 URL" when a conversion occurred,
// and "" when the input was already hex or is an opaque format (bcrypt /
// argon2 / scrypt / etc.) that must be passed through unchanged.
func normalizeHashInput(target string) (hexHash, format string) {
	target = strings.TrimSpace(target)

	// Already hex → nothing to do.
	if isHex(target) {
		return target, ""
	}

	// Signature-based opaque formats must not be decoded.
	if reBcrypt.MatchString(target) || reArgon2.MatchString(target) ||
		reScrypt.MatchString(target) || rePostgres.MatchString(target) ||
		reMySQL41.MatchString(target) || reMSSQLNew.MatchString(target) {
		return target, ""
	}

	// Try Base58 — only accept when decoded byte length matches a known hash.
	if reBase58Pat.MatchString(target) && len(target) >= 8 {
		if b, err := decodeBase58(target); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base58"
		}
	}

	// Try Base64 standard.
	if reBase64Std.MatchString(target) && len(target)%4 == 0 {
		if b, err := base64.StdEncoding.DecodeString(target); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base64"
		}
	}

	// Try Base64 URL-safe (with auto-padding).
	if reBase64URL.MatchString(target) && !strings.ContainsAny(target, "+/") {
		padding := strings.Repeat("=", (4-len(target)%4)%4)
		if b, err := base64.URLEncoding.DecodeString(target+padding); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base64 URL"
		}
	}

	// Try Base62 — only when the string contains at least one char outside Base58
	// (0, O, I, l) so we don't re-decode strings already handled by the Base58 branch.
	if isBase62Only(target) && len(target) >= 8 {
		if b, err := decodeBase62(target); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base62"
		}
	}

	return target, "" // unchanged
}
