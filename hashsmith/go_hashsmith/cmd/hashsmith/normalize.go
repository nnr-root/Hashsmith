package main

import (
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
	8:  {"MySQL 3.x", "CRC-64", "FNV-1a-64"},
	16: {"MD5", "NTLM", "MD4", "MD2", "LM"},
	20: {"SHA-1", "SHA-0", "RIPEMD-160"},
	28: {"SHA-224", "SHA-512/224", "SHA3-224"},
	32: {"SHA-256", "SHA-512/256", "SHA3-256", "SM3", "Keccak-256", "SHAKE128-256", "BLAKE2s", "BLAKE2b-256", "Streebog-256"},
	48: {"SHA-384", "SHA3-384", "BLAKE2b-384"},
	64: {"SHA-512", "SHA3-512", "Keccak-512", "SHAKE256-512", "BLAKE2b", "Whirlpool", "Streebog-512"},
}

// normalizeHashInput detects whether target is a Base32/Base58/Base62/Base64-encoded
// hash digest, decodes it to raw bytes, and returns the lowercase hex string.
// format names the encoding when a conversion occurred,
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

	// Checksummed Bech32 transports are unambiguous; accept either checksum
	// variant when the decoded payload has a known digest length.
	for _, typ := range []string{"bech32", "bech32m"} {
		if b, _, err := decodeBech32(target, "", typ); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), strings.ToUpper(typ[:1]) + typ[1:]
		}
	}

	// Try Base58 — only accept when decoded byte length matches a known hash.
	if reBase58Pat.MatchString(target) && len(target) >= 8 {
		if b, err := decodeBase58Check(target); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base58Check"
		}
		if b, err := decodeBase58(target); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base58"
		}
	}

	// Try Base64 standard.
	if reBase64Std.MatchString(target) && len(target)%4 != 1 {
		if b, err := decodeBase64Flexible(target, false); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base64"
		}
	}

	// Try Base64 URL-safe (with auto-padding).
	if reBase64URL.MatchString(target) && !strings.ContainsAny(target, "+/") {
		if b, err := decodeBase64Flexible(target, true); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base64 URL"
		}
	}

	// Try standard and extended-hex Base32, accepting padded and unpadded input.
	upper := strings.ToUpper(target)
	if strings.ContainsAny(strings.ToLower(target), "13456789") {
		if b, err := decodeZBase32(target); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "z-base-32"
		}
	}
	if reBase32Std.MatchString(upper) {
		if b, err := decodeBase32Flexible(upper, false); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base32"
		}
	}
	if reBase32Hex.MatchString(upper) && strings.ContainsAny(upper, "0189") {
		if b, err := decodeBase32Flexible(upper, true); err == nil && knownHashLen(len(b)*2) {
			return hex.EncodeToString(b), "Base32hex"
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
