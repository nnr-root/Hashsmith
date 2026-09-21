package main

// John-only record wrappers.
//
// John and hashcat disagree about whether a format's record carries its own
// name. For a dozen formats John writes "$md2$<hex>" where hashcat writes the
// bare digest, or "$django$*1*<payload>" where hashcat writes the payload on
// its own. The algorithm, the parameters and the digest are identical; only
// the envelope differs.
//
// That envelope is not noise, so it cannot simply be stripped on sight. It is
// the ONLY thing distinguishing "$md2$" from any other 32-hex digest — remove
// it before detection and MD2 becomes MD5, MD4 and NTLM, none of which will
// verify. So each wrapper is registered twice: as a detection prototype, so
// the record resolves to the right type, and here, so the verifier for that
// type sees the payload it expects.
//
// Every entry is verified against John's own published test vector for the
// format (testdata/john_format_tests.tsv); the John conformance ratchet keeps
// them honest.

import "strings"

// johnWrappers maps a record envelope John writes to the canonical type whose
// verifier should see the remainder.
//
// Matching is case-insensitive on the envelope name, because John is not
// consistent about it: "$SHA512$" and "$MD4$" are upper case, "$gost$" and
// "$keccak256$" are lower. Nothing downstream depends on the case, so there is
// no reason to make a user reproduce it.
var johnWrappers = []struct{ prefix, typ string }{
	// Raw digests. The envelope is the only thing that makes these
	// identifiable — a bare 128-hex digest is SHA-512, SHA3-512, BLAKE2b,
	// Whirlpool, Streebog-512 or Keccak-512 with nothing to choose between
	// them, and John's records say which.
	{"$sha224$", "sha224"},
	{"$sha256$", "sha256"},
	{"$sha384$", "sha384"},
	{"$sha512$", "sha512"},
	{"$md4$", "md4"},
	{"$md2$", "md2"},
	{"$gost$", "gost"},
	{"$keccak256$", "keccak256"},
	{"$whirlpool$", "whirlpool"},
	// Structured records whose payload this tool reads under another name.
	{"$oracle12c$", "oracle12c"},
	{"$django$*1*", "django"},
	{"$lm$", "lm"},
}

// johnWrapperFor reports the type and payload of a John-enveloped record.
func johnWrapperFor(target string) (typ, payload string, ok bool) {
	for _, w := range johnWrappers {
		if len(target) >= len(w.prefix) && strings.EqualFold(target[:len(w.prefix)], w.prefix) {
			return w.typ, target[len(w.prefix):], true
		}
	}
	return "", "", false
}

// stripJohnWrapper removes a John-only envelope when the record carries one
// and it belongs to the type being verified. Anything else is returned
// unchanged, so a record that merely resembles a wrapper is never mangled.
func stripJohnWrapper(target, typ string) string {
	if wrapped, payload, ok := johnWrapperFor(target); ok && wrapped == typ {
		return payload
	}
	return target
}

// isJohnWrappedRecord reports whether a record carries a John envelope this
// tool can unwrap, for the detection table.
func isJohnWrappedRecord(s string) bool {
	_, payload, ok := johnWrapperFor(strings.TrimSpace(s))
	return ok && payload != ""
}

// johnWrappedTypes names every type a John envelope can resolve to. Detection
// offers the set; the envelope itself narrows it to one at verification time,
// since stripJohnWrapper only unwraps for the matching type.
func johnWrappedTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range johnWrappers {
		if !seen[w.typ] {
			seen[w.typ] = true
			out = append(out, w.typ)
		}
	}
	return out
}

// johnHMACDigestLens are the digest sizes, in hex characters, that John's
// HMAC formats emit: MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512.
var johnHMACDigestLens = map[int]bool{32: true, 40: true, 56: true, 64: true, 96: true, 128: true}

// splitJohnHMAC reads John's `<message>#<digest>` HMAC spelling, the reverse
// of the `<digest>:<message>` pairing used here.
//
// The predicate is deliberately narrow. It splits on the LAST '#', because a
// message may contain one, and it requires the right-hand side to be hex of a
// digest length — which is what keeps it off records like
// "$DCC2$10240#user#hash" that use '#' as an ordinary field separator. A
// leading '$' is refused for the same reason: every record spelled that way
// names its own format and has no business being read as an HMAC message.
func splitJohnHMAC(target string) (message, digest string, ok bool) {
	if target == "" || target[0] == '$' {
		return "", "", false
	}
	i := strings.LastIndexByte(target, '#')
	if i <= 0 || i == len(target)-1 {
		return "", "", false
	}
	message, digest = target[:i], target[i+1:]
	if !johnHMACDigestLens[len(digest)] || !isHex(digest) {
		return "", "", false
	}
	return message, digest, true
}

// isJohnHMACRecord reports whether a record uses John's HMAC spelling.
func isJohnHMACRecord(s string) bool {
	_, _, ok := splitJohnHMAC(strings.TrimSpace(s))
	return ok
}

// johnHMACTypes names the HMAC types this spelling can resolve to. The
// digest length narrows it further at verification time; offering the whole
// family here costs one refused parse per wrong candidate and nothing else.
func johnHMACTypes() []string {
	return []string{
		"hmac-md5", "hmac-sha1", "hmac-sha224",
		"hmac-sha256", "hmac-sha384", "hmac-sha512",
	}
}
