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
var johnWrappers = []struct {
	prefix string
	types  []string
}{
	// Raw digests. The envelope is the only thing that makes these
	// identifiable — a bare 128-hex digest is SHA-512, SHA3-512, BLAKE2b,
	// Whirlpool, Streebog-512 or Keccak-512 with nothing to choose between
	// them, and John's records say which.
	{"$sha224$", []string{"sha224"}},
	{"$sha256$", []string{"sha256"}},
	{"$sha384$", []string{"sha384"}},
	{"$sha512$", []string{"sha512"}},
	{"$md4$", []string{"md4"}},
	{"$md2$", []string{"md2"}},
	{"$mdc2$", []string{"mdc2"}},
	{"$gost$", []string{"gost"}},
	// The same hash under the other parameter set, which John names.
	{"$gost-cp$", []string{"gost-cryptopro"}},
	{"$keccak256$", []string{"keccak256"}},
	{"$keccak$", []string{"keccak512"}},
	{"$nt$", []string{"ntlm"}},
	{"$radmin2$", []string{"radmin2"}},
	// John writes "$whirlpool$" for all three revisions of Whirlpool and
	// nothing in the record says which, so all three are offered.
	{"$whirlpool$", []string{"whirlpool", "whirlpool0", "whirlpool1"}},
	// As with $ripemd$, one envelope covers more than one digest size and the
	// payload's length settles which.
	{"$skein$", []string{"skein224", "skein256", "skein384", "skein512"}},
	// $haval$ names neither the size nor the pass count; the payload's length
	// settles the size, and all three pass counts for it are offered.
	{"$haval$", []string{
		"haval128-3", "haval128-4", "haval128-5",
		"haval160-3", "haval160-4", "haval160-5",
		"haval192-3", "haval192-4", "haval192-5",
		"haval224-3", "haval224-4", "haval224-5",
		"haval256-3", "haval256-4", "haval256-5",
	}},
	// One envelope, two digest sizes: John writes "$ripemd$" for both the
	// 128- and 160-bit variants and lets the length say which. Both are
	// offered; the payload length settles it at verification.
	{"$ripemd$", []string{"ripemd128", "ripemd160"}},
	{"$tiger$", []string{"tiger"}},
	{"$panama$", []string{"panama"}},
	// Dahua's eight-character token, which hashcat reads bare and John wraps.
	{"$dahua$", []string{"dahua-auth-md5"}},
	// Cisco's PIX and ASA hashes are dynamic_19 and dynamic_20 in John's
	// numbering, but the dynamic engine cannot read them: the digest is in
	// PIX's own base64, not the hex every dynamic expression produces. So the
	// number is an envelope here and nothing more, and the reader behind it is
	// the one hashcat's -m 2400/2410 records already use.
	{"$dynamic_19$", []string{"cisco-pix"}},
	{"$dynamic_20$", []string{"cisco-asa"}},
	// One envelope, two widths again: John writes "$snefru$" for both Snefru
	// sizes and lets the payload length say which.
	{"$snefru$", []string{"snefru128", "snefru256"}},
	// Structured records whose payload this tool reads under another name.
	{"$cisco4$", []string{"cisco4"}},
	// "Lion" is 10.7, the one release that used a salted SHA-512.
	{"$LION$", []string{"xsha512"}},
	{"$oracle12c$", []string{"oracle12c"}},
	{"$django$*1*", []string{"django"}},
	{"$lm$", []string{"lm"}},
}

// johnWrapperFor reports the types and payload of a John-enveloped record.
func johnWrapperFor(target string) (types []string, payload string, ok bool) {
	for _, w := range johnWrappers {
		if len(target) >= len(w.prefix) && strings.EqualFold(target[:len(w.prefix)], w.prefix) {
			return w.types, target[len(w.prefix):], true
		}
	}
	return nil, "", false
}

// stripJohnWrapper removes a John-only envelope when the record carries one
// and it belongs to the type being verified. Anything else is returned
// unchanged, so a record that merely resembles a wrapper is never mangled.
func stripJohnWrapper(target, typ string) string {
	if types, payload, ok := johnWrapperFor(target); ok {
		for _, t := range types {
			if t == typ {
				return payload
			}
		}
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
		for _, t := range w.types {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
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
