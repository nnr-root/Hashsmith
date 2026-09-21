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

// johnWrappers maps a record prefix John writes to the canonical type whose
// verifier should see the remainder. Order matters only in that a longer
// prefix must precede a shorter one that is its prefix.
var johnWrappers = []struct{ prefix, typ string }{
	{"$md2$", "md2"},
	{"$oracle12c$", "oracle12c"},
	{"$django$*1*", "django"},
	{"$LM$", "lm"},
}

// stripJohnWrapper removes a John-only envelope when the record carries one
// and it belongs to the type being verified. Anything else is returned
// unchanged, so a record that merely resembles a wrapper is never mangled.
func stripJohnWrapper(target, typ string) string {
	for _, w := range johnWrappers {
		if typ == w.typ && strings.HasPrefix(target, w.prefix) {
			return strings.TrimPrefix(target, w.prefix)
		}
	}
	return target
}
