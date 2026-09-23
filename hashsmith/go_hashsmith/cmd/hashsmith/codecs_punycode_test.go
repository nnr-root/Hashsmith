package main

import (
	"strings"
	"testing"
)

// Every sample string RFC 3492 publishes in section 7.1, transcribed from the
// RFC itself. The plaintext is written as \u escapes so that the vectors
// cannot be changed by an editor normalising the file — several of them are
// scripts whose rendering depends on the reader.
//
// These are the whole reason to trust this implementation: Punycode's
// arithmetic is easy to write plausibly and wrong, and nothing about a wrong
// answer looks wrong.
var punycodeRFCVectors = []struct{ label, plain, puny string }{
	{"A", "\u0644\u064a\u0647\u0645\u0627\u0628\u062a\u0643\u0644\u0645\u0648\u0634\u0639\u0631\u0628\u064a\u061f", "egbpdaj6bu4bxfgehfvwxn"},
	{"B", "\u4ed6\u4eec\u4e3a\u4ec0\u4e48\u4e0d\u8bf4\u4e2d\u6587", "ihqwcrb4cv8a8dqg056pqjye"},
	{"C", "\u4ed6\u5011\u7232\u4ec0\u9ebd\u4e0d\u8aaa\u4e2d\u6587", "ihqwctvzc91f659drss3x8bo0yb"},
	{"D", "Pro\u010dprost\u011bnemluv\u00ed\u010desky", "Proprostnemluvesky-uyb24dma41a"},
	{"E", "\u05dc\u05de\u05d4\u05d4\u05dd\u05e4\u05e9\u05d5\u05d8\u05dc\u05d0\u05de\u05d3\u05d1\u05e8\u05d9\u05dd\u05e2\u05d1\u05e8\u05d9\u05ea", "4dbcagdahymbxekheh6e0a7fei0b"},
	{"F", "\u092f\u0939\u0932\u094b\u0917\u0939\u093f\u0928\u094d\u0926\u0940\u0915\u094d\u092f\u094b\u0902\u0928\u0939\u0940\u0902\u092c\u094b\u0932\u0938\u0915\u0924\u0947\u0939\u0948\u0902", "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd"},
	{"G", "\u306a\u305c\u307f\u3093\u306a\u65e5\u672c\u8a9e\u3092\u8a71\u3057\u3066\u304f\u308c\u306a\u3044\u306e\u304b", "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa"},
	{"H", "\uc138\uacc4\uc758\ubaa8\ub4e0\uc0ac\ub78c\ub4e4\uc774\ud55c\uad6d\uc5b4\ub97c\uc774\ud574\ud55c\ub2e4\uba74\uc5bc\ub9c8\ub098\uc88b\uc744\uae4c", "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c"},
	{"I", "\u043f\u043e\u0447\u0435\u043c\u0443\u0436\u0435\u043e\u043d\u0438\u043d\u0435\u0433\u043e\u0432\u043e\u0440\u044f\u0442\u043f\u043e\u0440\u0443\u0441\u0441\u043a\u0438", "b1abfaaepdrnnbgefbaDotcwatmq2g4l"},
	{"J", "Porqu\u00e9nopuedensimplementehablarenEspa\u00f1ol", "PorqunopuedensimplementehablarenEspaol-fmd56a"},
	{"K", "T\u1ea1isaoh\u1ecdkh\u00f4ngth\u1ec3ch\u1ec9n\u00f3iti\u1ebfngVi\u1ec7t", "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g"},
	{"L", "3\u5e74B\u7d44\u91d1\u516b\u5148\u751f", "3B-ww4c5e180e575a65lsy2b"},
	{"M", "\u5b89\u5ba4\u5948\u7f8e\u6075-with-SUPER-MONKEYS", "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n"},
	{"N", "Hello-Another-Way-\u305d\u308c\u305e\u308c\u306e\u5834\u6240", "Hello-Another-Way--fc4qua05auwb3674vfr0b"},
	{"O", "\u3072\u3068\u3064\u5c4b\u6839\u306e\u4e0b2", "2-u9tlzr9756bt3uc0v"},
	{"P", "Maji\u3067Koi\u3059\u308b5\u79d2\u524d", "MajiKoi5-783gue6qz075azm5e"},
	{"Q", "\u30d1\u30d5\u30a3\u30fcde\u30eb\u30f3\u30d0", "de-jg4avhby1noc0d"},
	{"R", "\u305d\u306e\u30b9\u30d4\u30fc\u30c9\u3067", "d9juau41awczczp"},
	{"S", "-> $1.00 <-", "-> $1.00 <--"},
}

func TestPunycodeRFCVectors(t *testing.T) {
	for _, tc := range punycodeRFCVectors {
		got, err := decodePunycode(tc.puny)
		if err != nil {
			t.Errorf("%s: decode: %v", tc.label, err)
			continue
		}
		if got != tc.plain {
			t.Errorf("%s: decode gave %q, want %q", tc.label, got, tc.plain)
		}

		enc, err := encodePunycode(tc.plain)
		if err != nil {
			t.Errorf("%s: encode: %v", tc.label, err)
			continue
		}
		// RFC 3492's MIXED-CASE ANNOTATION lets an encoder record the case
		// of the original in the case of the digits. It is explicitly
		// optional and this implementation does not produce it, so one
		// vector (I) differs from the RFC's spelling in case alone. A
		// decoder must accept either, which the decode check above covers.
		if !strings.EqualFold(enc, tc.puny) {
			t.Errorf("%s: encode gave %q, want %q", tc.label, enc, tc.puny)
		}
	}
}

// Every vector must survive a round trip through this implementation alone,
// which is a weaker check than the RFC comparison but catches an encoder and
// decoder that are wrong in the same direction.
func TestPunycodeRoundTrip(t *testing.T) {
	for _, tc := range punycodeRFCVectors {
		enc, err := encodePunycode(tc.plain)
		if err != nil {
			t.Fatalf("%s: encode: %v", tc.label, err)
		}
		back, err := decodePunycode(enc)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.label, err)
		}
		if back != tc.plain {
			t.Errorf("%s: round trip gave %q, want %q", tc.label, back, tc.plain)
		}
	}
}

// IDNA is the domain-name wrapper: it splits on dots, encodes only the labels
// that need it, and adds the ACE prefix. The homograph pair is the reason the
// codec is here at all — two names that render identically and are not the
// same domain.
func TestIDNADomains(t *testing.T) {
	for _, tc := range []struct{ unicode, ascii string }{
		{"b\u00fccher.de", "xn--bcher-kva.de"},
		// Cyrillic \u0430 in place of the Latin a: a different domain that
		// renders the same way.
		{"\u0430pple.com", "xn--pple-43d.com"},
		{"\u4f8b\u3048.\u30c6\u30b9\u30c8", "xn--r8jz45g.xn--zckzah"},
		// An all-ASCII name is left exactly as it is, case included: it
		// needs no encoding and changing it would change a name that was
		// already right.
		{"Example.COM", "Example.COM"},
		{"", ""},
	} {
		got, err := encodeIDNA(tc.unicode)
		if err != nil {
			t.Errorf("encode %q: %v", tc.unicode, err)
			continue
		}
		if got != tc.ascii {
			t.Errorf("encode %q gave %q, want %q", tc.unicode, got, tc.ascii)
		}
		back, err := decodeIDNA(tc.ascii)
		if err != nil {
			t.Errorf("decode %q: %v", tc.ascii, err)
			continue
		}
		if back != tc.unicode {
			t.Errorf("decode %q gave %q, want %q", tc.ascii, back, tc.unicode)
		}
	}
}

// A label without the prefix is not Punycode for anything and must be passed
// through, not decoded. "test" is a perfectly good label.
func TestIDNALeavesPlainLabelsAlone(t *testing.T) {
	for _, name := range []string{"www.example.com", "test", "a.b.c", "XN.example"} {
		got, err := decodeIDNA(name)
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		if got != name {
			t.Errorf("%q was rewritten to %q", name, got)
		}
	}
}

// Malformed input is refused rather than decoded into whatever falls out. Each
// of these is a way the arithmetic can be pushed somewhere it should not go.
func TestPunycodeRefusesMalformedInput(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"a digit that is not base 36", "abc$def"},
		{"a digit sequence that never terminates", "99999999999"},
		{"arithmetic that overflows", strings.Repeat("9", 64)},
		{"a non-ASCII byte in the literal part", "caf\u00e9-abc"},
	} {
		if got, err := decodePunycode(tc.input); err == nil {
			t.Errorf("%s: %q decoded to %q instead of failing", tc.name, tc.input, got)
		}
	}
}
