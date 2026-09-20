package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Codec conformance ─────────────────────────────────────────────────────────
//
// Every crackable hash format in this project carries a provenance-labelled
// known-answer vector, and `selftest` reports 461 of 461. The codecs — the
// other half of what this tool does — carried none at all, and no test drove
// the catalogue as a whole. That is how `encode -t base91` came to corrupt its
// own output through the CLI: nothing asserted that what a codec writes is
// what it reads back.
//
// These drive EVERY entry in the catalogue rather than a hand-picked list, so
// a codec added tomorrow is covered the day it is added.

// codecCatalogueNames returns every encode/decode -t name.
func codecCatalogueNames() []string {
	var out []string
	for _, g := range codecCatalogue {
		for _, item := range g.items {
			out = append(out, item[0])
		}
	}
	return out
}

// codecsWithoutRoundTrip are the entries for which encode/decode is NOT
// expected to be an identity, with the reason. Anything not listed here must
// round-trip, so adding a lossy codec is a deliberate act that has to be
// written down.
var codecsWithoutRoundTrip = map[string]string{
	"morse":     "collapses case, and punctuation outside the alphabet has no code",
	"nato":      "a word alphabet has no code for punctuation, and case is lost",
	"a1z26":     "letters only; spacing and punctuation are not represented",
	"baconian":  "letters only, and I/J plus U/V share a code",
	"polybius":  "letters only, and I/J share a cell",
	"railfence": "needs the same -r rails, which its own test supplies",
	"caesar":    "needs the same -s shift, which its own test supplies",
	"vigenere":  "needs the same -k key, which its own test supplies",
	"xor":       "needs the same -k key, which its own test supplies",
	"rot5":      "digits only; letters pass through unchanged",
	"rot13":     "letters only",
	"rot18":     "letters and digits only",
	"atbash":    "letters only",
	"leet":      "a many-to-one substitution has no inverse",
	"reverse":   "reverses runes, so it is not byte-preserving",
}

// roundTripProbes are the payloads every codec is asked to survive. They are
// chosen to be exactly the shapes that broke in practice: a comma (which the
// input layer used to split on), surrounding whitespace (which it used to
// trim), a leading dash (which the flag parser used to eat), and bytes outside
// ASCII.
var roundTripProbes = []struct{ name, in string }{
	{"ascii", "Hashsmith"},
	{"with a comma", "alpha,beta"},
	{"surrounding spaces", "  padded  "},
	{"leading dash", "-hello"},
	{"punctuation", `a"b'c\d/e`},
	{"utf-8", "naïve café — 日本語"},
	{"single byte", "x"},
	{"long", strings.Repeat("The quick brown fox. ", 40)},
}

func TestEveryCodecRoundTrips(t *testing.T) {
	for _, name := range codecCatalogueNames() {
		if why, lossy := codecsWithoutRoundTrip[name]; lossy {
			_ = why
			continue
		}
		name := name
		t.Run(name, func(t *testing.T) {
			probes := roundTripProbes
			if name == "z85" {
				// Z85 is defined only for payloads whose length is a multiple
				// of four bytes. Feeding it anything else is testing the spec,
				// not the implementation.
				probes = []struct{ name, in string }{
					{"four bytes", "abcd"},
					{"eight bytes", "abcd,fgh"},
					{"utf-8, twelve bytes", "naïve caf\u00e9!"},
				}
			}
			for _, probe := range probes {
				enc, err := encodeText(probe.in, name, 3, "hashsmith", 2)
				if err != nil {
					// A codec that cannot represent a payload must SAY so.
					// Silently producing something that will not decode is
					// the failure this test exists to catch.
					continue
				}
				dec, err := decodeText(enc, name, 3, "hashsmith", 2)
				if err != nil {
					t.Errorf("%s: encoded %q to %.60q, which will not decode: %v",
						probe.name, probe.in, enc, err)
					continue
				}
				if dec != probe.in {
					t.Errorf("%s: %q -> %.60q -> %q (not the original)",
						probe.name, probe.in, enc, dec)
				}
			}
		})
	}
}

// Every catalogue entry must actually be usable: listing a name that encode
// rejects makes `hashsmith encodings` a list of promises rather than a menu.
func TestEveryListedCodecEncodes(t *testing.T) {
	for _, name := range codecCatalogueNames() {
		in := "Hashsmith"
		if name == "z85" {
			in = "abcd" // Z85 is defined only for multiples of four bytes
		}
		if _, err := encodeText(in, name, 3, "hashsmith", 2); err != nil {
			t.Errorf("catalogue lists %q but encode rejects it: %v", name, err)
		}
	}
}

// The lossy list must not drift: an entry naming a codec that no longer exists
// would quietly exempt nothing, and a codec removed from the catalogue while
// still listed here hides that it is gone.
func TestLossyCodecListMatchesTheCatalogue(t *testing.T) {
	known := map[string]bool{}
	for _, n := range codecCatalogueNames() {
		known[n] = true
	}
	for name := range codecsWithoutRoundTrip {
		if !known[name] {
			t.Errorf("codecsWithoutRoundTrip names %q, which is not in the catalogue", name)
		}
	}
}

// A positional argument that happens to name an existing file is read as that
// file. The behaviour is documented, but it was silent, and on a
// case-insensitive filesystem it fires when the user did not type a path at
// all: `encode -t base85 Hashsmith`, run beside a binary called "hashsmith",
// encoded twenty megabytes of executable and printed twenty-five million
// characters with no indication why.
func TestFileSubstitutionIsAnnouncedAndCanBeRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("line-one\nline-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var notice strings.Builder
	saved := fileSubstitutionNotice
	fileSubstitutionNotice = &notice
	t.Cleanup(func() { fileSubstitutionNotice = saved })

	got, err := collectInputsOpts(path, payloadInputOpts())
	if err != nil {
		t.Fatalf("collectInputsOpts: %v", err)
	}
	if len(got) != 2 || got[0] != "line-one" {
		t.Errorf("file inputs = %q; want the two lines", got)
	}
	if !strings.Contains(notice.String(), "Reading") || !strings.Contains(notice.String(), "secret") {
		t.Errorf("no notice was printed for the substitution: %q", notice.String())
	}
	if !strings.Contains(notice.String(), "--string") {
		t.Errorf("the notice does not say how to refuse the substitution: %q", notice.String())
	}

	// --string takes the argument as the text it is, and says nothing.
	notice.Reset()
	got, err = collectInputsOpts(path, withLiteral(payloadInputOpts(), true))
	if err != nil {
		t.Fatalf("literal: %v", err)
	}
	if len(got) != 1 || got[0] != path {
		t.Errorf("--string gave %q; want the argument itself", got)
	}
	if notice.String() != "" {
		t.Errorf("--string still printed a substitution notice: %q", notice.String())
	}
}

// Ascii85's decoder needs room for a whole four-byte group beyond what it
// writes, and reports NO error when it runs short — it just writes less.
// Sizing the destination at the input length silently dropped the final
// partial group: "hello" decoded back to "hell", and a single byte to nothing.
func TestAscii85KeepsThePartialFinalGroup(t *testing.T) {
	for _, codec := range []string{"base85", "adobe85"} {
		for _, in := range []string{"x", "hi", "hel", "hell", "hello", "Hashsmith"} {
			enc, err := encodeText(in, codec, 3, "", 2)
			if err != nil {
				t.Fatalf("%s encode %q: %v", codec, in, err)
			}
			dec, err := decodeText(enc, codec, 3, "", 2)
			if err != nil {
				t.Errorf("%s: %q -> %q will not decode: %v", codec, in, enc, err)
				continue
			}
			if dec != in {
				t.Errorf("%s: %q -> %q -> %q (the final group was dropped)", codec, in, enc, dec)
			}
		}
	}
}

// "<~>" is three characters in which the opening and closing Ascii85
// delimiters are the SAME three characters, so stripping two from each end
// asked for value[2:1] and took the whole process down. The length check is
// not redundant with the prefix and suffix checks. Found by fuzzing.
func TestAdobe85OverlappingDelimitersDoNotPanic(t *testing.T) {
	for _, in := range []string{"<~>", "<~~>", "<~", "~>", "<", ">", "<~~~>"} {
		// The only contract is that this returns rather than panics.
		if _, err := decodeText(in, "adobe85", 3, "", 2); err != nil {
			continue
		}
	}
	// A real record must still decode.
	got, err := decodeText("<~GQ~>", "adobe85", 3, "", 2)
	if err != nil || got != "x" {
		t.Errorf("decode(<~GQ~>) = %q, %v; want \"x\"", got, err)
	}
}

// A compressed stream can expand by a thousand to one, so the ceiling on the
// RESULT is what bounds the work — the input size says nothing.
func TestCompressionBombIsRefusedAtTheCallersCeiling(t *testing.T) {
	// gzip of 8 MiB of zeros is a few kilobytes.
	big := strings.Repeat("\x00", 8<<20)
	enc, err := encodeText(big, "gzip", 3, "", 2)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(enc) > 64<<10 {
		t.Fatalf("the seed did not compress: %d chars", len(enc))
	}

	// The default ceiling accepts it: someone who typed `decode -t gzip`
	// asked for whatever is in there.
	if _, err := decodeText(enc, "gzip", 3, "", 2); err != nil {
		t.Errorf("the default ceiling refused an 8 MiB result: %v", err)
	}

	// A caller with a smaller ceiling refuses it BEFORE building it. magic
	// searches recursively and discards anything over its own cap, so
	// inflating 64 MiB first was a large allocation for a result it had
	// already decided to throw away.
	if _, err := decodeTextLimited(enc, "gzip", 3, "", 2, 1<<20); err == nil {
		t.Error("a 1 MiB ceiling accepted an 8 MiB result")
	} else if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal does not mention a limit: %v", err)
	}

	// And magic itself must survive it.
	_ = magicDecode(enc, 2)
}
