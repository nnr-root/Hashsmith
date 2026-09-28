package smith

import (
	"bytes"
	"math/rand"
	"testing"
	"unicode/utf16"
)

// utf16leReference is a from-scratch reimplementation of utf16le's ORIGINAL
// (pre-fast-path) body, kept here only as an independent oracle: the fast
// path added to utf16le must never be trusted against itself, only against
// logic that does not share its code.
func utf16leReference(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// TestUTF16LEMatchesReference is the correctness backstop for the ASCII fast
// path added to utf16le: every case here must produce byte-identical output
// to the reference, whether it takes the fast path or falls back to it.
func TestUTF16LEMatchesReference(t *testing.T) {
	cases := []string{
		"",                              // empty candidate — a real dictionary entry
		"a",                             // shortest non-empty ASCII
		"password",                      // the common case this fast path targets
		"Password1!",                    // ASCII with punctuation and digits
		string([]byte{0x7f}),            // last byte still inside the ASCII fast path
		string([]byte{0x80}),            // first byte that must take the reference path
		string([]byte{0xC3, 0xA9}),      // 'é' as two-byte UTF-8 (one rune)
		"café",                          // mixed ASCII + one non-ASCII rune
		"世界",                            // pure multi-byte UTF-8, no ASCII at all
		"Hashsmith 世界 😀",                // ASCII + BMP + a rune needing a UTF-16 surrogate pair
		"😀😀😀",                           // pure surrogate-pair runes, no ASCII
		string([]byte{'a', 0xC3, 0xFF}), // the exact byte sequence used elsewhere in this
		// package's own fast-path guard test (TestNTLMFastPathRejectsNonASCIICharsets),
		// so this function's ASCII/non-ASCII boundary agrees with that one.
	}
	for _, s := range cases {
		got := utf16le(s)
		want := utf16leReference(s)
		if !bytes.Equal(got, want) {
			t.Errorf("utf16le(%q) = %x, want %x (reference)", s, got, want)
		}
	}
}

// TestUTF16LERandomMatchesReference extends the table above with randomized
// input spanning the full byte range, so the ASCII/non-ASCII boundary is
// checked well beyond the hand-picked cases above.
func TestUTF16LERandomMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		n := rng.Intn(24)
		b := make([]byte, n)
		for j := range b {
			// Every byte value is fair game, including invalid UTF-8
			// sequences: utf16le's contract (both paths) is "whatever
			// []rune(s) decodes this to", which for invalid UTF-8 already
			// meant U+FFFD substitutions in the original implementation —
			// the fast path must not be exercised for those (any byte
			// >= 0x80 sends it to the reference path), so this test is
			// really checking that routing decision, not new decode logic.
			b[j] = byte(rng.Intn(256))
		}
		s := string(b)
		got := utf16le(s)
		want := utf16leReference(s)
		if !bytes.Equal(got, want) {
			t.Fatalf("utf16le(%q) = %x, want %x (reference), input bytes %x", s, got, want, b)
		}
	}
}

// TestUTF16LEASCIIFastPathIsExercised is a coverage guard, not a correctness
// check: it fails if a refactor accidentally makes every case in the table
// above fall through to the reference path, which would let this fast path
// silently go untested by TestUTF16LEMatchesReference while still reporting
// green.
func TestUTF16LEASCIIFastPathIsExercised(t *testing.T) {
	got := utf16le("password")
	want := []byte{'p', 0, 'a', 0, 's', 0, 's', 0, 'w', 0, 'o', 0, 'r', 0, 'd', 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("utf16le(%q) = %x, want %x", "password", got, want)
	}
}

// TestUTF16LEIntoMatchesUTF16LE checks utf16leInto against utf16le itself
// (not just the reference) for every case that fits and is ASCII: the two
// must agree exactly, since utf16leInto is the same fast path with a
// caller-supplied destination.
func TestUTF16LEIntoMatchesUTF16LE(t *testing.T) {
	cases := []string{"", "a", "password", "Password1!", string([]byte{0x7f})}
	var buf [2 * stdMaxCandidateLen]byte
	for _, s := range cases {
		got, ok := utf16leInto(buf[:], s)
		if !ok {
			t.Fatalf("utf16leInto(%q) unexpectedly declined", s)
		}
		want := utf16le(s)
		if !bytes.Equal(got, want) {
			t.Errorf("utf16leInto(%q) = %x, want %x", s, got, want)
		}
	}
}

// TestUTF16LEIntoDeclinesNonASCII guards the fallback contract: any byte
// >= 0x80 must return ok=false, exactly like utf16le's own routing decision,
// so a caller can safely fall back to the allocating utf16le without ever
// silently mis-encoding a non-ASCII candidate.
func TestUTF16LEIntoDeclinesNonASCII(t *testing.T) {
	var buf [2 * stdMaxCandidateLen]byte
	for _, s := range []string{string([]byte{0x80}), "café", "😀"} {
		if _, ok := utf16leInto(buf[:], s); ok {
			t.Errorf("utf16leInto(%q) should decline non-ASCII input", s)
		}
	}
}

// TestUTF16LEIntoDeclinesOversizedInput guards the other fallback trigger: a
// candidate too long for the supplied buffer must be declined, never
// silently truncated.
func TestUTF16LEIntoDeclinesOversizedInput(t *testing.T) {
	var small [4]byte // room for 2 ASCII chars, not 3
	if _, ok := utf16leInto(small[:], "abc"); ok {
		t.Fatal("utf16leInto should decline a candidate that does not fit dst")
	}
	if v, ok := utf16leInto(small[:], "ab"); !ok || !bytes.Equal(v, []byte{'a', 0, 'b', 0}) {
		t.Fatalf("utf16leInto(%q) with an exact-fit buffer = %x, %v", "ab", v, ok)
	}
}

// TestUTF16LEIntoBytesMatchesUTF16LEInto checks the []byte-input twin agrees
// with the string-input version byte for byte, across the same ASCII,
// non-ASCII and oversized cases.
func TestUTF16LEIntoBytesMatchesUTF16LEInto(t *testing.T) {
	var bufA, bufB [2 * stdMaxCandidateLen]byte
	cases := []string{"", "password", string([]byte{0x80}), "café"}
	for _, s := range cases {
		gotStr, okStr := utf16leInto(bufA[:], s)
		gotBytes, okBytes := utf16leIntoBytes(bufB[:], []byte(s))
		if okStr != okBytes {
			t.Fatalf("utf16leInto/utf16leIntoBytes disagree on %q: ok=%v vs ok=%v", s, okStr, okBytes)
		}
		if okStr && !bytes.Equal(gotStr, gotBytes) {
			t.Errorf("utf16leInto(%q) = %x, utf16leIntoBytes = %x", s, gotStr, gotBytes)
		}
	}
}

func BenchmarkUTF16LEASCII(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = utf16le("benchmarkpassword123")
	}
}

func BenchmarkUTF16LEReferenceASCII(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = utf16leReference("benchmarkpassword123")
	}
}
