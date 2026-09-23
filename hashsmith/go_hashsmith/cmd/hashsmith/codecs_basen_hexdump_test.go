package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ── base-N ───────────────────────────────────────────────────────────────────

// Given a standardised alphabet, basen must produce exactly what the codec
// named after that alphabet produces. That is the check that the general code
// is the same code, rather than something that merely looks similar.
func TestBaseNMatchesTheNamedCodecs(t *testing.T) {
	payloads := []string{"", "a", "Hello, world!", "\x00\x00leading zeros",
		strings.Repeat("long", 40)}
	for _, tc := range []struct {
		name, alphabet string
		encode         func(string) (string, error)
	}{
		{"base58", base58Alphabet, func(s string) (string, error) {
			return encodeBase58WithAlphabet([]byte(s), base58Alphabet), nil
		}},
		{"base62", base62Alphabet, func(s string) (string, error) {
			return encodeBigRadix([]byte(s), base62Alphabet, base62Alphabet[0]), nil
		}},
		{"base36", base36Alphabet, func(s string) (string, error) {
			return encodeBase36([]byte(s)), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, payload := range payloads {
				want, err := tc.encode(payload)
				if err != nil {
					t.Fatalf("%q: %v", payload, err)
				}
				got, err := encodeBaseN([]byte(payload), tc.alphabet)
				if err != nil {
					t.Fatalf("%q: %v", payload, err)
				}
				if got != want {
					t.Errorf("%q: basen gave %q, %s gives %q", payload, got, tc.name, want)
				}
				back, err := decodeBaseN(got, tc.alphabet)
				if err != nil || string(back) != payload {
					t.Errorf("%q: round trip gave %q, %v", payload, back, err)
				}
			}
		})
	}
}

// The point of the codec is an alphabet nobody standardised, including one
// whose characters are outside ASCII.
func TestBaseNWithUnusualAlphabets(t *testing.T) {
	for _, alphabet := range []string{
		"01",                         // binary, as digits
		"0123456789abcdef",           // hex, the long way round
		"ZYXWVUTSRQPONMLKJIHGFEDCBA", // reversed, which a product might do
		"⚀⚁⚂⚃⚄⚅",                     // dice faces: base 6, no ASCII at all
	} {
		for _, payload := range []string{"", "x", "\x00\x01\x02", "round trip"} {
			got, err := encodeBaseN([]byte(payload), alphabet)
			if err != nil {
				t.Fatalf("%q in %q: %v", payload, alphabet, err)
			}
			back, err := decodeBaseN(got, alphabet)
			if err != nil {
				t.Fatalf("%q in %q: decode: %v", payload, alphabet, err)
			}
			if string(back) != payload {
				t.Errorf("%q in %q round-tripped to %q", payload, alphabet, back)
			}
		}
	}
}

// Every way of getting the alphabet wrong produces silent nonsense rather than
// an error, so each is refused by name.
func TestBaseNRefusesBadAlphabets(t *testing.T) {
	for _, tc := range []struct{ alphabet, want string }{
		{"", "needs an alphabet"},
		{"x", "not a base to count in"},
		{"aab", "repeats"},
		{strings.Repeat("ÿ", 1), "not a base to count in"},
	} {
		if _, err := encodeBaseN([]byte("x"), tc.alphabet); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("alphabet %q: got %v, want an error naming %q", tc.alphabet, err, tc.want)
		}
	}
	// A character that is not in the alphabet cannot be a digit of it.
	if _, err := decodeBaseN("01x", "01"); err == nil {
		t.Error("a character outside the alphabet should be refused")
	}
}

// ── Hex dumps ────────────────────────────────────────────────────────────────

// TestHexDumpMatchesTheSystemTool compares against the real hexdump, which is
// the only way to know the format is the format rather than something that
// resembles it.
func TestHexDumpMatchesTheSystemTool(t *testing.T) {
	bin, err := exec.LookPath("hexdump")
	if err != nil {
		t.Skip("hexdump is not installed here, so its output cannot be compared")
	}
	for _, payload := range []string{
		"Hello, world!\n",
		"",
		strings.Repeat("A", 16),
		strings.Repeat("A", 17),
		string([]byte{0, 1, 2, 0x7f, 0x80, 0xff}),
		"a longer body that runs past a single line of sixteen bytes and then some",
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "payload")
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "-C", path).Output()
		if err != nil {
			t.Skipf("this hexdump would not run: %v", err)
		}
		got := encodeHexDump([]byte(payload))
		if got != string(out) {
			t.Errorf("payload %q\n got:\n%s\nwant:\n%s", payload, got, out)
		}
		// And the dump the system tool wrote must read back.
		back, err := decodeHexDump(string(out))
		if err != nil {
			t.Errorf("payload %q: decoding hexdump's own output: %v", payload, err)
			continue
		}
		if !bytes.Equal(back, []byte(payload)) {
			t.Errorf("payload %q read back as %q", payload, back)
		}
	}
}

// The offset column comes in two spellings and both have to be discarded: a
// bare offset as hexdump writes it, and one followed by a colon as xxd does.
func TestHexDumpAcceptsBothOffsetStyles(t *testing.T) {
	want := []byte("Hello, world!")
	for _, tc := range []struct{ name, dump string }{
		{"hexdump -C", "00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21  |Hello, world!|\n0000000d\n"},
		{"offset with a colon", "00000000: 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21  |Hello, world!|\n"},
		{"no offset at all", "48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21\n"},
	} {
		got, err := decodeHexDump(tc.dump)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: gave %q", tc.name, got)
		}
	}
}

// xxd writes its printable column with no pipes, and the column's text may be
// indistinguishable from more hex — "beef" is a word and four bytes. The only
// signal is the SPACING: the column is separated by a run of two or more
// spaces where the hex bytes are separated by one.
func TestHexDumpReadsXxdsUndelimitedColumn(t *testing.T) {
	for _, tc := range []struct {
		name, dump string
		want       []byte
	}{
		// The worst case: every character of the printable column is
		// also a hex digit.
		{"an all-hex printable column", "00000000: 6265 6566                                beef\n",
			[]byte("beef")},
		{"a full line", "00000000: 4865 6c6c 6f2c 2077 6f72 6c64 2131 3233  Hello, world!123\n",
			[]byte("Hello, world!123")},
	} {
		got, err := decodeHexDump(tc.dump)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: gave %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Text that is not a dump at all is refused, and the message names the two
// forms that do work.
func TestHexDumpNamesTheFix(t *testing.T) {
	_, err := decodeHexDump("this is just prose, not a dump\n")
	if err == nil {
		t.Fatal("prose should not decode")
	}
	if !strings.Contains(err.Error(), "hexdump -C") || !strings.Contains(err.Error(), "xxd -p") {
		t.Errorf("the error should name both fixes, got %v", err)
	}
}

// An empty input is an empty dump in both directions, which is what the system
// tool does: there is no closing offset line because there is nothing to close.
func TestHexDumpEmpty(t *testing.T) {
	if got := encodeHexDump(nil); got != "" {
		t.Errorf("encoding nothing gave %q", got)
	}
	got, err := decodeHexDump("")
	if err != nil || len(got) != 0 {
		t.Errorf("decoding nothing gave %q, %v", got, err)
	}
}
