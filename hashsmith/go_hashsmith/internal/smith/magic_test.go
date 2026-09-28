package smith

import (
	"strings"
	"testing"
)

// Recursive automatic decoding. Neither john nor hashcat has anything like
// this, and it is the one place where having identification and decoding in
// the same binary pays off directly: a chain can end at "that is a bcrypt
// hash" rather than at bytes.

// encodeForTest is a helper that fails the test rather than returning an error.
func encodeForTest(t *testing.T, in, codec string) string {
	t.Helper()
	out, err := encodeText(in, codec, 3, "", 2)
	if err != nil {
		t.Fatalf("encode %s: %v", codec, err)
	}
	return out
}

func TestMagicFindsMultiLayerChains(t *testing.T) {
	for _, c := range []struct {
		name   string
		layers []string // applied in order; magic must undo them
		want   string
	}{
		{"one layer", []string{"base64"}, "the quick brown fox"},
		{"two layers", []string{"hex", "base64"}, "the quick brown fox"},
		{"compression", []string{"gzip", "base64"}, "the quick brown fox and the lazy dog"},
		{"three layers", []string{"hex", "base64", "url"}, "the quick brown fox"},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			enc := c.want
			for _, codec := range c.layers {
				enc = encodeForTest(t, enc, codec)
			}
			results := magicDecode(enc, 4)
			if len(results) == 0 {
				t.Fatalf("magic found nothing in %.60q", enc)
			}
			// The best result must be the original text, not an intermediate
			// layer that happens to be printable.
			if results[0].value != c.want {
				t.Errorf("best result is %.60q via %v; want %q",
					results[0].value, results[0].chain, c.want)
			}
			if len(results[0].chain) != len(c.layers) {
				t.Errorf("chain %v has %d steps; the input had %d layers",
					results[0].chain, len(results[0].chain), len(c.layers))
			}
		})
	}
}

// The payoff for one binary: a decoded layer that is a hash gets named.
func TestMagicIdentifiesWhatItUncovers(t *testing.T) {
	const bcryptHash = "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
	enc := encodeForTest(t, bcryptHash, "base64")

	results := magicDecode(enc, 3)
	if len(results) == 0 {
		t.Fatal("magic found nothing")
	}
	best := results[0]
	if best.value != bcryptHash {
		t.Fatalf("best result is %.60q; want the bcrypt hash", best.value)
	}
	if !strings.Contains(best.identified, "bcrypt") {
		t.Errorf("the uncovered hash was not identified (got %q)", best.identified)
	}
}

// Plain text is not a puzzle. Reporting a chain for it would be noise.
func TestMagicDeclinesPlainText(t *testing.T) {
	results := magicDecode("just some ordinary words here", 3)
	for _, r := range results {
		if r.score >= 1.0 {
			t.Errorf("plain text produced a confident decode: %v -> %.40q", r.chain, r.value)
		}
	}
}

// Keyed codecs are excluded on purpose. Trying one arbitrary key and
// reporting the noise it produced as a finding is worse than declining.
func TestMagicDoesNotGuessKeys(t *testing.T) {
	offered := map[string]bool{}
	for _, c := range magicCodecs() {
		offered[c] = true
	}
	for _, keyed := range []string{"caesar", "vigenere", "xor", "railfence"} {
		if offered[keyed] {
			t.Errorf("magic would try %q, which needs a key it does not have", keyed)
		}
	}
	// And it must still offer the ones that need nothing.
	for _, plain := range []string{"base64", "hex", "gzip", "url"} {
		if !offered[plain] {
			t.Errorf("magic does not try %q", plain)
		}
	}
}

// A value that is still obviously an encoding must not outrank the text
// underneath it. Character statistics alone rate hex digits a perfect 1.0,
// which used to put an intermediate layer level with the answer.
func TestMagicScoreRanksTextAboveAnotherEncodingLayer(t *testing.T) {
	text := magicScore("the quick brown fox and the lazy dog")
	hexLayer := magicScore("74686520717569636b2062726f776e20666f78")
	if hexLayer >= text {
		t.Errorf("a hex layer scores %.2f, not below plain text at %.2f", hexLayer, text)
	}

	// And a decode that turns ASCII into a wall of non-Latin script is almost
	// always the wrong decode.
	cjk := magicScoreFrom("㑢㥢ぢ攲昶㤰㥡摢", "62346239623032653666303961396264")
	if cjk >= 0.5 {
		t.Errorf("reading ASCII hex as UTF-16 scores %.2f; it should rank far down", cjk)
	}
}
