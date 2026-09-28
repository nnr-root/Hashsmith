package smith

import (
	"strings"
	"testing"
)

// A multi-step recipe used to mean N separate invocations piped together, and
// every hop back through argv re-exposed the payload to whatever the argument
// layer does to it. `-t a+b` does it in one.
func TestCodecChainRoundTrips(t *testing.T) {
	for _, c := range []struct{ name, chain, inverse, in string }{
		{"two steps", "hex+base64", "base64+hex", "the quick brown fox"},
		{"three steps", "hex+base64+url", "url+base64+hex", "a b&c"},
		{"compression", "gzip+hex", "hex+gzip", "the quick brown fox and the lazy dog"},
		{"payload with a comma", "hex+base64", "base64+hex", "alpha,beta"},
		{"payload with spaces", "hex+base64", "base64+hex", "  padded  "},
		{"single step still works", "base64", "base64", "Hashsmith"},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			enc, err := encodeChain(c.in, c.chain, 3, "", 2)
			if err != nil {
				t.Fatalf("encode -t %s: %v", c.chain, err)
			}
			dec, err := decodeChain(enc, c.inverse, 3, "", 2)
			if err != nil {
				t.Fatalf("decode -t %s: %v", c.inverse, err)
			}
			if dec != c.in {
				t.Errorf("%q -> %.50q -> %q", c.in, enc, dec)
			}
		})
	}
}

// The steps read left to right in both directions, so a chain and its inverse
// are mirror images — which is what lets a magic result be replayed directly.
func TestCodecChainMirrorsAMagicResult(t *testing.T) {
	const want = "the quick brown fox"
	enc, err := encodeChain(want, "hex+base64", 3, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	results := magicDecode(enc, 3)
	if len(results) == 0 {
		t.Fatal("magic found nothing")
	}
	best := results[0]
	if best.value != want {
		t.Fatalf("magic's best is %.40q; want %q", best.value, want)
	}
	// Replaying magic's chain verbatim must reproduce its own answer.
	replay := strings.Join(best.chain, "+")
	got, err := decodeChain(enc, replay, 3, "", 2)
	if err != nil {
		t.Fatalf("replaying magic's chain %q: %v", replay, err)
	}
	if got != want {
		t.Errorf("replaying %q gave %q; magic reported %q", replay, got, best.value)
	}
}

// An error must name the step that failed: "unsupported encode type" is not
// useful when the user gave four of them.
func TestCodecChainErrorNamesTheStep(t *testing.T) {
	_, err := encodeChain("x", "hex+nosuch+base64", 3, "", 2)
	if err == nil {
		t.Fatal("an unknown step was accepted")
	}
	msg := err.Error()
	for _, want := range []string{"step 2", "nosuch"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
	// A one-step chain keeps the plain error it always had.
	_, err = encodeChain("x", "nosuch", 3, "", 2)
	if err == nil || strings.Contains(err.Error(), "step") {
		t.Errorf("a single codec should report its own error, got %v", err)
	}
	if _, err := parseCodecChain("hex++base64"); err == nil {
		t.Error("an empty step was accepted")
	}
}
