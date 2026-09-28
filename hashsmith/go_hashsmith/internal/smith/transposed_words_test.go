package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// fillFromWords feeds the same vector cores fillFromSegment does, so the only
// thing worth asserting is that what it hashes is what hashText hashes. Every
// expected digest below comes from hashText — the path `hash -t md5` uses and
// the path the scalar verifier uses — never from the vector core itself, so a
// core and a filler cannot agree with each other and be wrong together.
func TestFillFromWordsMatchesHashText(t *testing.T) {
	for _, tc := range []struct{ typ, salt, saltMode string }{
		{"md5", "", ""},
		{"md4", "", ""},
		{"ntlm", "", ""},
		{"md5", "deadbeef", "prefix"},
		{"md5", "deadbeef", "suffix"},
	} {
		tc := tc
		t.Run(tc.typ+"/"+tc.salt+"/"+tc.saltMode, func(t *testing.T) {
			algo, ok := fastAlgoPlanFor(tc.typ, tc.salt, tc.saltMode)
			if !ok {
				t.Skipf("no vector plan for %s on this backend", tc.typ)
			}
			group := algo.shape.group()
			tb := newTransposedBatch(algo.shape)
			out := make([][16]byte, group)

			// One bucket of identical-length words, which is the only shape
			// the transposed layout accepts.
			const width = 6
			words := make([]string, 0, group)
			for i := 0; i < group; i++ {
				w := string([]byte{
					byte('a' + i%26), byte('a' + (i/26)%26), 'x', 'y',
					byte('0' + i%10), byte('0' + (i/10)%10),
				})
				if len(w) != width {
					t.Fatalf("test word %q is not %d bytes", w, width)
				}
				words = append(words, w)
			}

			if err := tb.resetSalted(width, algo.enc, algo.salt); err != nil {
				t.Fatalf("resetSalted: %v", err)
			}
			n := tb.fillFromWords(words)
			if n != len(words) {
				t.Fatalf("filled %d lanes, want %d", n, len(words))
			}
			algo.group(tb, out)

			for i, w := range words {
				want, err := hashText(w, tc.typ, tc.salt, tc.saltMode)
				if err != nil {
					t.Fatalf("hashText(%q): %v", w, err)
				}
				got := hex.EncodeToString(out[i][:])
				if !strings.EqualFold(got, want) {
					t.Fatalf("lane %d, word %q: vector core gave %s, hashText gives %s",
						i, w, got, want)
				}
				// And the batch must be able to hand the word back, since
				// that is how a hit is reported.
				if back := string(tb.candidateAt(i)); back != w {
					t.Errorf("candidateAt(%d) = %q, want %q", i, back, w)
				}
			}
		})
	}
}

// TestFillFromWordsCleansLeftoverLanes is the bug this shape invites: a short
// fill after a long one leaves a previous candidate's bytes in the tail lanes,
// and a caller that scanned the whole group would report a password that was
// never in this batch.
func TestFillFromWordsCleansLeftoverLanes(t *testing.T) {
	algo, ok := fastAlgoPlanFor("md5", "", "")
	if !ok {
		t.Skip("no md5 vector plan on this backend")
	}
	group := algo.shape.group()
	if group < 3 {
		t.Skip("group too small to have a tail")
	}
	tb := newTransposedBatch(algo.shape)
	out := make([][16]byte, group)

	full := make([]string, group)
	for i := range full {
		full[i] = "zzzzzz"
	}
	if err := tb.resetSalted(6, algo.enc, algo.salt); err != nil {
		t.Fatal(err)
	}
	tb.fillFromWords(full)

	// Now a fill of two. Lanes 2.. must hash the EMPTY candidate, not "zzzzzz".
	if n := tb.fillFromWords([]string{"aaaaaa", "bbbbbb"}); n != 2 {
		t.Fatalf("second fill wrote %d lanes, want 2", n)
	}
	algo.group(tb, out)

	stale, err := hashText("zzzzzz", "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	empty, err := hashText("", "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i < group; i++ {
		got := hex.EncodeToString(out[i][:])
		if strings.EqualFold(got, stale) {
			t.Fatalf("lane %d still holds the previous fill's candidate", i)
		}
		if !strings.EqualFold(got, empty) {
			t.Fatalf("lane %d = %s, want the empty candidate %s", i, got, empty)
		}
	}
}

// TestFillFromWordsRefusesAMixedBucket pins the precondition rather than
// leaving it to a comment. A word of the wrong length would be hashed with a
// bit length that does not describe it, producing a wrong digest silently.
func TestFillFromWordsRefusesAMixedBucket(t *testing.T) {
	algo, ok := fastAlgoPlanFor("md5", "", "")
	if !ok {
		t.Skip("no md5 vector plan on this backend")
	}
	tb := newTransposedBatch(algo.shape)
	if err := tb.resetSalted(4, algo.enc, algo.salt); err != nil {
		t.Fatal(err)
	}
	if n := tb.fillFromWords([]string{"aaaa", "bbbb", "ccccc", "dddd"}); n != 2 {
		t.Fatalf("filled %d lanes; want 2, stopping at the first wrong-length word", n)
	}
}
