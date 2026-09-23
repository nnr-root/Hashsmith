package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The contiguous batch feeds sha1/sha256/md5 through the stdlib's own
// hardware-accelerated cores, so the only thing worth asserting about a new
// filler is that what it hashes is what hashText hashes. Every expected digest
// comes from hashText, never from the batch itself.
func TestContigFillFromWordsMatchesHashText(t *testing.T) {
	for _, tc := range []struct{ typ, salt, saltMode string }{
		{"sha1", "", ""},
		{"sha256", "", ""},
		{"md5", "", ""},
		{"sha1", "deadbeef", "prefix"},
		{"sha256", "deadbeef", "suffix"},
		{"md5", "s4lt", "prefix"},
		// The rest of the SHA-2 family, held back until there was something
		// to test them against. sha512's digest is exactly stdMaxDigestLen,
		// so it is the one that would overflow the slab if that constant
		// ever shrank.
		{"sha224", "", ""},
		{"sha384", "", ""},
		{"sha512", "", ""},
		{"sha224", "deadbeef", "prefix"},
		{"sha384", "deadbeef", "suffix"},
		{"sha512", "deadbeef", "prefix"},
	} {
		tc := tc
		t.Run(tc.typ+"/"+tc.saltMode, func(t *testing.T) {
			algo, sp, ok := stdSaltedPlanFor(tc.typ, tc.salt, tc.saltMode)
			if !ok {
				t.Skipf("no contiguous plan for %s", tc.typ)
			}
			const group = 16
			cb := newContigBatch(group, algo.digLen, sp)

			const width = 7
			words := make([]string, group)
			for i := range words {
				words[i] = string([]byte{
					byte('a' + i%26), byte('a' + (i/26)%26), 'q', 'r', 's',
					byte('0' + i%10), byte('0' + (i/10)%10),
				})
				if len(words[i]) != width {
					t.Fatalf("test word %q is not %d bytes", words[i], width)
				}
			}

			n := cb.fillFromWords(words)
			if n != group {
				t.Fatalf("filled %d slots, want %d", n, group)
			}
			algo.hashBatch(cb.messages(n), cb.stride, n, cb.out)

			for i, w := range words {
				want, err := hashText(w, tc.typ, tc.salt, tc.saltMode)
				if err != nil {
					t.Fatalf("hashText(%q): %v", w, err)
				}
				got := hex.EncodeToString(cb.digest(i))
				if !strings.EqualFold(got, want) {
					t.Fatalf("slot %d, word %q: contiguous core gave %s, hashText gives %s",
						i, w, got, want)
				}
				if back := string(cb.candidate(i)); back != w {
					t.Errorf("candidate(%d) = %q, want %q", i, back, w)
				}
			}
		})
	}
}

// A mixed-length bucket must stop rather than hash at the wrong stride, which
// would produce a wrong digest with no signal.
func TestContigFillFromWordsRefusesAMixedBucket(t *testing.T) {
	algo, sp, ok := stdSaltedPlanFor("sha1", "", "")
	if !ok {
		t.Skip("no sha1 contiguous plan")
	}
	cb := newContigBatch(8, algo.digLen, sp)
	if n := cb.fillFromWords([]string{"aaaa", "bbbb", "ccccc", "dddd"}); n != 2 {
		t.Fatalf("filled %d slots; want 2, stopping at the first wrong-length word", n)
	}
}
