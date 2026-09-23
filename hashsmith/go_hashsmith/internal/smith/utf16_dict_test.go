package smith

import (
	"strings"
	"testing"
)

// TestDictUTF16MatchesScalar is the differential check for the UTF-16LE
// constructions through the whole dictionary engine. The non-ASCII words are
// the point: the fill's byte-to-(b,0x00) expansion is not utf16le for them, so
// the core must refuse them and the scalar verifier must find them anyway.
func TestDictUTF16MatchesScalar(t *testing.T) {
	words := []string{
		"alpha", "Bravo9", "", "café", "naïve", "日本", "x",
		strings.Repeat("p", 40), "hunter2",
	}
	path := writeWords(t, words)

	for _, typ := range []string{
		"sha1-utf16le-pass-salt", "sha256-salt-utf16le-pass", "md5-utf16le-pass-salt",
	} {
		typ := typ
		for _, want := range []string{"alpha", "café", "日本", "hunter2", ""} {
			want := want
			t.Run(typ+"/"+want, func(t *testing.T) {
				const salt = "s4lt"
				target, err := hashCompatSaltedDigest(want, typ, salt)
				if err != nil {
					t.Skipf("hashCompatSaltedDigest: %v", err)
				}
				// Guard against a vacuous pass: if the "batched" half were
				// also on the scalar verifier, the two halves would agree
				// trivially. This is how the sha1 differential test went a
				// whole commit asserting nothing.
				d := newDictVectorLanesMulti(typ, []string{target}, []int{0}, salt, "prefix")
				if d == nil {
					t.Fatalf("%s resolves to no batched core, so this test compares scalar with scalar", typ)
				}
				sc, ok := d.core.(*dictStdCore)
				if !ok || !sc.utf16 {
					t.Fatalf("%s did not resolve to a UTF-16 contiguous core (%T)", typ, d.core)
				}
				gotVec, okVec, _ := runDict(t, path, typ, target, salt, "prefix", 4)

				t.Setenv("HASHSMITH_NO_FASTPATH", "1")
				gotScalar, okScalar, _ := runDict(t, path, typ, target, salt, "prefix", 4)

				if okVec != okScalar || gotVec != gotScalar {
					t.Fatalf("batched found %q (%v), scalar found %q (%v) — the two paths disagree",
						gotVec, okVec, gotScalar, okScalar)
				}
				if !okScalar {
					t.Fatalf("neither path found %q, which is in the wordlist", want)
				}
			})
		}
	}
}
