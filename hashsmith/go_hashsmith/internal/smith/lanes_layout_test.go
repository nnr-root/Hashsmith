package smith

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// genLayout builds a keyspaceLayout backed by an explicit candidate list,
// which is what hybrid, combinator, markov and prince all look like from
// runLayoutBatched's side: a positional generator over a known total.
func genLayout(words []string) *keyspaceLayout {
	return &keyspaceLayout{
		total: int64(len(words)),
		gen:   func(i int64) string { return words[i] },
	}
}

// runBatchedLayout drives runLayoutBatched and reports what it found.
func runBatchedLayout(t *testing.T, words []string, typ, target, salt, saltMode string, workers int) (string, int64) {
	t.Helper()
	verify := func(pw string) bool {
		ok, _ := verifyCandidate(pw, target, typ, salt, saltMode)
		return ok
	}
	var attempts int64
	pw, err := runLayoutBatched(context.Background(), genLayout(words), 0, 0, workers, &attempts, nil,
		func() *dictVectorLanes {
			return newDictVectorLanesMulti(typ, []string{target}, []int{0}, salt, saltMode)
		},
		verify)
	if err != nil {
		t.Fatalf("runLayoutBatched: %v", err)
	}
	return pw, attempts
}

// TestRunLayoutBatchedMatchesRunLayout is the differential that matters: for a
// generated keyspace, the batched runner and the scalar one must reach the
// same verdict on every candidate. They are two implementations of one
// question.
func TestRunLayoutBatchedMatchesRunLayout(t *testing.T) {
	words := []string{
		"a", "bb", "ccc", "password", "hunter2", "",
		"café", "日本", strings.Repeat("z", 60), "final",
	}
	for _, typ := range []string{"md5", "ntlm", "sha1"} {
		typ := typ
		for _, want := range words {
			want := want
			t.Run(fmt.Sprintf("%s/%q", typ, want), func(t *testing.T) {
				target, err := hashText(want, typ, "", "")
				if err != nil {
					t.Skipf("hashText: %v", err)
				}
				gotBatched, _ := runBatchedLayout(t, words, typ, target, "", "", 4)

				verify := func(pw string) bool {
					ok, _ := verifyCandidate(pw, target, typ, "", "")
					return ok
				}
				var scalarAttempts int64
				gotScalar, err := runLayout(context.Background(), genLayout(words), 0, 0, 4,
					&scalarAttempts, nil, verify)
				if err != nil {
					t.Fatal(err)
				}
				if gotBatched != gotScalar {
					t.Fatalf("batched found %q, scalar found %q — the two runners disagree",
						gotBatched, gotScalar)
				}
				if gotScalar != want {
					t.Fatalf("neither runner found %q, which is in the keyspace", want)
				}
			})
		}
	}
}

// TestRunLayoutBatchedCountsEveryCandidate keeps the progress counter honest.
// A batched run hashes in groups, and a group that credited its padding slots
// or dropped a partial bucket would report a keyspace it never searched.
func TestRunLayoutBatchedCountsEveryCandidate(t *testing.T) {
	var words []string
	for i := 0; i < 1000; i++ {
		words = append(words, strings.Repeat(string(rune('a'+i%26)), 1+i%13)+fmt.Sprint(i))
	}
	target, err := hashText("definitely-absent-from-this-keyspace", "md5", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{1, 2, 4, 8} {
		got, attempts := runBatchedLayout(t, words, "md5", target, "", "", workers)
		if got != "" {
			t.Fatalf("workers=%d: found %q in a keyspace that does not contain it", workers, got)
		}
		if attempts != int64(len(words)) {
			t.Errorf("workers=%d: counted %d attempts, want %d — a bucket was dropped or "+
				"padding slots were credited", workers, attempts, len(words))
		}
	}
}

// TestRunLayoutBatchedFindsAtEveryPosition covers the partial-bucket flush: a
// hit in the last few candidates sits in a bucket that never fills a group and
// is only ever tested by the end-of-chunk flush.
func TestRunLayoutBatchedFindsAtEveryPosition(t *testing.T) {
	const n = 900
	for _, pos := range []int{0, 1, 19, 20, 21, n - 2, n - 1} {
		pos := pos
		t.Run(fmt.Sprint(pos), func(t *testing.T) {
			words := make([]string, n)
			for i := range words {
				words[i] = strings.Repeat(string(rune('a'+i%26)), 1+i%7)
			}
			words[pos] = "needle" + fmt.Sprint(pos)
			target, err := hashText(words[pos], "md5", "", "")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := runBatchedLayout(t, words, "md5", target, "", "", 4)
			if got != words[pos] {
				t.Fatalf("at position %d: found %q, want %q", pos, got, words[pos])
			}
		})
	}
}

// TestRunLayoutBatchedIsActuallyBatched guards against a vacuous suite: if no
// core resolved, every test above would compare the scalar path with itself.
func TestRunLayoutBatchedIsActuallyBatched(t *testing.T) {
	for _, typ := range []string{"md5", "ntlm", "sha1", "sha256"} {
		h, err := hashText("probe", typ, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if newDictVectorLanesMulti(typ, []string{h}, []int{0}, "", "") == nil {
			t.Errorf("%s resolves to no batched core, so the generated-keyspace runner "+
				"cannot be exercised for it", typ)
		}
	}
}
