package main

// Tests for PRINCE mode (prince.go).
//
// The coverage/ordering tests deliberately check the generator against an
// INDEPENDENT enumeration written here (princeReference below: nested loops and
// an odometer over freshly re-derived buckets) rather than against the
// generator's own chain table. Checking a generator against itself would pass
// for any self-consistent bug — including the two this design calls out as
// silent: a zero-count chain in the list, and a reversed mixed-radix order
// inside a chain.

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ── independent reference enumeration ────────────────────────────────────────

// princeReference produces the candidate stream PRINCE is specified to produce,
// derived from the spec directly: buckets by rune length; chains ordered by
// total length N ascending, then part count k ascending, then lexicographically
// on the composition; within a chain an odometer over the buckets with the LAST
// part varying fastest. It shares no code with prince.go.
func princeReference(elems []string, minLen, maxLen, maxElems int) []string {
	buckets := map[int][]string{}
	for _, e := range elems {
		n := len([]rune(e))
		if n < 1 || n > maxLen {
			continue
		}
		buckets[n] = append(buckets[n], e)
	}

	var out []string
	emit := func(parts []int) {
		idx := make([]int, len(parts))
		for {
			var sb strings.Builder
			for p, L := range parts {
				sb.WriteString(buckets[L][idx[p]])
			}
			out = append(out, sb.String())
			p := len(parts) - 1
			for p >= 0 {
				idx[p]++
				if idx[p] < len(buckets[parts[p]]) {
					break
				}
				idx[p] = 0
				p--
			}
			if p < 0 {
				return
			}
		}
	}

	var comps func(remaining, k int, cur []int)
	comps = func(remaining, k int, cur []int) {
		if k == 1 {
			if len(buckets[remaining]) == 0 {
				return
			}
			parts := make([]int, 0, len(cur)+1)
			parts = append(parts, cur...)
			parts = append(parts, remaining)
			emit(parts)
			return
		}
		for L := 1; L <= remaining-(k-1); L++ {
			if len(buckets[L]) == 0 {
				continue
			}
			next := make([]int, 0, len(cur)+1)
			next = append(next, cur...)
			next = append(next, L)
			comps(remaining-L, k-1, next)
		}
	}

	for N := minLen; N <= maxLen; N++ {
		for k := 1; k <= maxElems && k <= N; k++ {
			comps(N, k, nil)
		}
	}
	return out
}

// enumerate walks a layout index by index and returns the candidate stream.
func enumerate(l *keyspaceLayout) []string {
	out := make([]string, 0, l.total)
	for i := int64(0); i < l.total; i++ {
		out = append(out, l.candidate(i))
	}
	return out
}

// mustLayout builds a prince layout or fails the test.
func mustLayout(t *testing.T, elems []string, minLen, maxLen, maxElems int) *keyspaceLayout {
	t.Helper()
	l, _, err := princeLayout(elems, minLen, maxLen, maxElems)
	if err != nil {
		t.Fatalf("princeLayout(%v, %d, %d, %d): %v", elems, minLen, maxLen, maxElems, err)
	}
	return l
}

// princeCases are the shapes every structural property is checked over. They
// cover a dense length spectrum, a spectrum with a HOLE in the middle (no
// 3-rune element while 1, 2 and 4 exist), duplicate elements, single-element
// chains, and non-ASCII elements whose byte length differs from their rune
// length.
var princeCases = []struct {
	name                     string
	elems                    []string
	minLen, maxLen, maxElems int
}{
	{"dense", []string{"a", "b", "cd", "xyz", "q", "mnop"}, 1, 5, 3},
	{"hole-at-3", []string{"a", "bc", "defg"}, 1, 6, 3},
	{"single-element-chains", []string{"love", "you", "123", "dog"}, 3, 4, 1},
	{"two-elements", []string{"love", "you", "123"}, 1, 12, 2},
	{"three-elements", []string{"love", "you", "123"}, 1, 10, 3},
	{"duplicates-allowed", []string{"ab", "ab", "c"}, 1, 5, 3},
	{"narrow-range", []string{"aa", "bb", "c"}, 4, 5, 4},
	{"unicode-runes", []string{"é", "ü", "naïve", "ab"}, 1, 6, 3},
	{"all-too-long-but-one", []string{"abcdefgh", "xy"}, 1, 4, 3},
	{"min-equals-max", []string{"a", "bc", "def"}, 6, 6, 4},
}

// ── 1. purity / determinism / concurrency ────────────────────────────────────

func TestPrinceGenIsPureAndDeterministic(t *testing.T) {
	l := mustLayout(t, []string{"love", "you", "123", "a", "bc"}, 1, 9, 3)
	if l.total < 100 {
		t.Fatalf("test shape too small to be meaningful: total=%d", l.total)
	}
	ref := enumerate(l)

	// Repeated calls on the same index.
	for _, i := range []int64{0, 1, 7, l.total / 3, l.total - 1} {
		for r := 0; r < 5; r++ {
			if got := l.candidate(i); got != ref[i] {
				t.Fatalf("candidate(%d) call %d: want %q got %q", i, r, ref[i], got)
			}
		}
	}

	// Out-of-order traversal: a deterministic shuffle (a stride coprime with
	// total would be simplest, so use an explicit permutation instead).
	order := make([]int64, l.total)
	for i := range order {
		order[i] = int64(i)
	}
	sort.Slice(order, func(a, b int) bool {
		return (order[a]*2654435761)%1000003 < (order[b]*2654435761)%1000003
	})
	for _, i := range order {
		if got := l.candidate(i); got != ref[i] {
			t.Fatalf("out-of-order candidate(%d): want %q got %q", i, ref[i], got)
		}
	}
}

// TestPrinceGenConcurrent is the -race target: runLayout calls gen from every
// worker at once, so any retained state between calls (a shared digit scratch
// buffer, a cached chain index) must show up here.
func TestPrinceGenConcurrent(t *testing.T) {
	l := mustLayout(t, []string{"love", "you", "123", "a", "bc", "wxyz"}, 1, 9, 3)
	ref := enumerate(l)

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make([]string, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// Each goroutine walks the whole space from a different offset, so
			// they interleave on different indices at the same moment.
			start := int64(g) * (l.total / goroutines)
			for n := int64(0); n < l.total; n++ {
				i := (start + n) % l.total
				if got := l.candidate(i); got != ref[i] {
					errs[g] = fmt.Sprintf("goroutine %d: candidate(%d) want %q got %q", g, i, ref[i], got)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	for _, e := range errs {
		if e != "" {
			t.Fatal(e)
		}
	}
}

// ── 2. coverage against an independent enumeration ───────────────────────────

func TestPrinceCoverageMatchesReference(t *testing.T) {
	for _, tc := range princeCases {
		t.Run(tc.name, func(t *testing.T) {
			l := mustLayout(t, tc.elems, tc.minLen, tc.maxLen, tc.maxElems)
			want := princeReference(tc.elems, tc.minLen, tc.maxLen, tc.maxElems)
			if int64(len(want)) != l.total {
				t.Fatalf("total: reference has %d candidates, layout reports %d", len(want), l.total)
			}
			got := enumerate(l)
			// Exact ordered equality: this is coverage AND ordering AND the
			// within-chain mixed-radix direction, all at once.
			if len(got) != len(want) {
				t.Fatalf("length: want %d got %d", len(want), len(got))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("index %d: want %q got %q\n full want=%v\n full got =%v",
						i, want[i], got[i], want, got)
				}
			}
			// And as a multiset, independently of order — so a failure message
			// distinguishes "wrong order" from "wrong contents".
			if !sameMultiset(got, want) {
				t.Fatalf("multiset mismatch\n want=%v\n got =%v", want, got)
			}
		})
	}
}

func sameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] == 0 {
			delete(m, s)
		}
	}
	return len(m) == 0
}

// TestPrinceDuplicatesAreNotDeduped pins the documented deliberate limit: the
// same string reached through two different chains is emitted twice. Here
// "a"+"aa" (chain 1,2) and "aa"+"a" (chain 2,1) both yield "aaa", and both are
// kept — global dedup would cost memory proportional to the keyspace, and
// princeprocessor does not dedup by default either.
func TestPrinceDuplicatesAreNotDeduped(t *testing.T) {
	l := mustLayout(t, []string{"a", "aa"}, 3, 3, 2)
	got := enumerate(l)
	want := []string{"aaa", "aaa"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("want %v (cross-chain duplicate kept), got %v", want, got)
	}
	if l.total != 2 {
		t.Fatalf("total: want 2 got %d", l.total)
	}
}

// ── 3. tiling: --skip / --limit slices union to the unsliced run ─────────────

// collectSlice runs the layout through runLayout (the real engine) with one
// worker, so the candidates come back in index order for the requested slice.
func collectSlice(t *testing.T, l *keyspaceLayout, skip, limit int64) []string {
	t.Helper()
	var out []string
	var attempts int64
	_, err := runLayout(context.Background(), l, skip, limit, 1, &attempts, nil,
		func(c string) bool {
			out = append(out, c)
			return false
		})
	if err != nil {
		t.Fatalf("runLayout(skip=%d limit=%d): %v", skip, limit, err)
	}
	if int64(len(out)) != attempts {
		t.Fatalf("attempt accounting: collected %d, counter says %d", len(out), attempts)
	}
	return out
}

func TestPrinceSkipLimitTiling(t *testing.T) {
	for _, tc := range princeCases {
		t.Run(tc.name, func(t *testing.T) {
			l := mustLayout(t, tc.elems, tc.minLen, tc.maxLen, tc.maxElems)
			if l.total == 0 {
				t.Skip("empty keyspace")
			}
			full := collectSlice(t, l, 0, 0)
			if int64(len(full)) != l.total {
				t.Fatalf("unsliced run: want %d candidates got %d", l.total, len(full))
			}
			for _, chunk := range []int64{1, 2, 3, 7, 13, l.total, l.total + 5} {
				var joined []string
				for skip := int64(0); skip < l.total; skip += chunk {
					joined = append(joined, collectSlice(t, l, skip, chunk)...)
				}
				if len(joined) != len(full) {
					t.Fatalf("chunk %d: slices total %d candidates, unsliced run has %d "+
						"(gaps or repeats)", chunk, len(joined), len(full))
				}
				for i := range full {
					if joined[i] != full[i] {
						t.Fatalf("chunk %d: index %d: sliced %q, unsliced %q",
							chunk, i, joined[i], full[i])
					}
				}
			}
		})
	}
}

// TestPrinceSkipLimitFindsHitInExactlyOneSlice is the operational form of the
// tiling property: a target candidate must be produced by exactly one slice of
// a partitioned run — not zero (a gap) and not two (an overlap).
func TestPrinceSkipLimitFindsHitInExactlyOneSlice(t *testing.T) {
	l := mustLayout(t, []string{"love", "you", "123"}, 1, 10, 3)
	const target = "loveyou123"
	slices := int64(4)
	chunk := (l.total + slices - 1) / slices
	hits := 0
	for s := int64(0); s < slices; s++ {
		for _, c := range collectSlice(t, l, s*chunk, chunk) {
			if c == target {
				hits++
			}
		}
	}
	if hits != 1 {
		t.Fatalf("want %q in exactly 1 of %d slices, found in %d", target, slices, hits)
	}
}

// ── 4. ordering: shortest first ──────────────────────────────────────────────

func TestPrinceOrderingIsShortestFirst(t *testing.T) {
	for _, tc := range princeCases {
		t.Run(tc.name, func(t *testing.T) {
			l := mustLayout(t, tc.elems, tc.minLen, tc.maxLen, tc.maxElems)
			prev := -1
			for i := int64(0); i < l.total; i++ {
				n := len([]rune(l.candidate(i)))
				if n < prev {
					t.Fatalf("index %d: length %d follows length %d — not shortest-first",
						i, n, prev)
				}
				if n < tc.minLen || n > tc.maxLen {
					t.Fatalf("index %d: candidate %q has %d runes, outside [%d,%d]",
						i, l.candidate(i), n, tc.minLen, tc.maxLen)
				}
				prev = n
			}
		})
	}
}

// TestPrinceOrderingKAscendingWithinLength pins the second ordering key: within
// one total length, fewer parts come first.
func TestPrinceOrderingKAscendingWithinLength(t *testing.T) {
	// Lengths 1 and 2 both available, so N=4 has chains with k=2 ((2,2)) and
	// k=3 ((1,1,2),(1,2,1),(2,1,1)) and k=4.
	g, err := newPrinceGenerator([]string{"a", "bc"}, 4, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	var ks []int
	var comps [][]int
	for _, ch := range g.chains {
		ks = append(ks, len(ch.parts))
		comps = append(comps, ch.parts)
	}
	for i := 1; i < len(ks); i++ {
		if ks[i] < ks[i-1] {
			t.Fatalf("chain %d has %d parts after a chain with %d — k not ascending (%v)",
				i, ks[i], ks[i-1], comps)
		}
	}
	// And lexicographic within one k: k=3 must be (1,1,2),(1,2,1),(2,1,1).
	var k3 [][]int
	for _, c := range comps {
		if len(c) == 3 {
			k3 = append(k3, c)
		}
	}
	want := [][]int{{1, 1, 2}, {1, 2, 1}, {2, 1, 1}}
	if fmt.Sprint(k3) != fmt.Sprint(want) {
		t.Fatalf("k=3 compositions: want %v got %v", want, k3)
	}
}

// ── 5. boundaries ────────────────────────────────────────────────────────────

func TestPrinceBoundaries(t *testing.T) {
	t.Run("empty element list", func(t *testing.T) {
		l := mustLayout(t, nil, 1, 8, 4)
		if l.total != 0 {
			t.Fatalf("want total 0 got %d", l.total)
		}
		if l.gen == nil {
			t.Fatal("gen must be set even for an empty keyspace (a nil gen would " +
				"send candidate() into nil segments)")
		}
		if c := l.candidate(0); c != "" {
			t.Fatalf("candidate(0) on empty keyspace: want %q got %q", "", c)
		}
		if got := collectSlice(t, l, 0, 0); len(got) != 0 {
			t.Fatalf("empty keyspace produced %v", got)
		}
	})

	t.Run("all elements too long", func(t *testing.T) {
		l := mustLayout(t, []string{"abcdefgh", "ijklmnop"}, 1, 4, 4)
		if l.total != 0 {
			t.Fatalf("want total 0 got %d (candidates: %v)", l.total, enumerate(l))
		}
	})

	t.Run("elements shorter than minLen still combine", func(t *testing.T) {
		// A single 2-rune element with minLen 4 yields nothing at k=1 but
		// "abab" at k=2 — the point of the mode.
		l := mustLayout(t, []string{"ab"}, 4, 4, 2)
		got := enumerate(l)
		if len(got) != 1 || got[0] != "abab" {
			t.Fatalf("want [abab] got %v", got)
		}
	})

	t.Run("minLen > maxLen refused", func(t *testing.T) {
		if _, _, err := princeLayout([]string{"a"}, 5, 4, 2); err == nil {
			t.Fatal("want an error for minLen > maxLen, got nil")
		}
	})

	t.Run("minLen < 1 refused", func(t *testing.T) {
		if _, _, err := princeLayout([]string{"a"}, 0, 4, 2); err == nil {
			t.Fatal("want an error for minLen < 1, got nil")
		}
	})

	t.Run("maxElems < 1 refused", func(t *testing.T) {
		if _, _, err := princeLayout([]string{"a"}, 1, 4, 0); err == nil {
			t.Fatal("want an error for maxElems < 1, got nil")
		}
	})

	t.Run("maxElems above the ceiling refused", func(t *testing.T) {
		if _, _, err := princeLayout([]string{"a"}, 1, 4, princeMaxElemsPerChain+1); err == nil {
			t.Fatal("want an error for maxElems past the ceiling, got nil")
		}
	})

	t.Run("maxElems=1 is a length-filtered wordlist", func(t *testing.T) {
		elems := []string{"a", "bb", "ccc", "dddd", "eeeee"}
		l := mustLayout(t, elems, 2, 4, 1)
		got := enumerate(l)
		want := []string{"bb", "ccc", "dddd"} // shortest-first, list order within a length
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("want %v got %v", want, got)
		}
	})

	t.Run("empty bucket in the middle of the range", func(t *testing.T) {
		// No 3-rune element: N=3 is reachable only as 1+2 / 2+1, never k=1.
		l := mustLayout(t, []string{"a", "bc"}, 3, 3, 2)
		got := enumerate(l)
		want := []string{"abc", "bca"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("want %v got %v", want, got)
		}
	})

	t.Run("blank and oversized elements are dropped, not counted", func(t *testing.T) {
		l := mustLayout(t, []string{"", "a", "", "toolongforthis"}, 1, 2, 2)
		got := enumerate(l)
		want := []string{"a", "aa"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("want %v got %v", want, got)
		}
	})

	t.Run("out-of-range indices return empty", func(t *testing.T) {
		l := mustLayout(t, []string{"a", "bc"}, 1, 4, 2)
		if c := l.candidate(-1); c != "" {
			t.Fatalf("candidate(-1): want %q got %q", "", c)
		}
		if c := l.candidate(l.total); c != "" {
			t.Fatalf("candidate(total): want %q got %q", "", c)
		}
	})
}

// TestPrinceBucketsByRuneNotByte guards the rune-vs-byte-length hazard: "é" is
// one rune but two bytes, so byte bucketing would file it under length 2 and
// emit candidates outside the requested rune range.
func TestPrinceBucketsByRuneNotByte(t *testing.T) {
	l := mustLayout(t, []string{"é", "ü"}, 2, 2, 2)
	got := enumerate(l)
	want := []string{"éé", "éü", "üé", "üü"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("want %v got %v", want, got)
	}
	for _, c := range got {
		if n := len([]rune(c)); n != 2 {
			t.Fatalf("%q has %d runes, want 2", c, n)
		}
	}
}

// ── the two silent hazards ───────────────────────────────────────────────────

// TestPrinceNoZeroCountChains is the structural guard for the hazard the design
// calls out: a chain stored with count 0 makes the index-to-chain lookup
// ambiguous, and the symptom is wrong candidates rather than a crash. Offsets
// must therefore be STRICTLY increasing and every count > 0.
func TestPrinceNoZeroCountChains(t *testing.T) {
	for _, tc := range princeCases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := newPrinceGenerator(tc.elems, tc.minLen, tc.maxLen, tc.maxElems)
			if err != nil {
				t.Fatal(err)
			}
			var sum int64
			for i, ch := range g.chains {
				if ch.count <= 0 {
					t.Fatalf("chain %d %v has count %d — zero-count chains must be "+
						"omitted from the list entirely", i, ch.parts, ch.count)
				}
				if len(ch.parts) == 0 {
					t.Fatalf("chain %d has no parts", i)
				}
				for _, L := range ch.parts {
					if L < 1 || L >= len(g.buckets) || len(g.buckets[L]) == 0 {
						t.Fatalf("chain %d %v references empty bucket %d", i, ch.parts, L)
					}
				}
				if ch.off != sum {
					t.Fatalf("chain %d: off %d, expected prefix sum %d", i, ch.off, sum)
				}
				if i > 0 && g.offs[i] <= g.offs[i-1] {
					t.Fatalf("offsets not strictly increasing at %d: %d after %d",
						i, g.offs[i], g.offs[i-1])
				}
				sum = satAdd(sum, ch.count)
			}
			if sum != g.total {
				t.Fatalf("total %d != sum of chain counts %d", g.total, sum)
			}
		})
	}
}

// TestPrinceSaturatesRatherThanWraps: chain counts multiply then sum, so a big
// element list over a long range overflows int64. The layout total must
// saturate at MaxInt64 (an incomplete-but-correct sweep, as maskKeyspace does),
// never wrap negative, and the exact total must still be reported truthfully.
func TestPrinceSaturatesRatherThanWraps(t *testing.T) {
	elems := make([]string, 1000)
	for i := range elems {
		elems[i] = string(rune('a' + i%26)) // 1000 one-rune elements (with repeats)
	}
	// One chain: eight 1-rune parts -> 1000^8 = 1e24, far past int64.
	l, exact, err := princeLayout(elems, 8, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if l.total != math.MaxInt64 {
		t.Fatalf("total: want saturation at %d, got %d", int64(math.MaxInt64), l.total)
	}
	if l.total < 0 {
		t.Fatal("total wrapped negative")
	}
	if exact.Cmp(maxInt64Big) <= 0 {
		t.Fatalf("exact total %s should exceed int64", exact)
	}
	wantExact := new(big.Int).Exp(big.NewInt(1000), big.NewInt(8), nil)
	if exact.Cmp(wantExact) != 0 {
		t.Fatalf("exact: want %s got %s", wantExact, exact)
	}
	// Candidates near the saturated bound must still decode to real strings.
	for _, i := range []int64{0, 1, math.MaxInt64 - 1} {
		if c := l.candidate(i); len([]rune(c)) != 8 {
			t.Fatalf("candidate(%d) = %q, want 8 runes", i, c)
		}
	}
}

// TestPrinceKeyspaceExactMatchesTotal: when nothing saturates, the exact
// (math/big) total and the int64 total must agree — that is what --keyspace
// prints and what a distributed script divides into --skip/--limit slices.
func TestPrinceKeyspaceExactMatchesTotal(t *testing.T) {
	for _, tc := range princeCases {
		t.Run(tc.name, func(t *testing.T) {
			l, exact, err := princeLayout(tc.elems, tc.minLen, tc.maxLen, tc.maxElems)
			if err != nil {
				t.Fatal(err)
			}
			if exact.Cmp(big.NewInt(l.total)) != 0 {
				t.Fatalf("exact %s != total %d", exact, l.total)
			}
		})
	}
}

// TestPrinceRefusesOversizedInputs: both memory caps must REFUSE, never
// silently truncate — a truncated element list or chain list means candidates
// that are never tried while the tool still reports "not found".
func TestPrinceRefusesOversizedInputs(t *testing.T) {
	t.Run("element cap", func(t *testing.T) {
		old := princeMaxElements
		princeMaxElements = 4
		defer func() { princeMaxElements = old }()
		_, _, err := princeLayout([]string{"a", "b", "c", "d", "e"}, 1, 4, 2)
		if err == nil {
			t.Fatal("want a refusal past the element cap, got nil")
		}
		if !strings.Contains(err.Error(), "element") {
			t.Fatalf("refusal should name the element list: %v", err)
		}
		// At the cap exactly: accepted.
		if _, _, err := princeLayout([]string{"a", "b", "c", "d"}, 1, 4, 2); err != nil {
			t.Fatalf("exactly at the cap should be accepted: %v", err)
		}
	})

	t.Run("chain cap", func(t *testing.T) {
		old := princeMaxChains
		princeMaxChains = 8
		defer func() { princeMaxChains = old }()
		_, _, err := princeLayout([]string{"a", "bc", "def"}, 1, 12, 6)
		if err == nil {
			t.Fatal("want a refusal past the chain cap, got nil")
		}
		if !strings.Contains(err.Error(), "combination") {
			t.Fatalf("refusal should explain the chain explosion: %v", err)
		}
	})

	t.Run("defaults are the documented caps", func(t *testing.T) {
		if princeMaxElements != 1<<20 || princeMaxChains != 1<<20 {
			t.Fatalf("caps changed: elements=%d chains=%d", princeMaxElements, princeMaxChains)
		}
	})
}

// ── end-to-end wiring ────────────────────────────────────────────────────────

func princeMD5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func writeElemFile(t *testing.T, words []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "elems.txt")
	if err := os.WriteFile(p, []byte(strings.Join(words, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPrinceCracksMultiWordPasswordDictCannot is the reason the mode exists:
// "loveyou123" is not in the element list, so a dict run over the same list
// cannot find it; PRINCE builds it from three elements.
func TestPrinceCracksMultiWordPasswordDictCannot(t *testing.T) {
	elems := []string{"love", "you", "123", "dog", "cat"}
	path := writeElemFile(t, elems)
	target := princeMD5Hex("loveyou123")

	cc, err := newCrackCtx("", true, "", false, "", false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cc.princeElems = 3

	found, err := doCrack(target, "md5", "prince", path, "", 1, 10, 2,
		"", "prefix", "", false, nil, nil, cc)
	if err != nil {
		t.Fatalf("prince run: %v", err)
	}
	if !found {
		t.Fatal("prince did not find loveyou123")
	}

	// The same list under a plain dict attack must NOT find it.
	cc2, err := newCrackCtx("", true, "", false, "", false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	found, err = doCrack(target, "md5", "dict", path, "", 1, 10, 2,
		"", "prefix", "", false, nil, nil, cc2)
	if err != nil {
		t.Fatalf("dict run: %v", err)
	}
	if found {
		t.Fatal("dict found loveyou123 — the test's premise is broken")
	}
}

// TestPrinceStdoutAndKeyspaceAgree checks the two CLI surfaces against the
// layout: --stdout must emit exactly the layout's stream, and --keyspace must
// print exactly its total.
func TestPrinceStdoutAndKeyspaceAgree(t *testing.T) {
	elems := []string{"love", "you", "123"}
	path := writeElemFile(t, elems)
	l := mustLayout(t, elems, 1, 8, 2)

	out := captureStdout(t, func() error {
		return streamCandidates("prince", path, "", "", 1, 8, 2, nil, nil, 0, 0)
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if out == "" {
		lines = nil
	}
	want := enumerate(l)
	if fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Fatalf("--stdout stream:\n want %v\n got  %v", want, lines)
	}

	ks := captureStdout(t, func() error {
		return printKeyspace("prince", path, "", "", 1, 8, 2, nil)
	})
	if strings.TrimSpace(ks) != fmt.Sprint(l.total) {
		t.Fatalf("--keyspace: want %d got %q", l.total, strings.TrimSpace(ks))
	}
}

// TestPrinceKeyspaceRefusesSaturated: --keyspace must refuse to print a value a
// distributed script would divide and under-cover, exactly as the other modes do.
func TestPrinceKeyspaceRefusesSaturated(t *testing.T) {
	elems := make([]string, 1000)
	for i := range elems {
		elems[i] = string(rune('a' + i%26))
	}
	path := writeElemFile(t, elems)
	err := printKeyspace("prince", path, "", "", 8, 8, 8, nil)
	if err == nil {
		t.Fatal("want a refusal for a keyspace past int64, got nil")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPrinceSessionResumeDistinguishesElemCount: --prince-elems changes the
// candidate stream, so a saved index means something different under a
// different value. A session must not resume across that change.
func TestPrinceSessionResumeDistinguishesElemCount(t *testing.T) {
	s := &sessionState{
		Mode: "prince", Type: "md5", Target: "x", MinLen: 1, MaxLen: 8,
		Wordlist: "e.txt", PrinceElems: 3,
	}
	if !s.matches("prince", "md5", "x", "", 1, 8, "", [4]string{}, false, "", "", "e.txt", "", 3) {
		t.Fatal("identical prince session should match")
	}
	if s.matches("prince", "md5", "x", "", 1, 8, "", [4]string{}, false, "", "", "e.txt", "", 4) {
		t.Fatal("a different --prince-elems must NOT resume the saved checkpoint")
	}
}
