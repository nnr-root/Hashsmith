package main

// PRINCE mode — every other mode in Hashsmith takes ONE word and mutates it.
// PRINCE takes SEVERAL words from a single element list and concatenates them
// into chains, emitted shortest-first:
//
//	elements: love, you, 123, dog
//	  -> loveyou, love123, dogdog, loveyou123, ...
//
// It fills a real gap. `correcthorsebattery` is invisible to a dictionary
// attack (it is not a word) and hopeless for a mask (19 characters), but it is
// three common words, so PRINCE reaches it in a few million guesses.
//
// Combinator is the degenerate two-list case of this; PRINCE generalises it to
// N elements drawn from one list, chosen so the concatenation lands in a
// requested length range.
//
// ── Architecture ─────────────────────────────────────────────────────────────
//
// PRINCE is a `gen` override on keyspaceLayout, exactly like markov and
// combinator. That is the whole integration: because runLayout drives a layout
// purely by index, PRINCE inherits --skip, --limit, --session resume,
// checkpointing and multi-target verification for free, with no change to the
// runner.
//
// Setting `gen` deliberately routes PRINCE to the SCALAR runner:
// fastPathEligible declines any layout with a gen override, because the
// NEON/AVX2 cores need candidates that are mixed-radix decodable from
// fixed-length segments. PRINCE candidates are variable-length and word-derived,
// so they cannot use the transposed batch. This is a documented consequence,
// not a regression to fix.
//
// ── The generator ────────────────────────────────────────────────────────────
//
//  1. Bucket elements by RUNE length (the codebase is rune-aware throughout;
//     byte length would mis-bucket any non-ASCII element). Elements longer than
//     maxLen are dropped — they can never appear in any chain.
//  2. A chain is a composition of a total length N (minLen..maxLen) into k parts
//     (1..maxElems), every part having a NON-EMPTY bucket.
//  3. Chain count = product over parts of len(buckets[L]).
//  4. Chain order: N ascending, then k ascending, then lexicographic on the
//     composition. Short, simple candidates first — the practical point of the
//     mode.
//  5. Offsets are the prefix sums of the chain counts; total is the final sum.
//  6. candidate(i) binary-searches i to its chain, mixed-radix decodes the local
//     index across that chain's buckets (LAST part varying fastest) and
//     concatenates.
//
// candidate is a PURE function of i with no state retained between calls. That
// is the property that makes every slicing feature work: runLayout calls it
// concurrently from every worker, out of order, and a resumed session re-derives
// the identical stream from a saved index.
//
// ── Deliberate limits ────────────────────────────────────────────────────────
//
//   - No cross-chain dedup: `ab`+`c` and `a`+`bc` both yield "abc", and both are
//     emitted. Deduplicating globally would cost memory proportional to the
//     keyspace; princeprocessor does not dedup by default either.
//   - Rules do not apply to PRINCE output in v1 (hashcat pipes princeprocessor
//     into hashcat and applies rules there).

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// princeDefaultElems is --prince-elems' default: chains of up to four
	// words. Four words of a common-word list already reaches the
	// "correct horse battery staple" shape without an unusable keyspace.
	princeDefaultElems = 4

	// princeMaxElemsPerChain bounds --prince-elems. Each extra element
	// multiplies the keyspace by the whole element list, so past this the
	// total is unreachable anyway; a hard bound also keeps chain recursion
	// depth (and therefore stack use) trivially bounded.
	princeMaxElemsPerChain = 32
)

// The two memory caps are vars rather than consts ONLY so tests can exercise
// the refusal paths without building a million-element list or enumerating a
// million chains. No production code path assigns to either.
var (
	// princeMaxElements caps how many elements are loaded into memory. The
	// whole element list is resident for the life of the run (as
	// combinator's right-hand list already is). Past this we REFUSE — never
	// silently truncate: a truncated element list means candidates that were
	// never tried while the tool still reports "not found".
	princeMaxElements = 1 << 20 // 1,048,576

	// princeMaxChains caps the number of distinct chains (length
	// compositions) held in memory. The chain count grows combinatorially in
	// maxLen and maxElems — a 32-character range with 8 elements per chain is
	// already ~10M compositions — so this is refused rather than silently
	// enumerated into a multi-gigabyte slice.
	princeMaxChains = 1 << 20 // 1,048,576
)

// princeChain is one length composition: the rune lengths of its parts, its
// global start index, and how many candidates it contributes.
//
// A chain with count 0 is NEVER stored. A zero-width entry makes the
// index-to-chain search ambiguous, and the failure is silent — some indices
// decode against the wrong chain and produce wrong candidates rather than
// crashing. Chains are only built from parts whose bucket is non-empty, and the
// emit path asserts count > 0 before appending.
type princeChain struct {
	parts []int // rune length of each part, in order
	off   int64 // global index of this chain's first candidate
	count int64 // candidates contributed (saturating; always > 0)
}

// princeGenerator holds everything candidate(i) needs. It is read-only once
// built, which is what makes candidate safe to call concurrently.
type princeGenerator struct {
	buckets [][]string    // buckets[L] = elements of rune length L (0..maxLen)
	chains  []princeChain // ordered: N asc, then k asc, then composition lexicographic
	offs    []int64       // offs[c] == chains[c].off, extracted for binary search
	total   int64         // saturating sum of chain counts
	exact   *big.Int      // never-saturated total, for --keyspace
}

// newPrinceGenerator builds the chain table for an element list and a
// (minLen..maxLen, maxElems) shape. It refuses — rather than truncating or
// guessing — on an oversized element list or an unenumerable chain count.
func newPrinceGenerator(elems []string, minLen, maxLen, maxElems int) (*princeGenerator, error) {
	if minLen < 1 {
		return nil, fmt.Errorf("prince mode: -n (min length) must be at least 1, got %d", minLen)
	}
	if maxLen < minLen {
		return nil, fmt.Errorf("prince mode: -x (max length %d) must be at least -n (min length %d)", maxLen, minLen)
	}
	if maxElems < 1 {
		return nil, fmt.Errorf("prince mode: --prince-elems must be at least 1, got %d", maxElems)
	}
	if maxElems > princeMaxElemsPerChain {
		return nil, fmt.Errorf("prince mode: --prince-elems %d exceeds the maximum of %d",
			maxElems, princeMaxElemsPerChain)
	}
	if len(elems) > princeMaxElements {
		return nil, fmt.Errorf("prince mode: element list has %d entries, more than the %d-element cap "+
			"(the whole list is held in memory) — filter or split the list; refusing rather than "+
			"truncating it, which would silently leave candidates untried",
			len(elems), princeMaxElements)
	}

	g := &princeGenerator{
		buckets: make([][]string, maxLen+1),
		exact:   big.NewInt(0),
	}
	// Bucket by RUNE length. Elements longer than maxLen can never appear in a
	// chain; empty elements would be zero-length parts, which would break the
	// composition invariant (every part is at least one rune).
	for _, e := range elems {
		n := utf8.RuneCountInString(e)
		if n < 1 || n > maxLen {
			continue
		}
		g.buckets[n] = append(g.buckets[n], e)
	}

	// avail is the ascending list of lengths that actually have elements.
	// Compositions are drawn only from these, so a sparse element list (say,
	// only 3- and 6-rune words) never pays for the lengths in between.
	var avail []int
	for L := 1; L <= maxLen; L++ {
		if len(g.buckets[L]) > 0 {
			avail = append(avail, L)
		}
	}
	if len(avail) == 0 {
		// No usable elements: an empty keyspace, not an error. candidate is
		// still installed (see princeLayout) so nothing can index a nil slice.
		return g, nil
	}
	minAvail := avail[0]

	var running int64
	cur := make([]int, 0, maxElems)
	overflowChains := false

	// emit appends the chain currently described by cur. count is the product
	// of the parts' bucket sizes, saturating (satMul) exactly as maskKeyspace
	// does: a saturated bound still enumerates only genuine candidates, so it
	// is an incomplete-but-correct sweep, never a wrong one.
	emit := func() {
		count := int64(1)
		ex := big.NewInt(1)
		for _, L := range cur {
			b := int64(len(g.buckets[L]))
			count = satMul(count, b)
			ex.Mul(ex, big.NewInt(b))
		}
		if count <= 0 {
			// Unreachable: every part is drawn from a non-empty bucket. Kept
			// as a hard guard because a zero-count chain in the list is the
			// one failure mode here that is silent rather than loud.
			return
		}
		parts := make([]int, len(cur))
		copy(parts, cur)
		g.chains = append(g.chains, princeChain{parts: parts, off: running, count: count})
		g.offs = append(g.offs, running)
		running = satAdd(running, count)
		g.exact.Add(g.exact, ex)
	}

	// build enumerates compositions of `remaining` into exactly `partsLeft`
	// parts drawn from avail, in ascending-first order — which is exactly
	// lexicographic order on the composition.
	var build func(remaining, partsLeft int)
	build = func(remaining, partsLeft int) {
		if overflowChains {
			return
		}
		if partsLeft == 1 {
			if remaining >= 1 && remaining <= maxLen && len(g.buckets[remaining]) > 0 {
				if len(g.chains) >= princeMaxChains {
					overflowChains = true
					return
				}
				cur = append(cur, remaining)
				emit()
				cur = cur[:len(cur)-1]
			}
			return
		}
		for _, L := range avail {
			// Every one of the partsLeft-1 remaining parts is at least
			// minAvail runes long, so once L passes this bound no longer
			// prefix can complete — and avail is ascending, so stop.
			if L > remaining-(partsLeft-1)*minAvail {
				break
			}
			cur = append(cur, L)
			build(remaining-L, partsLeft-1)
			cur = cur[:len(cur)-1]
			if overflowChains {
				return
			}
		}
	}

	// Chain order: N ascending (shortest candidates first — the practical
	// point of PRINCE), then k ascending, then lexicographic within (N, k).
	for N := minLen; N <= maxLen && !overflowChains; N++ {
		for k := 1; k <= maxElems && k <= N && !overflowChains; k++ {
			build(N, k)
		}
	}
	if overflowChains {
		return nil, fmt.Errorf("prince mode: the length range %d..%d with up to %d elements per chain "+
			"produces more than %d distinct length combinations to hold in memory — "+
			"narrow -n/-x or lower --prince-elems; refusing rather than enumerating a partial set, "+
			"which would silently leave candidates untried",
			minLen, maxLen, maxElems, princeMaxChains)
	}
	g.total = running
	return g, nil
}

// candidate maps a global index to its chain and decodes it. It is a pure
// function of i: no state is read or written across calls, so it is safe to
// call concurrently, out of order, and after a resume.
func (g *princeGenerator) candidate(i int64) string {
	if i < 0 || i >= g.total || len(g.chains) == 0 {
		return ""
	}
	// The last chain whose start offset is <= i. Offsets are strictly
	// increasing because no chain has count 0.
	c := sort.Search(len(g.offs), func(j int) bool { return g.offs[j] > i }) - 1
	if c < 0 {
		return ""
	}
	ch := g.chains[c]
	local := i - ch.off
	n := len(ch.parts)
	// Mixed-radix decode with the LAST part varying fastest, mirroring
	// maskIdxToStr and markovModel.decode. digits is allocated per call rather
	// than reused from the generator: a shared scratch buffer would make this
	// stateful and race under runLayout's concurrent workers.
	digits := make([]int, n)
	size := 0
	for p := n - 1; p >= 0; p-- {
		base := int64(len(g.buckets[ch.parts[p]]))
		digits[p] = int(local % base)
		local /= base
		size += ch.parts[p]
	}
	var b strings.Builder
	b.Grow(size)
	for p := 0; p < n; p++ {
		b.WriteString(g.buckets[ch.parts[p]][digits[p]])
	}
	return b.String()
}

// princeLayout builds the resumable keyspace layout for a PRINCE run and, as a
// second return, the exact (never-saturated) candidate count for --keyspace.
//
// NOTE ON THE DESIGN DOC: the design sketches this as
// `princeLayout(...) *keyspaceLayout` with no error. That signature cannot
// express the doc's OWN hazards — refusing an oversized element list and an
// unknowable total — so the error is returned instead of being swallowed. The
// exact total is returned alongside for the same reason --keyspace exists:
// printing a saturated number a script would divide into --skip/--limit slices
// is the failure mode this codebase already refuses (see printKeyspace).
func princeLayout(elems []string, minLen, maxLen, maxElems int) (*keyspaceLayout, *big.Int, error) {
	g, err := newPrinceGenerator(elems, minLen, maxLen, maxElems)
	if err != nil {
		return nil, nil, err
	}
	// gen is set unconditionally, even for an empty keyspace: keyspaceLayout
	// falls back to segment decoding when gen is nil, and PRINCE has no
	// segments, so a nil gen would index a nil slice.
	return &keyspaceLayout{total: g.total, gen: g.candidate}, g.exact, nil
}

// princeElemsFor resolves --prince-elems from the crack context, falling back
// to the default when unset (or when there is no context at all).
func princeElemsFor(cc *crackCtx) int {
	if cc == nil || cc.princeElems < 1 {
		return princeDefaultElems
	}
	return cc.princeElems
}
