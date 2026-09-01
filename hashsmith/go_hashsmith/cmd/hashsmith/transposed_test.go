package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// The transposed layout must describe exactly the same candidates, in the same
// order, that the scalar path produces — and must be recoverable from the
// packed words, which is how a hit is reported.
func TestTransposedRoundTripsCandidates(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de"), []byte("fg")} // 3*2*2 = 12
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n := tb.fillFromSegment(sets, 0, maskKeyspace(sets))
	if n != 12 {
		t.Fatalf("filled %d, want 12 (the whole segment)", n)
	}
	for i := 0; i < n; i++ {
		want := maskIdxToStr(int64(i), sets)
		if got := string(tb.candidateAt(i)); got != want {
			t.Errorf("candidate %d = %q, want %q", i, got, want)
		}
	}
}

// The packed words must be a correct MD5 block for each candidate: bytes
// little-endian in words 0..13, 0x80 terminator, bit length in word 14.
func TestTransposedBlockIsValidMD5Padding(t *testing.T) {
	sets := [][]byte{[]byte("ab"), []byte("cd"), []byte("ef"), []byte("gh"), []byte("ij")}
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(5, encRaw); err != nil {
		t.Fatalf("reset: %v", err)
	}
	tb.fillFromSegment(sets, 0, maskKeyspace(sets))

	for i := 0; i < 8; i++ {
		cand := tb.candidateAt(i)
		// Rebuild the reference block the scalar way.
		var want [64]byte
		copy(want[:], cand)
		want[len(cand)] = 0x80
		binary.LittleEndian.PutUint64(want[56:], uint64(len(cand))*8)

		chain, lane := i/neonLanes, i%neonLanes
		var got [64]byte
		for w := 0; w < 16; w++ {
			binary.LittleEndian.PutUint32(got[w*4:], tb.words[chain*64+w*4+lane])
		}
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("candidate %d block mismatch:\n got %x\nwant %x", i, got, want)
		}
	}
}

// A partial final group must leave the unused lanes as valid, harmless blocks
// rather than stale data from the previous group — a stale lane could produce a
// spurious hit.
func TestTransposedPartialGroupIsClean(t *testing.T) {
	sets := [][]byte{[]byte("abc")} // 3 candidates, less than one 20-wide group
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(1, encRaw); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n := tb.fillFromSegment(sets, 0, maskKeyspace(sets))
	if n != 3 {
		t.Fatalf("filled %d, want 3", n)
	}
	// Lanes 3..19 are unused. They must be zero-length blocks, not garbage.
	for i := n; i < neonGroup; i++ {
		chain, lane := i/neonLanes, i%neonLanes
		w0 := tb.words[chain*64+0*4+lane]
		if w0 != 0x80 {
			t.Errorf("unused lane %d word0 = %#x, want 0x80 (empty padded block)", i, w0)
		}
	}
}

// Filling must not allocate in steady state — that is the whole point.
func TestTransposedFillDoesNotAllocate(t *testing.T) {
	sets := make([][]byte, 6)
	for i := range sets {
		sets[i] = []byte("abcdefghij")
	}
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		t.Fatalf("reset: %v", err)
	}
	total := maskKeyspace(sets)
	got := testing.AllocsPerRun(100, func() { tb.fillFromSegment(sets, 0, total) })
	if got != 0 {
		t.Errorf("fillFromSegment allocated %v times per run, want 0", got)
	}
}

// A batch reused across groups must not leak the previous group's candidates
// into lanes the new fill does not reach. Those lanes are hashed by the vector
// core, so a stale lane can be reported as a hit for a candidate that was
// never tried.
func TestTransposedReuseClearsStaleLanes(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de"), []byte("fg")} // 12 candidates
	total := maskKeyspace(sets)
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		t.Fatal(err)
	}
	// First fill: as many as the segment provides.
	first := tb.fillFromSegment(sets, 0, total)
	if first == 0 {
		t.Fatal("first fill wrote nothing")
	}
	// Second fill near the end of the segment: fewer candidates, no reset.
	second := tb.fillFromSegment(sets, int64(total)-2, total)
	if second >= neonGroup {
		t.Fatalf("second fill wrote %d, expected a partial group", second)
	}
	for i := second; i < neonGroup; i++ {
		chain, lane := i/neonLanes, i%neonLanes
		if got := tb.words[chain*64+0*4+lane]; got != 0x80 {
			t.Errorf("lane %d word0 = %#x, want 0x80 (stale candidate left behind)", i, got)
		}
		if got := tb.words[chain*64+14*4+lane]; got != 0 {
			t.Errorf("lane %d word14 = %d, want 0 (stale bit length left behind)", i, got)
		}
	}
}

func TestTransposedFixedLenOK(t *testing.T) {
	for _, c := range []struct {
		n    int
		want bool
	}{{0, true}, {55, true}, {56, false}, {100, false}} {
		if got := transposedFixedLenOK(c.n, encRaw); got != c.want {
			t.Errorf("transposedFixedLenOK(%d) = %v, want %v", c.n, got, c.want)
		}
	}
}

// UTF-16LE mode must produce exactly the message the scalar NTLM path hashes.
// For ASCII that is byte, 0x00 per character — and the bit length doubles.
func TestTransposedUTF16LEBlockMatchesScalar(t *testing.T) {
	sets := [][]byte{[]byte("ab"), []byte("cd"), []byte("ef")}
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encUTF16LE); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n := tb.fillFromSegment(sets, 0, maskKeyspace(sets))
	if n == 0 {
		t.Fatal("filled nothing")
	}
	for i := 0; i < n; i++ {
		cand := tb.candidateAt(i)
		want := utf16le(string(cand)) // the scalar path's own encoder
		var wantBlock [64]byte
		copy(wantBlock[:], want)
		wantBlock[len(want)] = 0x80
		binary.LittleEndian.PutUint64(wantBlock[56:], uint64(len(want))*8)

		chain, lane := i/neonLanes, i%neonLanes
		var got [64]byte
		for w := 0; w < 16; w++ {
			binary.LittleEndian.PutUint32(got[w*4:], tb.words[chain*64+w*4+lane])
		}
		if !bytes.Equal(got[:], wantBlock[:]) {
			t.Fatalf("candidate %d (%q):\n got %x\nwant %x", i, cand, got, wantBlock)
		}
	}
}

// candidateAt must round-trip in BOTH modes: it reports the hit, so a wrong
// answer here means reporting a password that was never tried.
func TestTransposedCandidateAtRoundTripsBothModes(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de")}
	for _, enc := range []encodeMode{encRaw, encUTF16LE} {
		tb := newTransposedBatch(neonShape)
		if err := tb.reset(len(sets), enc); err != nil {
			t.Fatalf("enc %v: reset: %v", enc, err)
		}
		n := tb.fillFromSegment(sets, 0, maskKeyspace(sets))
		for i := 0; i < n; i++ {
			want := maskIdxToStr(int64(i), sets)
			if got := string(tb.candidateAt(i)); got != want {
				t.Errorf("enc %v candidate %d = %q, want %q", enc, i, got, want)
			}
		}
	}
}

// The length ceiling differs per mode: UTF-16LE doubles the message.
func TestTransposedFixedLenOKPerMode(t *testing.T) {
	cases := []struct {
		n    int
		enc  encodeMode
		want bool
	}{
		{55, encRaw, true}, {56, encRaw, false},
		{27, encUTF16LE, true}, {28, encUTF16LE, false},
	}
	for _, c := range cases {
		if got := transposedFixedLenOK(c.n, c.enc); got != c.want {
			t.Errorf("transposedFixedLenOK(%d, %v) = %v, want %v", c.n, c.enc, got, c.want)
		}
	}
}

// The stale-lane invariant must hold in UTF-16LE mode too — same hazard,
// same consequence (a spurious hit on a candidate never tried).
func TestTransposedReuseClearsStaleLanesUTF16(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de"), []byte("fg")}
	total := maskKeyspace(sets)
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encUTF16LE); err != nil {
		t.Fatal(err)
	}
	if first := tb.fillFromSegment(sets, 0, total); first == 0 {
		t.Fatal("first fill wrote nothing")
	}
	second := tb.fillFromSegment(sets, total-2, total)
	if second >= neonGroup {
		t.Fatalf("second fill wrote %d, expected a partial group", second)
	}
	for i := second; i < neonGroup; i++ {
		chain, lane := i/neonLanes, i%neonLanes
		if got := tb.words[chain*64+0*4+lane]; got != 0x80 {
			t.Errorf("lane %d word0 = %#x, want 0x80", i, got)
		}
		if got := tb.words[chain*64+14*4+lane]; got != 0 {
			t.Errorf("lane %d word14 = %d, want 0", i, got)
		}
	}
}

// The generalised index formula must be a bijection for EVERY shape, not just
// NEON's 5x4: each (candidate, word) pair maps to a distinct slot, and the
// slots together cover the whole word array exactly once. A collision would
// make two candidates share message words — silently corrupting digests — and
// a gap would leave stale memory inside a message block.
//
// This test exists because the l=4 path is covered transitively by the rest of
// the suite (everything is built from neonShape), so a formula that happened to
// be right at 4 lanes and wrong at 8 would pass every other test in the package
// right up until an 8-lane core was wired in.
func TestTransposedShapeLayout(t *testing.T) {
	for _, sh := range []vecShape{
		{chains: 5, lanes: 4}, // NEON
		{chains: 3, lanes: 8}, // AVX2
		{chains: 2, lanes: 8},
		{chains: 1, lanes: 4},
	} {
		tb := newTransposedBatch(sh)
		wantLen := sh.chains * 16 * sh.lanes
		if len(tb.words) != wantLen {
			t.Fatalf("shape %+v: words len %d, want %d", sh, len(tb.words), wantLen)
		}
		seen := make(map[int]string, wantLen)
		for i := 0; i < sh.group(); i++ {
			for w := 0; w < 16; w++ {
				idx := tb.wordIndex(i, w)
				if idx < 0 || idx >= wantLen {
					t.Fatalf("shape %+v: wordIndex(%d,%d) = %d, out of range [0,%d)",
						sh, i, w, idx, wantLen)
				}
				if prev, dup := seen[idx]; dup {
					t.Fatalf("shape %+v: wordIndex(%d,%d) = %d collides with %s",
						sh, i, w, idx, prev)
				}
				seen[idx] = fmt.Sprintf("(cand %d, word %d)", i, w)
			}
		}
		if len(seen) != wantLen {
			t.Errorf("shape %+v: covered %d of %d slots — the mapping leaves gaps",
				sh, len(seen), wantLen)
		}

		// Bijectivity alone is not enough: a lane-major mapping such as
		// (i/l)*16*l + (i%l)*16 + w is ALSO a bijection over the same range,
		// and would pass the checks above while being wrong for the vector
		// cores, whose assembly reads word-major ("word g at byte offset
		// g*32" for 8 lanes). Pin the strides so the layout, not merely its
		// coverage, is what this test proves.
		for i := 0; i < sh.group(); i++ {
			for w := 0; w+1 < 16; w++ {
				if got := tb.wordIndex(i, w+1) - tb.wordIndex(i, w); got != sh.lanes {
					t.Fatalf("shape %+v: candidate %d word stride = %d, want %d "+
						"(layout is not word-major)", sh, i, got, sh.lanes)
				}
			}
			// Consecutive candidates inside one chain are adjacent lanes.
			if (i+1)%sh.lanes != 0 && i+1 < sh.group() {
				if got := tb.wordIndex(i+1, 0) - tb.wordIndex(i, 0); got != 1 {
					t.Fatalf("shape %+v: lane stride between candidates %d and %d = %d, want 1",
						sh, i, i+1, got)
				}
			}
		}
	}
}

// --- Odometer correctness -------------------------------------------------
//
// fillFromSegment used to decode every candidate from scratch with
// maskIdxInto (a division and modulo per character position — profiling
// showed this as generation's dominant cost). It now decodes `from` once and
// advances an odometer (increment the last position, carry left on
// overflow) for the rest of the group. The odometer MUST produce
// byte-identical candidates to maskIdxInto/maskIdxToStr for every index: an
// off-by-one in the carry silently skips or repeats candidates, and a
// skipped candidate is a password that is never tried but reported "not
// found". These tests are the oracle-comparison the doc comment on
// fillFromSegment references.

// fillExhaustiveGroupAligned walks the WHOLE keyspace of sets through
// fillFromSegment, one neonGroup-sized fill at a time (from = 0, group,
// 2*group, …), and checks every candidate it writes against
// maskIdxToStr(idx, sets) — the untouched, division-based oracle.
func fillExhaustiveGroupAligned(t *testing.T, name string, sets [][]byte) {
	t.Helper()
	total := maskKeyspace(sets)
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		t.Fatalf("%s: reset: %v", name, err)
	}
	var checked int64
	for from := int64(0); from < total; from += int64(neonShape.group()) {
		n := tb.fillFromSegment(sets, from, total)
		if n == 0 {
			t.Fatalf("%s: from=%d: fillFromSegment wrote 0 candidates before reaching total=%d", name, from, total)
		}
		for i := 0; i < n; i++ {
			idx := from + int64(i)
			want := maskIdxToStr(idx, sets)
			got := string(tb.candidateAt(i))
			if got != want {
				t.Fatalf("%s: index %d = %q, want %q (oracle)", name, idx, got, want)
			}
			checked++
		}
	}
	if checked != total {
		t.Fatalf("%s: checked %d candidates, want exactly total=%d", name, checked, total)
	}
}

// fillExhaustiveArbitraryFrom calls fillFromSegment from EVERY possible
// starting index in [0, total) — group-aligned or not, including the last
// partial group right up against total — and checks every candidate it
// writes against the oracle. fillFromSegment only has to be internally
// consistent within one call (it cannot assume continuity ACROSS calls), so
// this is the test that actually exercises "decode once at an arbitrary
// `from`, then odometer for the rest of this call's group" rather than only
// ever decoding at a multiple of the group size.
func fillExhaustiveArbitraryFrom(t *testing.T, name string, sets [][]byte) {
	t.Helper()
	total := maskKeyspace(sets)
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		t.Fatalf("%s: reset: %v", name, err)
	}
	for from := int64(0); from < total; from++ {
		n := tb.fillFromSegment(sets, from, total)
		wantN := int(total - from)
		if wantN > neonShape.group() {
			wantN = neonShape.group()
		}
		if n != wantN {
			t.Fatalf("%s: from=%d: fillFromSegment wrote %d, want %d", name, from, n, wantN)
		}
		for i := 0; i < n; i++ {
			idx := from + int64(i)
			want := maskIdxToStr(idx, sets)
			got := string(tb.candidateAt(i))
			if got != want {
				t.Fatalf("%s: from=%d index %d = %q, want %q (oracle)", name, from, idx, got, want)
			}
		}
	}
}

// TestFillFromSegmentMatchesMaskIdxInto is the exhaustive correctness proof
// for the odometer, across several segment shapes chosen to defeat a
// uniform-radix bug (which would pass with same-size sets at every
// position): uniform sets, sets whose sizes differ per position (a
// uniform-radix carry bug survives uniform tests), a single position, and a
// maximum-length (55-position) segment. Every shape's ENTIRE keyspace is
// enumerated through fillFromSegment, both group-aligned and from every
// arbitrary starting index, and compared against maskIdxToStr at the same
// index.
func TestFillFromSegmentMatchesMaskIdxInto(t *testing.T) {
	byteSet := func(n int) []byte {
		s := make([]byte, n)
		for i := range s {
			s[i] = byte('A' + i)
		}
		return s
	}

	shapes := map[string][][]byte{
		// Uniform: every position the same size (4^3 = 64).
		"uniform": {byteSet(4), byteSet(4), byteSet(4)},
		// Mixed sizes per position (3*1*7*2 = 42) — the case a uniform-radix
		// carry bug would NOT be caught by.
		"mixed-size": {byteSet(3), byteSet(1), byteSet(7), byteSet(2)},
		// Single position.
		"single-position": {byteSet(10)},
		// Maximum length (one full block, 55 positions): singleton at every
		// position except the last two, which are small and variable so the
		// whole keyspace (3*4 = 12) stays enumerable while still exercising
		// a carry across a long run of positions.
		"max-length": func() [][]byte {
			sets := make([][]byte, transposedMaxLen)
			for i := range sets {
				sets[i] = []byte{'x'}
			}
			sets[transposedMaxLen-2] = byteSet(3)
			sets[transposedMaxLen-1] = byteSet(4)
			return sets
		}(),
	}

	for name, sets := range shapes {
		t.Run(name+"/group-aligned", func(t *testing.T) {
			fillExhaustiveGroupAligned(t, name, sets)
		})
		t.Run(name+"/arbitrary-from", func(t *testing.T) {
			fillExhaustiveArbitraryFrom(t, name, sets)
		})
	}
}

// TestFillFromSegmentSingleCallHasNoCrossCallState confirms fillFromSegment
// does not (and must not) assume continuity across calls: two calls with
// the SAME `from` on freshly-reset batches must agree, regardless of what
// other calls happened on the batch in between (a stateful odometer cached
// on tb between calls, rather than re-decoded at each call's `from`, would
// break this the moment a caller seeks backwards or skips forward — exactly
// what chunk boundaries and --skip/--limit do).
func TestFillFromSegmentSingleCallHasNoCrossCallState(t *testing.T) {
	sets := [][]byte{[]byte("ABC"), []byte("X"), []byte("0123456"), []byte("ab")} // 42
	total := maskKeyspace(sets)

	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		t.Fatal(err)
	}
	// Walk forward, then jump backward, then forward again non-monotonically —
	// mimicking multiple workers claiming out-of-order chunks.
	order := []int64{0, 20, 5, total - 3, 10, 1}
	for _, from := range order {
		n := tb.fillFromSegment(sets, from, total)
		for i := 0; i < n; i++ {
			idx := from + int64(i)
			want := maskIdxToStr(idx, sets)
			if got := string(tb.candidateAt(i)); got != want {
				t.Fatalf("from=%d index %d = %q, want %q", from, idx, got, want)
			}
		}
	}
}
