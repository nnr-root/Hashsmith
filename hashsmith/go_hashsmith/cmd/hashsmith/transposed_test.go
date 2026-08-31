package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The transposed layout must describe exactly the same candidates, in the same
// order, that the scalar path produces — and must be recoverable from the
// packed words, which is how a hit is reported.
func TestTransposedRoundTripsCandidates(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de"), []byte("fg")} // 3*2*2 = 12
	tb := newTransposedBatch()
	if err := tb.reset(len(sets)); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n := tb.fillFromSegment(sets, 0)
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
	tb := newTransposedBatch()
	if err := tb.reset(5); err != nil {
		t.Fatalf("reset: %v", err)
	}
	tb.fillFromSegment(sets, 0)

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
	tb := newTransposedBatch()
	if err := tb.reset(1); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n := tb.fillFromSegment(sets, 0)
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
	tb := newTransposedBatch()
	if err := tb.reset(len(sets)); err != nil {
		t.Fatalf("reset: %v", err)
	}
	got := testing.AllocsPerRun(100, func() { tb.fillFromSegment(sets, 0) })
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
	tb := newTransposedBatch()
	if err := tb.reset(len(sets)); err != nil {
		t.Fatal(err)
	}
	// First fill: as many as the segment provides.
	first := tb.fillFromSegment(sets, 0)
	if first == 0 {
		t.Fatal("first fill wrote nothing")
	}
	// Second fill near the end of the segment: fewer candidates, no reset.
	second := tb.fillFromSegment(sets, int64(maskKeyspace(sets))-2)
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
		if got := transposedFixedLenOK(c.n); got != c.want {
			t.Errorf("transposedFixedLenOK(%d) = %v, want %v", c.n, got, c.want)
		}
	}
}
