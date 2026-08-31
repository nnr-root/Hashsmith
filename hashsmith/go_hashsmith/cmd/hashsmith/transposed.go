package main

import (
	"encoding/binary"
	"errors"
)

// Candidate generation directly in the layout the pipelined NEON core reads.
//
// Task 5b measured the core at 5.58x crypto/md5, but only 2.16x when
// candidates were packed as bytes and transposed afterwards. Since a mask or
// brute-force keyspace GENERATES its candidates, the transpose is avoidable
// entirely: write each candidate's words straight into the interleaved slot
// the core will read them from.

const (
	neonChains       = 5                      // independent 4-way chains in flight
	neonLanes        = 4                      // 32-bit lanes per 128-bit vector
	neonGroup        = neonChains * neonLanes // candidates hashed per core call
	transposedMaxLen = 55                     // one MD5 block after padding
)

// errTransposedLen is returned by reset when the candidate length does not
// fit in a single 64-byte MD5 block after padding.
var errTransposedLen = errors.New("candidate length does not fit one MD5 block")

// transposedFixedLenOK reports whether a candidate length fits one block.
func transposedFixedLenOK(n int) bool { return n >= 0 && n <= transposedMaxLen }

// transposedBatch holds neonGroup candidates of a FIXED length, already padded
// and interleaved. words is [neonChains][16][neonLanes]uint32 flattened: the
// word for chain c, message-word w, lane l is at c*64 + w*4 + l.
type transposedBatch struct {
	words  []uint32
	length int
	n      int
}

func newTransposedBatch() *transposedBatch {
	return &transposedBatch{words: make([]uint32, neonChains*16*neonLanes)}
}

// wordIndex returns the slot for message-word w of candidate i.
func wordIndex(i, w int) int {
	return (i/neonLanes)*64 + w*4 + (i % neonLanes)
}

// reset prepares the batch for candidates of candidateLen bytes, writing a
// valid padded block into EVERY lane. Unused lanes therefore hash an empty
// message rather than stale bytes from the previous group, which could
// otherwise produce a spurious hit.
func (tb *transposedBatch) reset(candidateLen int) error {
	if !transposedFixedLenOK(candidateLen) {
		return errTransposedLen
	}
	tb.length = candidateLen
	tb.n = 0
	for i := range tb.words {
		tb.words[i] = 0
	}
	// Every lane starts as a valid zero-length block: 0x80 at byte 0.
	for i := 0; i < neonGroup; i++ {
		tb.words[wordIndex(i, 0)] = 0x80
	}
	return nil
}

// fillFromSegment writes up to neonGroup candidates starting at index `from`
// of the mixed-radix segment `sets`, returning how many it wrote. It allocates
// nothing: candidate bytes are decoded into a stack buffer and packed straight
// into their interleaved slots.
func (tb *transposedBatch) fillFromSegment(sets [][]byte, from int64) int {
	total := maskKeyspace(sets)
	n := 0
	var buf [transposedMaxLen]byte
	L := len(sets)
	bitLen := uint32(L) * 8
	for n < neonGroup {
		idx := from + int64(n)
		if idx >= total {
			break
		}
		maskIdxInto(buf[:L], idx, sets)
		// Pack L bytes plus the 0x80 terminator into words 0..(L/4).
		full := L / 4
		for w := 0; w < full; w++ {
			tb.words[wordIndex(n, w)] = binary.LittleEndian.Uint32(buf[w*4:])
		}
		// The partial final word carries the remaining bytes then 0x80.
		rem := L % 4
		var tail uint32
		for b := 0; b < rem; b++ {
			tail |= uint32(buf[full*4+b]) << (8 * b)
		}
		tail |= 0x80 << (8 * rem)
		tb.words[wordIndex(n, full)] = tail
		tb.words[wordIndex(n, 14)] = bitLen
		n++
	}
	tb.n = n
	return n
}

// candidateAt reconstructs candidate i's bytes, for reporting a hit. Not on the
// hot path, so clarity beats speed.
func (tb *transposedBatch) candidateAt(i int) []byte {
	out := make([]byte, tb.length)
	for b := 0; b < tb.length; b++ {
		w := tb.words[wordIndex(i, b/4)]
		out[b] = byte(w >> (8 * (b % 4)))
	}
	return out
}
