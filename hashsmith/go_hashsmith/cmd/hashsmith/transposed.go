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
	transposedMaxLen = 55                     // one block after padding, raw mode

	// transposedMaxLenUTF16LE is the candidate-length ceiling in encUTF16LE
	// mode: each candidate byte expands to 2 message bytes (b, 0x00), so the
	// message is 2x the candidate length and must still fit transposedMaxLen
	// after padding (2*27 = 54 <= 55).
	transposedMaxLenUTF16LE = 27
)

// vecShape describes a vector core's candidate layout: how many independent
// pipelined chains it runs and how many 32-bit lanes each vector holds. It is
// carried as data rather than baked into constants so cores of different
// widths can share one generation path and one runner — NEON is 5 chains of 4
// lanes, an AVX2 core is 3 chains of 8.
type vecShape struct {
	chains int
	lanes  int
}

// group is the number of candidates hashed per core call.
func (s vecShape) group() int { return s.chains * s.lanes }

// neonShape is the shape of the shipped arm64 NEON cores.
var neonShape = vecShape{chains: neonChains, lanes: neonLanes}

// encodeMode selects how fillFromSegment turns candidate bytes into the
// message bytes that get packed and hashed. Most formats hash the candidate
// bytes verbatim (encRaw); NTLM hashes UTF-16LE(candidate) instead, so its
// message bytes are not its candidate bytes.
type encodeMode int

const (
	encRaw     encodeMode = iota // message bytes = candidate bytes verbatim
	encUTF16LE                   // message bytes = candidate byte, 0x00 per char (ASCII only)
)

// errTransposedLen is returned by reset when the candidate length does not
// fit in a single 64-byte block after padding, for the given encoding mode.
var errTransposedLen = errors.New("candidate length does not fit one block")

// transposedFixedLenOK reports whether a candidate length fits one block
// once encoded under enc. UTF-16LE doubles the message, halving the ceiling.
func transposedFixedLenOK(n int, enc encodeMode) bool {
	if n < 0 {
		return false
	}
	if enc == encUTF16LE {
		return n <= transposedMaxLenUTF16LE
	}
	return n <= transposedMaxLen
}

// transposedBatch holds neonGroup candidates of a FIXED length, already padded
// and interleaved. words is [neonChains][16][neonLanes]uint32 flattened: the
// word for chain c, message-word w, lane l is at c*64 + w*4 + l.
type transposedBatch struct {
	words  []uint32
	shape  vecShape
	length int
	enc    encodeMode
	n      int
}

func newTransposedBatch(shape vecShape) *transposedBatch {
	return &transposedBatch{
		words: make([]uint32, shape.chains*16*shape.lanes),
		shape: shape,
	}
}

// wordBase returns the slot for message-word 0 of candidate i — the base
// that every word of that candidate is offset from by w*lanes. Factored out
// of wordIndex so a caller writing every word of one candidate (the common
// case, e.g. fillFromSegment) can compute the i/l, i%l division once per
// candidate instead of once per word.
func (tb *transposedBatch) wordBase(i int) int {
	l := tb.shape.lanes
	return (i/l)*(16*l) + (i % l)
}

// wordIndex returns the slot for message-word w of candidate i, for this
// batch's shape: chain i/lanes holds 16 words of `lanes` uint32 each, so a
// chain strides 16*lanes and a message word strides `lanes`.
func (tb *transposedBatch) wordIndex(i, w int) int {
	return tb.wordBase(i) + w*tb.shape.lanes
}

// reset prepares the batch for candidates of candidateLen bytes encoded under
// enc, writing a valid padded block into EVERY lane. This guarantee holds
// only for the fill that immediately follows reset: on a batch reused across
// groups (the intended "reset once, fill repeatedly" calling convention), it
// is fillFromSegment's job to keep unused lanes clean on every partial group
// — see the comment there. Do not assume the reset-time guarantee persists.
func (tb *transposedBatch) reset(candidateLen int, enc encodeMode) error {
	if !transposedFixedLenOK(candidateLen, enc) {
		return errTransposedLen
	}
	tb.length = candidateLen
	tb.enc = enc
	tb.n = 0
	for i := range tb.words {
		tb.words[i] = 0
	}
	// Every lane starts as a valid zero-length block: 0x80 at byte 0.
	for i := 0; i < tb.shape.group(); i++ {
		tb.words[tb.wordIndex(i, 0)] = 0x80
	}
	return nil
}

// fillFromSegment writes up to neonGroup candidates starting at index `from`
// of the mixed-radix segment `sets`, whose total keyspace is `total`
// (== maskKeyspace(sets); the caller hoists this since it is invariant for a
// segment and would otherwise be recomputed on every group-sized fill).
// Returns how many candidates it wrote. It allocates nothing: candidate
// bytes are decoded into a stack buffer and packed straight into their
// interleaved slots.
//
// Candidates for consecutive indices are generated with an odometer rather
// than a full mixed-radix decode per index: maskIdxInto (mask.go) is a
// division and modulo per character position, and profiling showed it as
// the dominant cost of generation. `from` is decoded once, in full, exactly
// as maskIdxInto would; every subsequent candidate in the group is produced
// by incrementing the last position's digit and carrying left on overflow —
// standard odometer arithmetic, mathematically identical to decoding
// from+1, from+2, … independently, but with no division at all. This must
// stay byte-identical to maskIdxInto/maskIdxToStr for every index; see
// TestFillFromSegmentMatchesMaskIdxInto* in transposed_test.go, which
// enumerate whole segments through both paths and compare.
//
// fillFromSegment owns the "unused lanes are harmless" invariant across
// reuse, not just after reset: on a batch that is reset once and filled
// repeatedly (walking a segment group by group via `from`), a shrinking
// final fill would otherwise leave lanes n..neonGroup-1 holding the PREVIOUS
// call's candidate bytes and nonzero bit length — a valid-looking block the
// vector core will still hash, and a stale match would be reported as a hit
// for a candidate that was never tried. So whenever n < neonGroup, the
// leftover lanes are reset to the empty-message block (all words zero except
// word 0 = 0x80) before returning. This only runs on the final partial group
// of a segment; a full group pays nothing extra.
func (tb *transposedBatch) fillFromSegment(sets [][]byte, from int64, total int64) int {
	n := 0
	var msg [transposedMaxLen]byte // staged message bytes: encoded per tb.enc
	L := len(sets)
	msgLen := L
	bitLen := uint32(L) * 8
	if tb.enc == encUTF16LE {
		msgLen = L * 2
		bitLen = uint32(L) * 16
	}
	group := tb.shape.group()

	if from < total {
		var buf [transposedMaxLen]byte // buf[i] = sets[i][dig[i]], kept in sync with dig
		var dig [transposedMaxLen]int  // dig[i] = current digit (index into sets[i])

		// Full decode, once, at `from` — identical arithmetic to maskIdxInto.
		idx := from
		for i := L - 1; i >= 0; i-- {
			base := int64(len(sets[i]))
			d := int(idx % base)
			dig[i] = d
			buf[i] = sets[i][d]
			idx /= base
		}

		for {
			if tb.enc == encUTF16LE {
				// Each candidate byte b expands to b, 0x00 — byte-identical to
				// utf16le(s) for ASCII input (see hash.go's utf16le).
				for b := 0; b < L; b++ {
					msg[b*2] = buf[b]
					msg[b*2+1] = 0
				}
			} else {
				copy(msg[:L], buf[:L])
			}
			// Pack msgLen bytes plus the 0x80 terminator into words 0..(msgLen/4).
			full := msgLen / 4
			base := tb.wordBase(n)
			lanes := tb.shape.lanes
			for w := 0; w < full; w++ {
				tb.words[base+w*lanes] = binary.LittleEndian.Uint32(msg[w*4:])
			}
			// The partial final word carries the remaining bytes then 0x80.
			rem := msgLen % 4
			var tail uint32
			for b := 0; b < rem; b++ {
				tail |= uint32(msg[full*4+b]) << (8 * b)
			}
			tail |= 0x80 << (8 * rem)
			tb.words[base+full*lanes] = tail
			tb.words[base+14*lanes] = bitLen
			n++

			if n >= group || from+int64(n) >= total {
				break
			}
			// Advance the odometer by one: increment the last position,
			// carrying left on overflow. Mathematically the same as
			// decoding from+n independently, since dig[] together encodes
			// exactly the value (from+n-1) mod (product of the bases to
			// its right) at every position.
			for i := L - 1; i >= 0; i-- {
				dig[i]++
				if dig[i] < len(sets[i]) {
					buf[i] = sets[i][dig[i]]
					break
				}
				dig[i] = 0
				buf[i] = sets[i][0]
			}
		}
	}
	// Clean any leftover lanes from a previous, longer fill of this batch.
	for i := n; i < group; i++ {
		for w := 0; w < 16; w++ {
			tb.words[tb.wordIndex(i, w)] = 0
		}
		tb.words[tb.wordIndex(i, 0)] = 0x80
	}
	tb.n = n
	return n
}

// candidateAt reconstructs candidate i's bytes, for reporting a hit. Not on the
// hot path, so clarity beats speed. In encUTF16LE mode each candidate byte
// occupies every other message byte (b, 0x00), so the interleaved zero bytes
// are stripped back out.
func (tb *transposedBatch) candidateAt(i int) []byte {
	out := make([]byte, tb.length)
	step := 1
	if tb.enc == encUTF16LE {
		step = 2
	}
	for b := 0; b < tb.length; b++ {
		msgByte := b * step
		w := tb.words[tb.wordIndex(i, msgByte/4)]
		out[b] = byte(w >> (8 * (msgByte % 4)))
	}
	return out
}
