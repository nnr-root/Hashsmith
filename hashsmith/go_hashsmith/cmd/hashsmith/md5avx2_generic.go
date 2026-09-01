//go:build !amd64

package main

import "crypto/md5"

// avx2Shape is the shape of the AVX2 core: 3 independent 8-lane chains, 24
// candidates per call. Defined identically (build-tag-gated) in both
// md5avx2_amd64.go and md5avx2_generic.go so it is visible regardless of
// GOARCH, matching neonShape's role for the NEON core. It stays 3x8 here
// too (rather than collapsing to some arch-neutral shape) so a caller that
// picks a batch shape at init time sees the same group size on every
// platform, even though this file's md5GroupAVX2 never actually dispatches
// to real AVX2 instructions.
var avx2Shape = vecShape{chains: 3, lanes: 8}

// hasAVX2 reports whether this CPU supports AVX2. On non-amd64
// architectures there is no AVX2 to have.
func hasAVX2() bool { return false }

// md5GroupAVX2 is the portable fallback for non-amd64 architectures: no
// AVX2 core here, so hash each lane individually. It decodes each lane's
// true message straight out of the transposed words — reading the bit
// length from word 14 and the message bytes from words 0..13 — rather than
// calling tb.candidateAt, which assumes every lane holds a tb.length-byte
// candidate. That assumption is false for a lane fillFromSegment cleaned
// (an unused padding lane on a partial final group): the stored block
// there is the empty message (word 0 = 0x80, bit length 0), not tb.length
// bytes of "\x80\x00...". By decoding from the words themselves, this
// hashes exactly what the AVX2 core hashes for every lane, including
// cleaned ones, which is what makes this function usable as the test
// oracle md5avx2_test.go compares against (mirrors md5neon_generic.go's
// md5Group).
func md5GroupAVX2(tb *transposedBatch, out [][16]byte) {
	for i := 0; i < tb.shape.group(); i++ {
		bitLen := tb.words[tb.wordIndex(i, 14)]
		byteLen := int(bitLen / 8)
		var buf [56]byte
		for w := 0; w < 14; w++ {
			word := tb.words[tb.wordIndex(i, w)]
			buf[w*4+0] = byte(word)
			buf[w*4+1] = byte(word >> 8)
			buf[w*4+2] = byte(word >> 16)
			buf[w*4+3] = byte(word >> 24)
		}
		out[i] = md5.Sum(buf[:byteLen])
	}
}
