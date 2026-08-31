//go:build !arm64

package main

import "crypto/md5"

// md5Group is the portable fallback: no vector core on this architecture, so
// hash each lane individually. It decodes each lane's true message straight
// out of the transposed words — reading the bit length from word 14 and the
// message bytes from words 0..13 — rather than calling tb.candidateAt, which
// assumes every lane holds a tb.length-byte candidate. That assumption is
// false for a lane fillFromSegment cleaned (an unused padding lane on a
// partial final group): the stored block there is the empty message
// (word 0 = 0x80, bit length 0), not tb.length bytes of "\x80\x00...". By
// decoding from the words themselves, this hashes exactly what the NEON core
// hashes for every lane, including cleaned ones, which is what makes this
// function usable as the test oracle md5neon_test.go compares against — a
// divergence between what this reads and what the NEON assembly reads is a
// real bug, not a fixture mismatch.
func md5Group(tb *transposedBatch, out [][16]byte) {
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

// md5GroupAccelerated reports whether this build has the vector core, for
// reporting purposes (e.g. benchmark/throughput output).
func md5GroupAccelerated() bool { return false }
