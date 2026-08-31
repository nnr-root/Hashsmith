//go:build !arm64

package main

import "golang.org/x/crypto/md4"

// md4Group is the portable fallback: no vector core on this architecture, so
// hash each lane individually. It decodes each lane's true message straight
// out of the transposed words — reading the bit length from word 14 and the
// message bytes from words 0..13 — rather than calling tb.candidateAt, which
// assumes every lane holds a tb.length-byte candidate. That assumption is
// false for a lane fillFromSegment cleaned (an unused padding lane on a
// partial final group): the stored block there is the empty message
// (word 0 = 0x80, bit length 0), not tb.length bytes of "\x80\x00...". By
// decoding from the words themselves, this hashes exactly what the NEON core
// hashes for every lane, including cleaned ones, which is what makes this
// function usable as the test oracle md4neon_test.go compares against — a
// divergence between what this reads and what the NEON assembly reads is a
// real bug, not a fixture mismatch. See md5neon_generic.go for the MD5
// sibling this mirrors.
func md4Group(tb *transposedBatch, out *[neonGroup][16]byte) {
	for i := 0; i < neonGroup; i++ {
		bitLen := tb.words[wordIndex(i, 14)]
		byteLen := int(bitLen / 8)
		var buf [56]byte
		for w := 0; w < 14; w++ {
			word := tb.words[wordIndex(i, w)]
			buf[w*4+0] = byte(word)
			buf[w*4+1] = byte(word >> 8)
			buf[w*4+2] = byte(word >> 16)
			buf[w*4+3] = byte(word >> 24)
		}
		h := md4.New()
		h.Write(buf[:byteLen])
		copy(out[i][:], h.Sum(nil))
	}
}

// md4GroupAccelerated reports whether this build has the vector core, for
// reporting purposes (e.g. benchmark/throughput output).
func md4GroupAccelerated() bool { return false }
