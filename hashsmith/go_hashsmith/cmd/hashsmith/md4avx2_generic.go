//go:build !amd64

package main

import "golang.org/x/crypto/md4"

// md4AVX2IsAssembly reports, as a build-time constant, that this build
// linked the scalar fallback below rather than the real AVX2 assembly core.
// md4avx2_test.go's coverage guard reads it so that CI's amd64 lane fails
// loudly if it ever stops exercising the assembly — see
// TestMD4AVX2CoreWasActuallyExercised.
const md4AVX2IsAssembly = false

// md4GroupAVX2 is the portable fallback for non-amd64 architectures: no
// AVX2 core here, so hash each lane individually. It decodes each lane's
// true message straight out of the transposed words — reading the bit
// length from word 14 and the message bytes from words 0..13 — rather than
// calling tb.candidateAt, which assumes every lane holds a tb.length-byte
// candidate. That assumption is false for a lane fillFromSegment cleaned
// (an unused padding lane on a partial final group): the stored block there
// is the empty message (word 0 = 0x80, bit length 0), not tb.length bytes
// of "\x80\x00...". By decoding from the words themselves, this hashes
// exactly what the AVX2 core hashes for every lane, including cleaned ones,
// which is what makes this function usable as the test oracle
// md4avx2_test.go compares against — a divergence between what this reads
// and what the AVX2 assembly reads is a real bug, not a fixture mismatch.
// Mirrors md5avx2_generic.go and md4neon_generic.go.
func md4GroupAVX2(tb *transposedBatch, out [][16]byte) {
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
		h := md4.New()
		h.Write(buf[:byteLen])
		copy(out[i][:], h.Sum(nil))
	}
}
