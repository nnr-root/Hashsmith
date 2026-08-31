//go:build !arm64

package main

import "crypto/md5"

// md5Group is the portable fallback: no vector core on this architecture, so
// hash each lane individually. Output is identical to the NEON path by
// construction — this is also the oracle md5neon_test.go compares against.
func md5Group(tb *transposedBatch, out *[neonGroup][16]byte) {
	for i := 0; i < neonGroup; i++ {
		out[i] = md5.Sum(tb.candidateAt(i))
	}
}

// md5GroupAccelerated reports whether this build has the vector core, for
// reporting purposes (e.g. benchmark/throughput output).
func md5GroupAccelerated() bool { return false }
