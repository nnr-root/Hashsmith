package main

import "testing"

// Core-only benchmarks, to be read ALONGSIDE the *Group benchmarks in the same
// invocation on the same runner.
//
// The *Group benchmarks call fillFromSegment then the vector core, which is
// what production does. These fill the batch ONCE outside the timer and time
// only the core. The scalar baselines hash a pre-built buffer and pay no
// generation cost at all, so comparing *Group against scalar is structurally
// unfair to the vector path — the difference between Core and Group here is
// exactly the generation cost that comparison silently charges to the core.
//
// This trio exists because a spike measured the AVX2 core alone at 12.3x
// crypto/md5 on one CPU, while the production-shaped Group benchmark measured
// 2.39x on another. Two variables moved at once (generation cost, and CPU
// generation), and separating them needs all three numbers from one run.

func benchFilledBatch(b *testing.B, shape vecShape) *transposedBatch {
	b.Helper()
	sets := make([][]byte, 8)
	for i := range sets {
		sets[i] = []byte("abcdefghijklmnopqrstuvwxyz")
	}
	tb := newTransposedBatch(shape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		b.Fatalf("reset: %v", err)
	}
	tb.fillFromSegment(sets, 0)
	return tb
}

// BenchmarkMD5AVX2Core times the AVX2 core with no candidate generation.
// On non-amd64 this measures the portable fallback, not the vector core.
func BenchmarkMD5AVX2Core(b *testing.B) {
	tb := benchFilledBatch(b, avx2Shape)
	out := make([][16]byte, avx2Shape.group())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		md5GroupAVX2(tb, out)
	}
	b.ReportMetric(float64(b.N*avx2Shape.group())/b.Elapsed().Seconds()/1e6, "MH/s")
}

// BenchmarkMD5NeonCore times the NEON core with no candidate generation.
// On non-arm64 this measures the portable fallback, not the vector core.
func BenchmarkMD5NeonCore(b *testing.B) {
	tb := benchFilledBatch(b, neonShape)
	out := make([][16]byte, neonShape.group())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		md5Group(tb, out)
	}
	b.ReportMetric(float64(b.N*neonShape.group())/b.Elapsed().Seconds()/1e6, "MH/s")
}
