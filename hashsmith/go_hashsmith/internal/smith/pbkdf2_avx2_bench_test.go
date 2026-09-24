package smith

import "testing"

// Real-hardware throughput benchmarks for the PBKDF2 AVX2 multi-buffer
// project (docs/superpowers/specs/2026-09-24-pbkdf2-avx2-multibuffer-design.md).
//
// These CANNOT be trusted from a QEMU-emulated run (see that design's §7:
// "QEMU timing is meaningless") — every number in this file must come from
// CI's `bench` job (.github/workflows/ci.yml), the one place a trustworthy
// x86 number can come from at all on this project's Apple Silicon
// development machine. Local runs of this file are for compile-checking
// the benchmarks, not for reading the numbers they print.
//
// The comparison that matters is end-to-end, not the raw compression
// primitive in isolation: crypto/pbkdf2.Key run sequentially for a batch
// matching this core's own lane width, against one Run() call on the lane
// hasher covering that same batch, at the same iteration count. That is
// the actual choice a real crack loop makes between the scalar path and
// this one.
//
// GODEBUG=cpu.sha=off is the fair-comparison run: it forces Go's stdlib
// crypto/sha1/256/512 to their generic (non-hardware-accelerated) path
// regardless of whether the CI runner's actual silicon has SHA
// Extensions, reproducing this design's actual target hardware class
// (AVX2 present, SHA-NI absent) on any real machine — see
// internal/cpu/cpu_x86.go's own `{Name: "sha", Feature: &X86.HasSHA}`
// GODEBUG registration, confirmed against Go 1.26.3's source rather than
// assumed. The default run (SHA-NI left however the runner's silicon
// actually has it) is also worth reading: it is the "as shipped, whatever
// this specific machine happens to have" number, and the gap between the
// two runs on the same hardware is itself the size of SHA-NI's own
// advantage.
const pbkdf2BenchIterations = 5000

func BenchmarkPBKDF2Sha256StdlibSequential(b *testing.B) {
	salt := []byte("benchmark-salt-16b")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
			_ = pbkdf2Sha256Reference([]byte("benchmarkpassword"), salt, pbkdf2BenchIterations, 32)
		}
	}
	b.ReportMetric(float64(b.N*pbkdf2Sha256Lanes)/b.Elapsed().Seconds(), "candidates/s")
}

func BenchmarkPBKDF2Sha256LaneHasherAVX2(b *testing.B) {
	salt := []byte("benchmark-salt-16b")
	want := pbkdf2Sha256Reference([]byte("benchmarkpassword"), salt, pbkdf2BenchIterations, 32)
	target := pbkdf2Sha256Target(salt, pbkdf2BenchIterations, want)
	h := newPBKDF2Sha256LaneHasher(target)
	if h == nil {
		b.Fatal("newPBKDF2Sha256LaneHasher refused its own valid target")
	}
	pw := make([][]byte, pbkdf2Sha256Lanes)
	for i := range pw {
		pw[i] = []byte("benchmarkpassword")
	}
	out := make([]bool, pbkdf2Sha256Lanes)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Run(pw, out)
	}
	b.ReportMetric(float64(b.N*pbkdf2Sha256Lanes)/b.Elapsed().Seconds(), "candidates/s")
}

func BenchmarkPBKDF2Sha1StdlibSequential(b *testing.B) {
	salt := []byte("benchmark-salt-16b")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for lane := 0; lane < pbkdf2Sha1Lanes; lane++ {
			_ = pbkdf2Sha1Reference([]byte("benchmarkpassword"), salt, pbkdf2BenchIterations, 20)
		}
	}
	b.ReportMetric(float64(b.N*pbkdf2Sha1Lanes)/b.Elapsed().Seconds(), "candidates/s")
}

func BenchmarkPBKDF2Sha1LaneHasherAVX2(b *testing.B) {
	salt := []byte("benchmark-salt-16b")
	want := pbkdf2Sha1Reference([]byte("benchmarkpassword"), salt, pbkdf2BenchIterations, 20)
	target := pbkdf2Sha1Target(salt, pbkdf2BenchIterations, want)
	h := newPBKDF2Sha1LaneHasher(target)
	if h == nil {
		b.Fatal("newPBKDF2Sha1LaneHasher refused its own valid target")
	}
	pw := make([][]byte, pbkdf2Sha1Lanes)
	for i := range pw {
		pw[i] = []byte("benchmarkpassword")
	}
	out := make([]bool, pbkdf2Sha1Lanes)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Run(pw, out)
	}
	b.ReportMetric(float64(b.N*pbkdf2Sha1Lanes)/b.Elapsed().Seconds(), "candidates/s")
}

func BenchmarkPBKDF2Sha512StdlibSequential(b *testing.B) {
	salt := []byte("benchmark-salt-16b")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
			_ = pbkdf2Sha512Reference([]byte("benchmarkpassword"), salt, pbkdf2BenchIterations, 64)
		}
	}
	b.ReportMetric(float64(b.N*pbkdf2Sha512Lanes)/b.Elapsed().Seconds(), "candidates/s")
}

func BenchmarkPBKDF2Sha512LaneHasherAVX2(b *testing.B) {
	salt := []byte("benchmark-salt-16b")
	want := pbkdf2Sha512Reference([]byte("benchmarkpassword"), salt, pbkdf2BenchIterations, 64)
	target := pbkdf2Sha512Target(salt, pbkdf2BenchIterations, want)
	h := newPBKDF2Sha512LaneHasher(target)
	if h == nil {
		b.Fatal("newPBKDF2Sha512LaneHasher refused its own valid target")
	}
	pw := make([][]byte, pbkdf2Sha512Lanes)
	for i := range pw {
		pw[i] = []byte("benchmarkpassword")
	}
	out := make([]bool, pbkdf2Sha512Lanes)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Run(pw, out)
	}
	b.ReportMetric(float64(b.N*pbkdf2Sha512Lanes)/b.Elapsed().Seconds(), "candidates/s")
}
