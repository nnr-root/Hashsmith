package smith

import (
	"math/rand"
	"testing"
)

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

// The three pairs below isolate WHERE time goes inside one PBKDF2 hot-loop
// iteration, to find out whether a disappointing end-to-end result (see
// the other benchmarks in this file) comes from the AVX2 compression core
// itself or from the Go-side, per-lane, unbatched schedule expansion the
// design deliberately kept out of assembly (§4.2 of the design doc). Each
// pair does the SAME amount of real work two ways: N scalar calls (one per
// lane, matching what a real iteration does today) vs the batched AVX2
// call alone (schedule expansion excluded, already-built schedules
// reused) — the ratio between the two lines is the actual, measurable
// answer, not a guess.

func BenchmarkSHA256ScheduleExpansionScalarX8(b *testing.B) {
	block := randomBlock(rand.New(rand.NewSource(20)))
	var w [64]uint32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for lane := 0; lane < 8; lane++ {
			sha256ExpandSchedule(&block, &w)
		}
	}
}

func BenchmarkSHA256CompressAVX2GroupOnly(b *testing.B) {
	rng := rand.New(rand.NewSource(21))
	var states [8][8]uint32
	var schedules [64][8]uint32
	for lane := 0; lane < 8; lane++ {
		for w := 0; w < 8; w++ {
			states[w][lane] = sha256IV[w]
		}
		block := randomBlock(rng)
		var w [64]uint32
		sha256ExpandSchedule(&block, &w)
		for step := 0; step < 64; step++ {
			schedules[step][lane] = w[step]
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sha256Group8AVX2(&states, &schedules)
	}
}

func BenchmarkSHA1ScheduleExpansionScalarX16(b *testing.B) {
	block := randomBlock(rand.New(rand.NewSource(22)))
	var w [80]uint32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for lane := 0; lane < 16; lane++ {
			sha1ExpandSchedule(&block, &w)
		}
	}
}

func BenchmarkSHA1CompressAVX2GroupOnly(b *testing.B) {
	rng := rand.New(rand.NewSource(23))
	var s [5][16]uint32
	var schedules [80][16]uint32
	for lane := 0; lane < 16; lane++ {
		for w := 0; w < 5; w++ {
			s[w][lane] = sha1IV[w]
		}
		block := randomBlock(rng)
		var w [80]uint32
		sha1ExpandSchedule(&block, &w)
		for step := 0; step < 80; step++ {
			schedules[step][lane] = w[step]
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sha1Group16AVX2(&s, &schedules)
	}
}

func BenchmarkSHA512ScheduleExpansionScalarX4(b *testing.B) {
	block := randomBlock128(rand.New(rand.NewSource(24)))
	var w [80]uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for lane := 0; lane < 4; lane++ {
			sha512ExpandSchedule(&block, &w)
		}
	}
}

func BenchmarkSHA512CompressAVX2GroupOnly(b *testing.B) {
	rng := rand.New(rand.NewSource(25))
	var states [8][4]uint64
	var schedules [80][4]uint64
	for lane := 0; lane < 4; lane++ {
		for w := 0; w < 8; w++ {
			states[w][lane] = sha512IV[w]
		}
		block := randomBlock128(rng)
		var w [80]uint64
		sha512ExpandSchedule(&block, &w)
		for step := 0; step < 80; step++ {
			schedules[step][lane] = w[step]
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sha512Group4AVX2(&states, &schedules)
	}
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
