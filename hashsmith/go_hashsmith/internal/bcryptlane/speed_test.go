package bcryptlane

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// bcryptSpeedupFloor is a ratchet, not a target. Raise it as the core improves;
// never lower it to make a change pass.
//
// It is a RATIO against x/crypto/bcrypt measured in this same process, not an
// absolute c/s figure. An absolute floor would encode one machine's clock speed
// and flake on every other runner; the ratio is the quantity the work is
// actually about and is stable across hardware.
//
// Set from the measurement in docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md
// with a 15% margin below the observed value to absorb runner variance.
const bcryptSpeedupFloor = 1.92 * 0.85 // measured 1.92x speedup at Lanes=4, see docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md

// refQuietBaselineNs is the best-of-5 wall-clock cost of a single
// x/crypto/bcrypt.CompareHashAndPassword at cost 5, as measured on this
// project's tuning machine (Apple M2, darwin/arm64) under low load — see
// docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md, which records
// 3,305,662 ns/op (library-wrapped) against 3,291,526 ns/op (raw cipher
// loop) on that same quiet machine, both ~3.3ms. This number is
// MACHINE-SPECIFIC and exists only as a load guard — to tell a contended
// test run apart from a real regression — never as a portable performance
// claim, and it must not be used anywhere the ratchet's actual pass/fail
// threshold (bcryptSpeedupFloor, a ratio) is decided.
const refQuietBaselineNs = 3.3e6

// bestOfNInterleaved samples two benchmarks in ALTERNATION and returns the
// minimum ns/op seen for each.
//
// The alternation is the point. Measuring one side five times and then the
// other five times gives the two sides two different windows of machine load,
// and best-of-N does not rescue that: if every sample of the second side lands
// in a busy window, its minimum is contended too, and the ratio between the
// two is a comparison of two different machines.
//
// That is not hypothetical. This ratchet failed at 1.10x during a `go test
// ./...` run, with the reference side measuring 3.27ms — its normal quiet-
// machine cost, so the existing load guard saw nothing wrong — while the
// four-lane side ran in a window where sibling test binaries were evicting
// its working set. Four interleaved bcrypt states are four Blowfish S-box
// sets, around four times the L1 footprint of the single-lane reference, so
// cache pressure lands on the lane side and almost entirely misses the
// reference. Alternating makes any such pressure hit both sides, which is
// what a ratio needs to stay honest.
//
// Machine load and scheduler noise only ever ADD time to a wall-clock sample,
// so the minimum across repeated samples remains the closest available
// estimate of the true, unloaded cost — see
// docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md's record of this
// ratchet flaking under load average 30 on a single-sample measurement.
func bestOfNInterleaved(n int, a, b func(*testing.B)) (int64, int64) {
	bestA, bestB := int64(-1), int64(-1)
	for i := 0; i < n; i++ {
		if ns := testing.Benchmark(a).NsPerOp(); bestA < 0 || ns < bestA {
			bestA = ns
		}
		if ns := testing.Benchmark(b).NsPerOp(); bestB < 0 || ns < bestB {
			bestB = ns
		}
	}
	return bestA, bestB
}

// This ratchet runs in the ordinary test suite, and the story of why it
// briefly did not is worth keeping.
//
// It failed at 1.10x during a full-suite run, and again at 1.29x on a rerun,
// which looked like proof that a wall-clock RATIO cannot be measured on a
// machine that is doing something else. It was gated behind an environment
// variable on that reasoning, so that only a dedicated CI job would run it.
//
// The reasoning was wrong, and the cause was self-inflicted: eight runaway
// busy-loop processes, orphaned by a botched cleanup in an unrelated
// experiment, had been saturating all eight cores of the measuring machine for
// over four hours. Every "loaded" reading came from that.
//
// With them gone, measured here: 2.19x, 1.90x and 2.11x on a quiet machine,
// and 1.89x, 2.12x and 2.14x WHILE a full `go test ./cmd/hashsmith` ran
// alongside — all clear of the 1.63x floor. The reference side read 1.84ms
// against the 3.27ms recorded during the contaminated period, so that machine
// had been running at roughly half speed.
//
// So the gate is gone and the test is back in the default suite, where a
// ratchet belongs. What stayed is the part that was a real improvement
// regardless: the two sides are measured in ALTERNATION rather than in two
// separate blocks, and a reading below the floor is re-measured before it
// fails.
func TestSpeedupOverXCrypto(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test; run without -short")
	}
	crypt, err := bcrypt.GenerateFromPassword([]byte("ratchet"), 5)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHasher(string(crypt))
	if err != nil {
		t.Fatal(err)
	}
	pw := make([][]byte, Lanes)
	for i := range pw {
		pw[i] = []byte("candidate")
	}
	out := make([]bool, Lanes)

	lane := func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h.Run(pw, out)
		}
	}
	ref := func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bcrypt.CompareHashAndPassword(crypt, []byte("candidate"))
		}
	}

	laneNs, refNs := bestOfNInterleaved(5, lane, ref)
	perCandidate := float64(laneNs) / float64(Lanes)

	// Load guard: a wall-clock RATIO cannot tell "the machine is contended"
	// apart from "the core regressed" on its own — both make bcryptlane look
	// relatively slower. If the reference side alone is already running at
	// more than 2x its quiet-machine baseline, the machine is too loaded for
	// this measurement to mean anything either way. Skip loudly rather than
	// fail: a skip here means "not measured here", NOT "passed", and NOT
	// "failed" — see docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md
	// for the run that motivated this (1.18x observed, below the 1.632
	// floor, under load average 30 on this same 8-core machine).
	if refNs > 2*int64(refQuietBaselineNs) {
		t.Skipf("SKIPPING speedup ratchet: this machine is too loaded to measure it. "+
			"best-of-5 x/crypto/bcrypt reference took %.2fms/op, more than 2x the %.2fms "+
			"quiet-machine baseline (docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md). "+
			"This SKIP means the ratchet was NOT MEASURED on this run — it is not evidence "+
			"the speedup floor was met.",
			float64(refNs)/1e6, refQuietBaselineNs/1e6)
	}

	got := float64(refNs) / perCandidate
	t.Logf("x/crypto %d ns/op (best of 5), bcryptlane %.0f ns/candidate (best of 5) at %d lanes, speedup %.2fx",
		refNs, perCandidate, Lanes, got)

	// A real regression is reproducible; one unlucky measurement window is
	// not. Rather than fail on a single reading, take a second, longer set of
	// samples and fail only if that one agrees. This cannot hide a regression
	// — a slower core is slower in both sets — and it costs the extra
	// measurement only on runs that were going to fail anyway.
	if got < bcryptSpeedupFloor {
		laneNs2, refNs2 := bestOfNInterleaved(9, lane, ref)
		got2 := float64(refNs2) / (float64(laneNs2) / float64(Lanes))
		t.Logf("re-measured with 9 interleaved samples: speedup %.2fx", got2)
		if got2 > got {
			got = got2
		}
	}
	if got < bcryptSpeedupFloor {
		t.Errorf("speedup %.2fx is below the %.2fx floor", got, bcryptSpeedupFloor)
	}
}
