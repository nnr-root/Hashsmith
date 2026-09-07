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

// bestOfN runs a benchmark function n times with testing.Benchmark and
// returns the minimum ns/op observed. Machine load and scheduler noise only
// ever ADD time to a wall-clock sample, so the minimum across repeated
// samples is the closest available estimate of the true, unloaded cost —
// see docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md's record of
// this ratchet flaking under load average 30 on a single-sample measurement.
func bestOfN(n int, f func(b *testing.B)) int64 {
	best := int64(-1)
	for i := 0; i < n; i++ {
		r := testing.Benchmark(f)
		ns := r.NsPerOp()
		if best < 0 || ns < best {
			best = ns
		}
	}
	return best
}

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

	laneNs := bestOfN(5, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h.Run(pw, out)
		}
	})
	perCandidate := float64(laneNs) / float64(Lanes)

	refNs := bestOfN(5, func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bcrypt.CompareHashAndPassword(crypt, []byte("candidate"))
		}
	})

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
	if got < bcryptSpeedupFloor {
		t.Errorf("speedup %.2fx is below the %.2fx floor", got, bcryptSpeedupFloor)
	}
}
