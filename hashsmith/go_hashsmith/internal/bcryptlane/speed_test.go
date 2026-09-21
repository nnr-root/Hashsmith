package bcryptlane

import (
	"os"
	"slices"
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
// x/crypto/bcrypt.CompareHashAndPassword at cost 5 on this project's tuning
// machine (Apple M2, darwin/arm64) when nothing else is running: four
// consecutive quiet runs on 2026-09-21 read 3.259, 3.264, 3.265 and 3.254 ms,
// matching the 3,305,662 ns/op recorded in
// docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md.
//
// This number is MACHINE-SPECIFIC and exists only as a coarse guard against an
// outright crawling runner, never as a portable performance claim, and it must
// not be used anywhere the ratchet's actual pass/fail threshold
// (bcryptSpeedupFloor, a ratio) is decided. It is deliberately NOT the main
// contention guard — see quietSpreadCeiling for why it cannot be.
const refQuietBaselineNs = 3.3e6

// quietSpreadCeiling is the largest median/min ratio tolerated across the
// repeated samples of either side before the whole measurement is declared
// untrustworthy.
//
// This is the contention guard, and it replaces an earlier attempt to infer
// contention from the reference side's absolute cost. That attempt could not
// work, and the reason is worth recording: the reference side is ALMOST IMMUNE
// to the contention that breaks this ratchet. One bcrypt state is a single ~4KB
// Blowfish S-box set; four interleaved lanes are four of them, so a sibling test
// binary evicting cache lands on the lane side and largely misses the reference.
// Measured on 2026-09-21 during a `go test ./...` run that failed at 1.57x, the
// reference read 3.255 ms — indistinguishable from its 3.259 ms quiet reading —
// while the lane side read 2.075 ms/candidate against 1.527 ms quiet. A guard
// watching the reference sees a perfectly healthy machine in exactly the case it
// exists to catch.
//
// Sample dispersion does see it, because contention is bursty where a real
// regression is not. The statistic is median/min rather than max/min: the result
// is a best-of-N, so it survives one unlucky sample intact and is invalidated
// only when MOST samples are dirty, which is precisely what median/min measures.
// max/min was tried first and rejected — a single hiccup on an otherwise quiet
// machine pushed it to 1.047 against a 1.05 ceiling, while the same samples read
// 1.001 by median/min. Measured on this machine on 2026-09-21, over five
// interleaved samples per side:
//
//	              max/min                    median/min
//	quiet      lane 1.001 1.001 1.001     lane 1.0005 1.0006 1.0004
//	           ref  1.002 1.013 1.002     ref  1.0009 1.0007 1.0007
//	contended  lane 1.091 1.231 1.238     lane 1.0485 1.0947 1.1541
//	           ref  1.085 1.168 1.274     ref  1.0677 1.0636 1.2151
//
// The ceiling sits twenty times above the quiet cluster and below half the
// contended one. It is a self-consistency check on the measurement rather than a
// hardware constant, so unlike refQuietBaselineNs it carries to other runners
// unchanged.
const quietSpreadCeiling = 1.02

// obviousContentionSpread is a cost cut, not a second verdict. Both it and
// quietSpreadCeiling lead to the same outcome — a skip — so it changes only how
// long the test spends getting there.
//
// The re-measurement below exists to give a borderline reading a second chance
// at a clean window, and it triples the sample count to do it. On a machine
// that is plainly busy that second chance is nearly always wasted: it turned a
// 10-second skip into a 50-second one on every `go test ./...` run measured
// here. The observed contended cluster starts at 1.048 median/min, so a first
// reading past 1.05 is not borderline and gets no retry.
//
// What this gives up is the occasional busy-machine run that would have found a
// clean window on the second try. The dedicated CI job covers that case
// properly, by retrying the whole test three times — see .github/workflows/ci.yml.
const obviousContentionSpread = 1.05

// ratchetRequiredEnv, when set to "1", turns every skip below into a failure.
// A guard that can skip is a guard that can go silently unmeasured forever, so
// CI runs this package on its own with this set; see .github/workflows/ci.yml.
const ratchetRequiredEnv = "HASHSMITH_RATCHET_REQUIRED"

// interleavedSamples runs two benchmarks in ALTERNATION n times each and
// returns every sample, in order.
//
// The alternation is the point. Measuring one side five times and then the
// other five times gives the two sides two different windows of machine load,
// and best-of-N does not rescue that: if every sample of the second side lands
// in a busy window, its minimum is contended too, and the ratio between the two
// is a comparison of two different machines. Alternating makes any such pressure
// hit both sides, which is what a ratio needs to stay honest.
//
// Machine load and scheduler noise only ever ADD time to a wall-clock sample, so
// the minimum across repeated samples remains the closest available estimate of
// the true, unloaded cost — and the max/min ratio over the same samples is the
// evidence for whether such a window was ever found. See
// docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md for the run that
// motivated interleaving.
func interleavedSamples(n int, a, b func(*testing.B)) (aNs, bNs []int64) {
	for i := 0; i < n; i++ {
		aNs = append(aNs, testing.Benchmark(a).NsPerOp())
		bNs = append(bNs, testing.Benchmark(b).NsPerOp())
	}
	return aNs, bNs
}

// minMax returns the smallest and largest of v, which must be non-empty.
func minMax(v []int64) (int64, int64) {
	lo, hi := v[0], v[0]
	for _, x := range v {
		if x < lo {
			lo = x
		}
		if x > hi {
			hi = x
		}
	}
	return lo, hi
}

// spread is the median/min ratio of v: 1.0 when every sample agrees, and above
// quietSpreadCeiling when most of them were taken on a busy machine. It does not
// modify v.
func spread(v []int64) float64 {
	sorted := append([]int64(nil), v...)
	slices.Sort(sorted)
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	return float64(median) / float64(sorted[0])
}

// This ratchet runs in the ordinary test suite, and the story of why it briefly
// did not is worth keeping.
//
// It failed at 1.10x during a full-suite run, and again at 1.29x on a rerun,
// which looked like proof that a wall-clock RATIO cannot be measured on a
// machine that is doing something else. It was gated behind an environment
// variable on that reasoning, so only a dedicated CI job would run it.
//
// That gate came off after the readings turned out to be contaminated: eight
// runaway busy-loop processes, orphaned by a botched cleanup in an unrelated
// experiment, had been saturating all eight cores for over four hours. But
// removing the gate with nothing in its place was too far the other way — on a
// clean machine the ratchet still failed 2 runs out of 4 under `go test ./...`,
// at 1.57x and 1.61x, while passing every time the package was run on its own
// (2.13, 2.14, 2.14, 2.13x).
//
// So the test stays in the default suite, where a ratchet belongs, and declines
// to render a verdict when its own samples show it could not get a clean window.
// See quietSpreadCeiling for how that is detected and why the obvious guard —
// watching the reference side's absolute cost — cannot do it.
func TestSpeedupOverXCrypto(t *testing.T) {
	required := os.Getenv(ratchetRequiredEnv) == "1"
	// skipf reports "not measured here", which is NOT "passed" and NOT
	// "failed" — except under ratchetRequiredEnv, where being unable to
	// measure is itself the failure. Every skip in this test goes through
	// here, -short included: a required measurement that a flag can quietly
	// turn off is not required.
	skipf := func(format string, args ...any) {
		if required {
			t.Fatalf("%s=1 but the ratchet could not be measured: "+format,
				append([]any{ratchetRequiredEnv}, args...)...)
		}
		t.Skipf(format, args...)
	}
	if testing.Short() {
		skipf("timing test; run without -short")
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

	// measure returns the speedup along with the evidence for whether the
	// samples it came from are worth believing.
	measure := func(n int) (got, worstSpread float64, laneNs, refNs []int64) {
		laneNs, refNs = interleavedSamples(n, lane, ref)
		bestLane, _ := minMax(laneNs)
		bestRef, _ := minMax(refNs)
		worstSpread = spread(laneNs)
		if s := spread(refNs); s > worstSpread {
			worstSpread = s
		}
		return float64(bestRef) / (float64(bestLane) / float64(Lanes)), worstSpread, laneNs, refNs
	}

	got, worstSpread, laneNs, refNs := measure(5)
	bestLane, _ := minMax(laneNs)
	bestRef, _ := minMax(refNs)
	t.Logf("x/crypto %d ns/op (best of 5), bcryptlane %.0f ns/candidate (best of 5) at %d lanes, speedup %.2fx, worst sample spread %.3f (lane %v, reference %v)",
		bestRef, float64(bestLane)/float64(Lanes), Lanes, got, worstSpread, laneNs, refNs)

	// A single unlucky measurement window is not a regression, and neither is
	// a single bursty one. Re-measure with a longer run before acting on
	// either a below-floor reading or a noisy one. This cannot hide a
	// regression — a slower core is slower in both sets — and it costs the
	// extra measurement only on runs that were going to stop here anyway.
	if worstSpread > obviousContentionSpread {
		skipf("SKIPPING speedup ratchet: this machine is plainly busy. "+
			"Repeated samples of the same work spread by %.3fx median-over-minimum, past the "+
			"%.2fx point where a re-measurement is worth taking (ceiling %.2fx) — lane %v, "+
			"reference %v. Run `go test ./internal/bcryptlane` on its own to measure it. This "+
			"SKIP means the ratchet was NOT MEASURED on this run — it is not evidence the "+
			"speedup floor was met.",
			worstSpread, obviousContentionSpread, quietSpreadCeiling, laneNs, refNs)
	}

	if got < bcryptSpeedupFloor || worstSpread > quietSpreadCeiling {
		got2, spread2, lane2, ref2 := measure(9)
		bestLane2, _ := minMax(lane2)
		bestRef2, _ := minMax(ref2)
		t.Logf("re-measured with 9 interleaved samples: x/crypto %d ns/op, bcryptlane %.0f ns/candidate, speedup %.2fx, worst sample spread %.3f (lane %v, reference %v)",
			bestRef2, float64(bestLane2)/float64(Lanes), got2, spread2, lane2, ref2)
		if got2 > got {
			got, laneNs, refNs = got2, lane2, ref2
		}
		worstSpread = spread2
	}

	if worstSpread > quietSpreadCeiling {
		skipf("SKIPPING speedup ratchet: this machine was not quiet enough to measure it. "+
			"Repeated samples of the same work spread by %.3fx median-over-minimum (ceiling %.2fx) — lane %v, reference %v — "+
			"so no clean window was found and the ratio between the two sides is not a "+
			"comparison of the same machine. Run `go test ./internal/bcryptlane` on its own "+
			"to measure it. This SKIP means the ratchet was NOT MEASURED on this run — it is "+
			"not evidence the speedup floor was met.",
			worstSpread, quietSpreadCeiling, laneNs, refNs)
	}

	// Coarse second guard, for the different failure the spread check cannot
	// see: a runner that is uniformly slow rather than bursty. Steady samples
	// on a machine crawling at more than 2x the quiet reference cost are
	// repeatable but still not comparable to a floor derived elsewhere.
	if bestRef, _ := minMax(refNs); bestRef > 2*int64(refQuietBaselineNs) {
		skipf("SKIPPING speedup ratchet: this machine is too slow to measure it. "+
			"best x/crypto/bcrypt reference took %.2fms/op, more than 2x the %.2fms "+
			"quiet-machine baseline (docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md). "+
			"This SKIP means the ratchet was NOT MEASURED on this run — it is not evidence "+
			"the speedup floor was met.",
			float64(bestRef)/1e6, refQuietBaselineNs/1e6)
	}

	if got < bcryptSpeedupFloor {
		t.Errorf("speedup %.2fx is below the %.2fx floor", got, bcryptSpeedupFloor)
	}
}
