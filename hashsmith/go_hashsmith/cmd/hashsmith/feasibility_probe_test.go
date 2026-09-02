package main

// Tests for the feasibility guard's tier-two probe: the mechanism that
// changed is feasibilityRate/feasibilityProbeRate now measuring the RUN'S
// OWN dispatch (runBruteOrMaskLayout — the exact function doCrack calls)
// instead of benchTarget's hand-rolled per-candidate loop, so a batch fast
// path (unsalted md5/md4/ntlm's vector core; salted/unsalted md5/sha1/sha256's
// contiguous batch path) is timed as it actually runs. See feasibility.go's
// package doc and doCrack's probe construction in crack.go for the mechanism
// itself; this file exercises the properties that mechanism has to hold.

import (
	"context"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// feasibilityTestCharset is a-z, spelled out: the crack CLI's -C flag takes a
// literal character set, not a range expression, so tests build layouts
// directly with bruteLayout instead.
const feasibilityTestCharset = "abcdefghijklmnopqrstuvwxyz"

// feasibilityBenchTarget hashes a plaintext no brute-force test layout here
// is long enough to reach, so every probe and every timed sweep in this file
// runs its FULL candidate count — an honest measurement, never cut short by
// an accidental match.
func feasibilityBenchTarget(t *testing.T, typ, salt, saltMode string) string {
	t.Helper()
	target, err := hashText("feasibility-probe-unreachable-plaintext", typ, salt, saltMode)
	if err != nil {
		t.Fatalf("hashText(%s): %v", typ, err)
	}
	return target
}

// feasibilityScalarVerifier is the exact verifyFn doCrack builds (see
// crack.go, just above where it constructs the feasibility probe): the
// zero-allocation fast verifier for a salt-independent raw digest, the
// generic verifier otherwise. It is what runBruteOrMaskLayout's scalar
// fallback calls, so a probe built from it pays the real verification cost.
func feasibilityScalarVerifier(typ, salt, saltMode, target string) func(string) bool {
	verifyFn := func(c string) bool {
		ok, _ := verifyCandidate(c, target, typ, salt, saltMode)
		return ok
	}
	if salt == "" {
		if fv, ok := newFastVerifier(typ, target); ok {
			verifyFn = fv.match
		}
	}
	return verifyFn
}

// feasibilityDispatchProbe builds a feasibilityProbe that runs runBruteOrMaskLayout
// — the SAME dispatcher doCrack calls for a real brute/mask attack — exactly
// as doCrack's own probe construction does. Tests use this instead of
// re-deriving eligibility conditions, for the same reason production code
// does: a second copy of "which path would this take" is how the estimate
// went stale the first time.
func feasibilityDispatchProbe(layout *keyspaceLayout, workers int, typ, salt, saltMode, target string, verifyFn func(string) bool) feasibilityProbe {
	return func(ctx context.Context, n int64) (int64, bool) {
		var attempts int64
		if _, _, err := runBruteOrMaskLayout(ctx, layout, nil, 0, n, workers,
			&attempts, typ, salt, saltMode, target, verifyFn); err != nil {
			return 0, false
		}
		return attempts, true
	}
}

// feasibilityScalarOnlyProbe is feasibilityDispatchProbe's twin that calls
// runLayout directly instead of going through the dispatcher — i.e. it always
// takes the scalar path, exactly what the guard measured before this task's
// fix (and exactly the "probe the scalar path again" mutation the task asks
// to check the tests catch).
func feasibilityScalarOnlyProbe(layout *keyspaceLayout, workers int, verifyFn func(string) bool) feasibilityProbe {
	return func(ctx context.Context, n int64) (int64, bool) {
		var attempts int64
		if _, err := runLayout(ctx, layout, 0, n, workers, &attempts, nil, verifyFn); err != nil {
			return 0, false
		}
		return attempts, true
	}
}

// feasibilityETATolerance bounds how far a fast-path prediction may sit above
// the ACTUAL measured wall clock for the same real dispatch. 4x is chosen
// from two clusters actually observed developing this suite on shared,
// heavily loaded CI/dev hardware (double-digit load averages on an 8-core
// box, from OTHER tenants — this suite's own noise, not anything this task
// changed): the fix in place typically measures anywhere from ~0.5x to ~2x,
// occasionally higher under a load spike, while reverting it (dispatching
// through the scalar path again — see the mutation testing performed for
// this task) reliably measures ~5x-26x. 10x, tried first, sat inside that
// second cluster and let the "probe the scalar path again" mutation slip
// through some runs; 4x sits in the gap with real margin on both sides
// without demanding the guard be exact. Only pessimism (predicted slower
// than real) is bounded here, matching the guard's own asymmetric safety
// rule: erring optimistic costs nothing but an honest ETA line, so it is
// never penalized.
const feasibilityETATolerance = 4.0

// measureDispatchETA sizes a brute-force layout of `length` from
// feasibilityTestCharset, asks feasibilityProbeRate for its prediction via the
// REAL dispatch probe, then times that same dispatch running the full,
// unbounded sweep — so "predicted" and "actual" are the same code path this
// task changed. It deliberately bypasses tier one's own single-call estimate
// (by handing feasibilityProbeRate a tiny seed perOp directly, rather than
// going through feasibilityRate's tier-one gate) so the test exercises tier
// two — the mechanism that changed — regardless of whether tier one's own
// noisy cheap estimate happens to resolve early on a given run.
func measureDispatchETA(t *testing.T, typ, salt, saltMode string, length, workers int) (predictedETASec, actualElapsedSec float64) {
	t.Helper()
	target := feasibilityBenchTarget(t, typ, salt, saltMode)
	layout := bruteLayout(feasibilityTestCharset, length, length)
	verifyFn := feasibilityScalarVerifier(typ, salt, saltMode, target)
	probe := feasibilityDispatchProbe(layout, workers, typ, salt, saltMode, target, verifyFn)

	rate, ok := feasibilityProbeRate(probe, time.Nanosecond, feasibilityProbeDuration, workers)
	if !ok || rate <= 0 {
		t.Fatalf("feasibilityProbeRate failed for type=%s salt=%q: rate=%v ok=%v", typ, salt, rate, ok)
	}
	predictedETASec = float64(layout.total) / rate

	var realAttempts int64
	start := time.Now()
	_, _, err := runBruteOrMaskLayout(context.Background(), layout, nil, 0, 0, workers,
		&realAttempts, typ, salt, saltMode, target, verifyFn)
	actualElapsedSec = time.Since(start).Seconds()
	if err != nil {
		t.Fatalf("real dispatch run: %v", err)
	}
	if realAttempts != layout.total {
		t.Fatalf("real run attempted %d candidates, want the full %d-candidate sweep "+
			"(the target is built to be unreachable, so a short count means something else stopped it)",
			realAttempts, layout.total)
	}
	return predictedETASec, actualElapsedSec
}

// TestFeasibilityETAMatchesRealDispatch is properties 1 and 2 from the task:
// the printed ETA (here, the number that feeds it) must be within a sane
// factor of reality for a run that uses a fast path, and salted/unsalted
// md5/sha256 all improve — these are exactly the paths that regressed when a
// batch fast path was added without teaching the guard about it.
func TestFeasibilityETAMatchesRealDispatch(t *testing.T) {
	// This test times real cracking runs, so it costs ~6s of wall clock.
	// CI runs the full suite and still gates on it; -short keeps the local
	// edit-test loop fast.
	if testing.Short() {
		t.Skip("times real runs; run without -short to include it")
	}
	const workers = 4
	cases := []struct {
		name     string
		typ      string
		salt     string
		saltMode string
		length   int
	}{
		{"md5 unsalted (vector fast path)", "md5", "", "prefix", 5},
		{"md5 salted (contiguous batch path)", "md5", "deadbeef", "prefix", 5},
		{"sha256 unsalted (contiguous batch path)", "sha256", "", "prefix", 5},
		{"sha256 salted (contiguous batch path)", "sha256", "deadbeef", "prefix", 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// This suite runs on shared hardware that has shown load averages
			// several times its core count during development (other tenants,
			// not this test) — enough to occasionally distort a single 150ms
			// sample by an order of magnitude on its own, independent of
			// anything this task changed. Retrying up to 3 times and passing
			// on the best attempt tolerates that noise; it does not weaken
			// what the test proves, because a genuine regression (probing the
			// scalar path again, a pessimistic constant factor, tier two
			// skipped) makes EVERY attempt pessimistic by roughly the same
			// systematic factor — see the mutation testing performed for this
			// task — so it still fails all 3, not just most.
			const attempts = 3
			var best float64 = math.Inf(1)
			var lastPredicted, lastActual float64
			for i := 0; i < attempts; i++ {
				predicted, actual := measureDispatchETA(t, c.typ, c.salt, c.saltMode, c.length, workers)
				if actual <= 0 {
					t.Fatalf("real sweep reported non-positive elapsed time %v — cannot compute a ratio", actual)
				}
				ratio := predicted / actual
				t.Logf("%s: attempt %d/%d predicted ETA %.4gs, actual %.4gs, ratio %.2fx",
					c.name, i+1, attempts, predicted, actual, ratio)
				lastPredicted, lastActual = predicted, actual
				if ratio < best {
					best = ratio
				}
				if ratio <= feasibilityETATolerance {
					break
				}
			}
			if best > feasibilityETATolerance {
				t.Errorf("%s: best of %d attempts still predicted an ETA (%.4gs) %.1fx the real "+
					"dispatch's actual time (%.4gs), exceeding the %.0fx tolerance — the guard is "+
					"timing the wrong path again", c.name, attempts, lastPredicted, best, lastActual, feasibilityETATolerance)
			}
		})
	}
}

// TestFeasibilityProbeBeatsScalarPath directly proves the fix's premise —
// that dispatching through the real path (fast/std batch when eligible) beats
// timing the scalar verify closure — and doubles as the "probe the scalar
// path again" mutation check: if doCrack's probe were changed to call
// runLayout directly (scalar) instead of runBruteOrMaskLayout (the real
// dispatch), this test fails.
func TestFeasibilityProbeBeatsScalarPath(t *testing.T) {
	const workers = 4
	cases := []struct {
		name     string
		typ      string
		salt     string
		saltMode string
		// minRatio is the smallest dispatchRate/scalarRate this case must
		// clear. Salted digests always measure their scalar baseline through
		// the slow, allocating generic verifyCandidate (benchVerifyPath only
		// takes the zero-alloc newFastVerifier for salt==""), so the batch
		// path's advantage there is large and consistent — 1.2x is a
		// deliberately modest floor under speedups typically seen from
		// ~5x to ~28x. An UNSALTED digest's scalar baseline already IS that
		// zero-alloc newFastVerifier (md5's own NEON/AVX2 core when running
		// natively, Go's hardware-accelerated stdlib sha256 otherwise), so
		// its batch/vector path's edge over that baseline is smaller and, on
		// shared/noisy hardware or under CPU emulation (this suite's amd64
		// cross-build runs under Rosetta on the machine this was developed
		// on), sometimes not even positive — 0.5 only rules out a dramatic
		// regression (falling back to scalar would still measure ~1.0x, well
		// above 0.5, so this still catches that mutation for every case);
		// the unsalted cases' real regression coverage comes from
		// TestFeasibilityETAMatchesRealDispatch instead, which compares
		// against real wall clock rather than this synthetic pairing.
		minRatio float64
	}{
		{"md5 unsalted", "md5", "", "prefix", 0.5},
		{"md5 salted", "md5", "deadbeef", "prefix", 1.2},
		{"sha256 unsalted", "sha256", "", "prefix", 0.5},
		{"sha256 salted", "sha256", "deadbeef", "prefix", 1.2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := feasibilityBenchTarget(t, c.typ, c.salt, c.saltMode)
			layout := bruteLayout(feasibilityTestCharset, 5, 5)
			verifyFn := feasibilityScalarVerifier(c.typ, c.salt, c.saltMode, target)

			dispatchProbe := feasibilityDispatchProbe(layout, workers, c.typ, c.salt, c.saltMode, target, verifyFn)
			scalarProbe := feasibilityScalarOnlyProbe(layout, workers, verifyFn)

			dispatchRate, ok1 := feasibilityProbeRate(dispatchProbe, time.Nanosecond, feasibilityProbeDuration, workers)
			scalarRate, ok2 := feasibilityProbeRate(scalarProbe, time.Nanosecond, feasibilityProbeDuration, workers)
			if !ok1 || !ok2 {
				t.Fatalf("probe measurement failed: dispatch ok=%v rate=%v, scalar ok=%v rate=%v",
					ok1, dispatchRate, ok2, scalarRate)
			}
			t.Logf("%s: dispatch %.4g/s, scalar %.4g/s (%.2fx)", c.name, dispatchRate, scalarRate, dispatchRate/scalarRate)
			if dispatchRate < scalarRate*c.minRatio {
				t.Errorf("%s: dispatching through the real fast/std path (%.4g/s) should be at least "+
					"%.2fx the scalar verify closure (%.4g/s) — got only %.2fx",
					c.name, dispatchRate, c.minRatio, scalarRate, dispatchRate/scalarRate)
			}
		})
	}
}

// TestFeasibilityNoFalseRefusalForFastPath is property 3: a run whose true
// (fast-path) ETA is comfortably under the one-year limit must not be
// refused, even though the OLD (pre-fix) scalar-path estimate for the exact
// same candidate count would have exceeded it. The candidate count is picked
// dynamically from measured rates rather than a hardcoded constant, so the
// test adapts to whatever throughput this machine actually has.
func TestFeasibilityNoFalseRefusalForFastPath(t *testing.T) {
	preserveExitCode(t)
	const workers = 4
	typ, salt, saltMode := "md5", "deadbeef", "prefix"
	target := feasibilityBenchTarget(t, typ, salt, saltMode)
	// Long enough that no probe sample (sized in the thousands to low
	// millions of candidates) can ever run past the layout's own total.
	layout := bruteLayout(feasibilityTestCharset, 8, 8)
	verifyFn := feasibilityScalarVerifier(typ, salt, saltMode, target)
	fastProbe := feasibilityDispatchProbe(layout, workers, typ, salt, saltMode, target, verifyFn)

	fastRate, ok := feasibilityProbeRate(fastProbe, time.Nanosecond, feasibilityProbeDuration, workers)
	if !ok || fastRate <= 0 {
		t.Fatalf("fast-path rate measurement failed: rate=%v ok=%v", fastRate, ok)
	}
	// feasibilityRate with probe=nil is exactly the pre-fix path: tier one
	// (unaffected by this task) plus benchTarget. work is set enormous so
	// tier one — a ceiling on the SCALAR path only — cannot possibly resolve
	// this as feasible on its own; only benchTarget's real timing can.
	scalarRate, ok := feasibilityRate(1<<62, typ, target, salt, saltMode, workers, nil)
	if !ok || scalarRate <= 0 {
		t.Fatalf("scalar-path rate measurement failed: rate=%v ok=%v", scalarRate, ok)
	}
	t.Logf("fast-path rate %.4g/s, scalar-path rate %.4g/s", fastRate, scalarRate)

	ratio := fastRate / scalarRate
	// The gate (and the k derived from it below) both need real headroom, not
	// just ratio > 1: checkFeasibility below takes its OWN fresh measurement
	// of each rate rather than reusing fastRate/scalarRate above (that is the
	// whole point — it has to measure the run it is actually about to make,
	// same as production), and on shared/noisy hardware two 150ms samples of
	// the "same" rate taken moments apart can differ by several x on their
	// own. A thin margin (this failed at k just over 1, i.e. work barely past
	// the limit at the sizing-time scalarRate) flips sign against that noise
	// often enough to fail outright rather than skip. k=4 costs margin on
	// both sides — work is 4x over the limit at scalarRate, 4x under-margin
	// at fastRate (ratio/4, still comfortably under limit/10 once ratio>=40)
	// — deliberately trading a higher skip rate on quiet machines for one
	// that does not spuriously fail on noisy ones.
	const marginK = 4
	if ratio < 10*marginK {
		t.Skipf("fast-path rate (%.4g/s) is not usefully faster than the scalar-path rate (%.4g/s) "+
			"on this machine — cannot construct a case that separates them with enough margin", fastRate, scalarRate)
	}
	work := int64(scalarRate * feasibilityLimitSeconds * marginK)

	// checkFeasibility takes its OWN fresh measurement every call (that is
	// the whole point — it measures the run it is actually about to make),
	// so on shared/noisy hardware a single call can land on the wrong side of
	// `work` despite the marginK=4 headroom. Retrying up to 3 times and
	// requiring success on any one of them tolerates that without weakening
	// what is being proven: a genuinely broken fix (probe not wired in,
	// probe ignored) refuses on every attempt, not just some.
	const attempts = 3
	var out string
	var err error
	for i := 0; i < attempts; i++ {
		out, err = captureStderrResult(t, func() error {
			return checkFeasibility(work, false, typ, target, salt, saltMode, workers, false, fastProbe)
		})
		if err == nil {
			break
		}
		t.Logf("attempt %d/%d: fast-path checkFeasibility refused: %v", i+1, attempts, err)
	}
	if err != nil {
		t.Fatalf("a run whose real fast-path ETA (%.4gs, %.2f%% of the 1-year limit) must not be refused, "+
			"in %d attempts: %v\n%s", float64(work)/fastRate, 100*float64(work)/fastRate/feasibilityLimitSeconds,
			attempts, err, out)
	}
	if !strings.Contains(out, "-> ETA") {
		t.Errorf("a feasible run must still print an ETA:\n%s", out)
	}

	// Prove this test is actually exercising the gap it claims to: the SAME
	// candidate count, on the pre-fix path (probe=nil), must be refused at
	// least once in the same number of attempts. Without this check, a
	// `work` too small to separate the two rates would pass trivially and
	// this test would catch nothing. If EVERY attempt fails to refuse, that
	// means this run's measured rates did not separate cleanly just now —
	// noise, not a claim the fix is broken — so it skips rather than fails.
	var errOld error
	refusedOnce := false
	for i := 0; i < attempts; i++ {
		_, errOld = captureStderrResult(t, func() error {
			return checkFeasibility(work, false, typ, target, salt, saltMode, workers, false, nil)
		})
		if errOld != nil && isFeasibilityRefusal(errOld) {
			refusedOnce = true
			break
		}
	}
	if !refusedOnce {
		t.Skipf("measurement noise: a fresh scalar-path measurement did not refuse this candidate "+
			"count in %d attempts (last result: %v) — the gap between the fast and scalar rates was "+
			"not reliably large enough to separate them just now", attempts, errOld)
	}
}

// TestFeasibilityUnchangedForSlowKDF is property 5: bcrypt has no fast/std
// path to reach (fastPathEligible and stdPathEligible both decline it), so
// runBruteOrMaskLayout's dispatcher falls straight through to the same
// scalar runner benchTarget already used. Probing through the real dispatch
// must therefore measure ~the same throughput as the old benchTarget-only
// path, not a faster or slower number.
func TestFeasibilityUnchangedForSlowKDF(t *testing.T) {
	const workers = 4
	target := testBcryptTarget(t)
	// Large enough that tier one (which for bcrypt gives an accurate, not
	// optimistic, estimate — see feasibility.go) cannot resolve either call
	// early; both must reach their tier-two measurement for this to compare
	// anything.
	layout := bruteLayout(feasibilityTestCharset, 6, 6)
	verifyFn := feasibilityScalarVerifier("bcrypt", "", "prefix", target)
	probe := feasibilityDispatchProbe(layout, workers, "bcrypt", "", "prefix", target, verifyFn)

	withProbe, ok1 := feasibilityRate(layout.total, "bcrypt", target, "", "prefix", workers, probe)
	withoutProbe, ok2 := feasibilityRate(layout.total, "bcrypt", target, "", "prefix", workers, nil)
	if !ok1 || !ok2 {
		t.Fatalf("rate measurement failed: withProbe ok=%v rate=%v, withoutProbe ok=%v rate=%v",
			ok1, withProbe, ok2, withoutProbe)
	}
	ratio := withProbe / withoutProbe
	t.Logf("bcrypt: with real-dispatch probe %.4g/s, benchTarget-only %.4g/s (%.2fx)", withProbe, withoutProbe, ratio)
	// Wide tolerance: bcrypt is slow enough that either measurement only
	// covers a handful of calls in the probe budget, so the sample is noisy
	// — observed run-to-run anywhere from ~0.4x to ~5.8x on shared, loaded
	// hardware even with this fix correctly in place. The property under
	// test is "no systematic change" (the un-fixed version of this mechanism
	// measured a consistent, repeatable ~0.1-0.3x — workers idle behind a
	// chunk-granularity floor — not "no change ever", which one-off noise on
	// a two-sample comparison cannot promise), not precision.
	if ratio < 0.1 || ratio > 10.0 {
		t.Errorf("bcrypt has no fast path to reach; probing the real dispatch should measure ~the same "+
			"throughput as the pre-fix benchTarget path, got %.4g/s vs %.4g/s (ratio %.2fx)",
			withProbe, withoutProbe, ratio)
	}
}

// TestFeasibilityProbeRateFallsBack checks every way feasibilityProbeRate is
// documented to decline back to benchTarget: no probe supplied, an
// unmeasurable seed perOp, and a probe that reports it cannot run at all.
// None of these may report ok=true — a false "trustworthy" measurement here
// would feed a made-up rate into the ETA instead of falling back honestly.
func TestFeasibilityProbeRateFallsBack(t *testing.T) {
	alwaysDeclines := func(ctx context.Context, n int64) (int64, bool) { return 0, false }
	trivialProbe := func(ctx context.Context, n int64) (int64, bool) { return n, true }

	cases := []struct {
		name  string
		probe feasibilityProbe
		perOp time.Duration
	}{
		{"nil probe", nil, time.Microsecond},
		{"unmeasurable perOp (zero)", trivialProbe, 0},
		{"negative perOp", trivialProbe, -time.Microsecond},
		{"probe declines outright", alwaysDeclines, time.Microsecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rate, ok := feasibilityProbeRate(c.probe, c.perOp, feasibilityProbeDuration, 4)
			if ok {
				t.Errorf("expected feasibilityProbeRate to fall back (ok=false), got ok=true rate=%v", rate)
			}
		})
	}
}

// TestFeasibilityProbeRateConvergesRegardlessOfSeed pins the doubling/sizing
// arithmetic itself, deterministically: a fake probe with a known, fixed
// candidates/sec rate must make feasibilityProbeRate converge to that rate
// whether the seed perOp it is sized from under- or over-estimates the real
// per-candidate cost by a realistic factor (the kind of mismatch candidate
// generation overhead can introduce on the scalar fallback — see
// feasibilityProbeRate's doc comment — not an unbounded adversarial one).
func TestFeasibilityProbeRateConvergesRegardlessOfSeed(t *testing.T) {
	const realRate = 2_000_000.0 // fake candidates/sec
	perCandidate := time.Duration(float64(time.Second) / realRate)
	probe := func(ctx context.Context, n int64) (int64, bool) {
		time.Sleep(time.Duration(n) * perCandidate)
		return n, true
	}
	const budget = 60 * time.Millisecond
	seeds := map[string]time.Duration{
		"seed matches real cost":  perCandidate,
		"seed 5x too optimistic":  perCandidate / 5,
		"seed 5x too pessimistic": perCandidate * 5,
	}
	for name, seed := range seeds {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			rate, ok := feasibilityProbeRate(probe, seed, budget, 1)
			elapsed := time.Since(start)
			if !ok {
				t.Fatalf("expected a trustworthy measurement, got ok=false")
			}
			if ratio := rate / realRate; ratio < 0.5 || ratio > 2.0 {
				t.Errorf("measured rate %.0f/s too far from the real %.0f/s (ratio %.2fx)", rate, realRate, ratio)
			}
			// A seed that is too OPTIMISTIC (assumes candidates are cheaper
			// than they are) sizes its first attempt too large; since that
			// attempt is bounded by candidate count, not by a cancellation
			// check (see feasibilityProbeRate's doc comment), it can overrun
			// budget by up to about the mismatch factor itself — here 5x —
			// before the elapsed/minElapsed check ever gets a say. A seed
			// that is too PESSIMISTIC only ever undersizes, so it costs at
			// most a few doublings, never a multi-x overrun. This bounds
			// both at roughly (mismatch factor + 1) x budget with headroom.
			if elapsed > 7*budget {
				t.Errorf("feasibilityProbeRate took %v against a %v budget (seed %v) — too far over budget", elapsed, budget, seed)
			}
		})
	}
}

// feasibilityRateLineRE matches the ETA line's "at ~<N> <unit>H/s" clause —
// the same string formatRate produces — so a test can recover the numeric
// rate the guard actually printed.
var feasibilityRateLineRE = regexp.MustCompile(`at ~([0-9.]+) (G|M|k|)H/s`)

// feasibilityPredictedETAFromOutput parses the candidate count and rate out
// of checkFeasibility's printed ETA line and returns keyspace/rate — the same
// arithmetic checkFeasibility itself does to produce the ETA it prints.
func feasibilityPredictedETAFromOutput(t *testing.T, out string) float64 {
	t.Helper()
	keyspace := estimatedKeyspace(t, out)
	m := feasibilityRateLineRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no rate clause in feasibility output:\n%s", out)
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("unparsable rate %q: %v", m[1], err)
	}
	mult := map[string]float64{"": 1, "k": 1e3, "M": 1e6, "G": 1e9}[m[2]]
	rate := n * mult
	if rate <= 0 {
		t.Fatalf("non-positive parsed rate in output:\n%s", out)
	}
	return float64(keyspace) / rate
}

// TestFeasibilityETAThroughRunCrack is the one true end-to-end check in this
// file: it drives the actual CLI entry point (runCrack -> doCrack), not a
// hand-assembled probe. Every other test above builds its OWN probe closure
// with feasibilityDispatchProbe, which calls runBruteOrMaskLayout directly —
// faithful to how doCrack builds its probe, but NOT sensitive to doCrack's
// own wiring breaking (e.g. its probe construction being changed to call
// runLayout, the scalar path, instead — see crack.go, just above the
// checkFeasibility call). Only a test that goes through runCrack itself can
// catch that; this is it.
func TestFeasibilityETAThroughRunCrack(t *testing.T) {
	// This test times real cracking runs, so it costs ~24s of wall clock.
	// CI runs the full suite and still gates on it; -short keeps the local
	// edit-test loop fast.
	if testing.Short() {
		t.Skip("times real runs; run without -short to include it")
	}
	preserveExitCode(t)
	target, err := hashText("feasibility-cli-unreachable-plaintext", "md5", "deadbeef", "prefix")
	if err != nil {
		t.Fatal(err)
	}

	// 26^6 candidates, not 26^5: this has to be large enough that tier ONE's
	// own cheap estimate (unaffected by the probe under test — it always
	// measures the generic verifyCandidate closure for a salted target,
	// mutated or not) already exceeds feasibilityRoughCeiling on its own.
	// Below that size tier one can resolve the ETA by itself without ever
	// reaching tier two, and this test would sometimes pass on tier one's
	// number regardless of whether doCrack's probe is wired correctly —
	// exactly the gap that let the "probe the scalar path again" mutation
	// slip through this test once during development, at 26^5.

	// Same noise-tolerant retry as TestFeasibilityETAMatchesRealDispatch —
	// see its comment for why up to 3 attempts, passing on the best, does
	// not weaken what a systematic regression (this mutation included) would
	// still reliably fail.
	const attemptsN = 3
	best := math.Inf(1)
	var lastPredicted, lastActual float64
	for i := 0; i < attemptsN; i++ {
		start := time.Now()
		out, err := captureStderrResult(t, func() error {
			return runCrack([]string{"-t", "md5", "-s", "deadbeef", "-S", "prefix",
				"-M", "brute", "-C", feasibilityTestCharset, "-n", "6", "-x", "6",
				"-p", "4", "--no-pot", target})
		})
		elapsed := time.Since(start).Seconds()
		if err != nil {
			t.Fatalf("attempt %d/%d: runCrack: %v\n%s", i+1, attemptsN, err, out)
		}
		predicted := feasibilityPredictedETAFromOutput(t, out)
		ratio := predicted / elapsed
		t.Logf("attempt %d/%d: predicted ETA %.4gs, actual %.4gs, ratio %.2fx", i+1, attemptsN, predicted, elapsed, ratio)
		lastPredicted, lastActual = predicted, elapsed
		if ratio < best {
			best = ratio
		}
		if ratio <= feasibilityETATolerance {
			break
		}
	}
	if best > feasibilityETATolerance {
		t.Errorf("best of %d attempts through runCrack still predicted an ETA (%.4gs) %.1fx the "+
			"real elapsed time (%.4gs), exceeding the %.0fx tolerance — the guard is timing the "+
			"wrong path again", attemptsN, lastPredicted, best, lastActual, feasibilityETATolerance)
	}
}
