package main

import (
	"sync"
	"testing"
	"time"
)

func TestBenchType(t *testing.T) {
	rate, ok := benchType("md5", 2, 100*time.Millisecond)
	if !ok || rate <= 0 {
		t.Errorf("md5 benchmark: ok=%v rate=%v", ok, rate)
	}
	if _, ok := benchSeed("not-a-real-type"); ok {
		t.Error("bogus type should not be seedable")
	}
	if _, ok := benchType("not-a-real-type", 2, 10*time.Millisecond); ok {
		t.Error("bogus type should not be benchmarkable")
	}
	// bcrypt is seedable (KDF reference)
	if _, ok := benchSeed("bcrypt"); !ok {
		t.Error("bcrypt should be seedable")
	}
}

// A slow KDF must not overrun its time budget. The old loop checked the
// deadline every 1024 iterations, so bcrypt (~60ms/op) ran ~61s against a
// 1s budget.
//
// The allowance is derived from a directly measured bcrypt op cost rather
// than a hardcoded constant: under -race a single bcrypt op goes from ~60ms
// to ~1s+, and a fixed "+2s" allowance is not generous enough to cover that
// without becoming meaningless on a fast build.
//
// Op cost is measured by running `workers` bcrypt ops concurrently — the
// same contention pattern (goroutines sharing cores, -race's extra
// synchronization) the real run experiences — and is sampled both before
// and after the real run, taking the larger of the two. A single probe
// taken only before the real run was found by experiment to be flaky on
// this machine: under sustained -race + bcrypt load the CPU visibly slows
// down further (thermal throttling) between the "before" probe and the
// real run, so a single pre-run sample understates the cost the real run
// actually pays. Sampling after too and taking the max tracks that drift
// instead of guessing a fixed safety factor for it.
//
// The test still fails if the 1024-iteration stride is reintroduced: that
// overruns by ~500x opCost, far past any allowance built from a few
// multiples of opCost.
func TestBenchTypeRespectsBudgetForSlowKDF(t *testing.T) {
	const workers = 2
	seed, ok := benchSeed("bcrypt")
	if !ok {
		t.Skip("bcrypt not benchmarkable in this build")
	}

	// measureOpCost times `workers` concurrent bcrypt verifications via the
	// same generic verify path benchType's non-fast branch uses.
	measureOpCost := func() time.Duration {
		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = verifyCandidate("benchprobe", seed, "bcrypt", "", "prefix")
			}()
		}
		wg.Wait()
		return time.Since(start)
	}

	before := measureOpCost()

	budget := 300 * time.Millisecond
	start := time.Now()
	if _, ok := benchType("bcrypt", workers, budget); !ok {
		t.Skip("bcrypt not benchmarkable in this build")
	}
	elapsed := time.Since(start)

	after := measureOpCost()
	opCost := before
	if after > opCost {
		opCost = after
	}

	// benchType pays one more op serially (its internal stride-sizing
	// probe) before workers start, and each worker may have one op in
	// flight past the deadline — both roughly opCost-sized under this same
	// contention — so allow 8x opCost, plus slack for run-to-run noise.
	// (8x rather than 3x: measured 2-of-3 flakiness under external CPU
	// contention, e.g. a concurrent race-detector build competing for
	// cores. This still leaves a ~130x margin against the fixed
	// local&1023 deadline-stride defect this test guards against, which
	// for bcrypt would overrun by roughly 1024x opCost.)
	allowance := budget + 8*opCost + 300*time.Millisecond
	if elapsed > allowance {
		t.Errorf("bcrypt benchmark overran its %v budget (opCost before=%v after=%v, allowance=%v): took %v",
			budget, before, after, allowance, elapsed)
	}
}

// matchBytes exists to remove the string conversion the measurement loop was
// paying per candidate. It must allocate strictly less than the string path.
//
// Note it is NOT expected to reach zero: the local digest buffer escapes
// because buf[:] is passed to a func-typed struct field the compiler cannot
// see through (measured: match() is 64 B/op, 1 allocs/op). Removing that last
// allocation would need a verifier-owned scratch field, and fastVerifier is
// shared across workers on the non-batch path, where a mutable field would
// race. The win being asserted here is the string conversion, nothing more.
func TestMatchBytesAllocatesLessThanMatch(t *testing.T) {
	fv, ok := newFastVerifier("md5", "5f4dcc3b5aa765d61d8327deb882cf99")
	if !ok {
		t.Fatal("md5 must have a fast verifier")
	}

	// Correctness first: testing.AllocsPerRun below discards matchBytes's
	// return value, so a matchBytes that always returned false would still
	// pass the allocation assertion. benchType also never checks the
	// result (benchSeed deliberately seeds a non-matching target), so
	// nothing else in the suite or the real command would catch that. The
	// target hash above is md5("password"), so assert against it directly.
	if !fv.matchBytes([]byte("password")) {
		t.Error("matchBytes: expected true for the matching candidate \"password\"")
	}
	if fv.matchBytes([]byte("benchAAAA")) {
		t.Error("matchBytes: expected false for a non-matching candidate")
	}

	buf := []byte("benchAAAA")
	viaString := testing.AllocsPerRun(1000, func() { fv.match(string(buf)) })
	viaBytes := testing.AllocsPerRun(1000, func() { fv.matchBytes(buf) })
	if viaBytes >= viaString {
		t.Errorf("matchBytes allocated %v/run, match(string) allocated %v/run; "+
			"matchBytes must allocate strictly less", viaBytes, viaString)
	}
	t.Logf("allocs per run: match(string)=%v matchBytes=%v", viaString, viaBytes)
}
