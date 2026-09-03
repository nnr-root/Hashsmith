package main

// Tests for the feasibility guard's tier-two probe on the MULTI-HASH (dump)
// path: batch.go now builds a feasibilityProbe over the SAME dispatch
// batchRunType's own runPass drives — batchFastLayout / batchStdLayout / the
// scalar runLayout fallback — instead of leaving probe nil and falling back
// to benchTarget's hand-rolled per-candidate loop. See feasibility_probe_test.go
// for the single-target twin of this mechanism and doc comments; this file
// exercises the same properties for a dump.

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// buildUnreachableBatch builds n batchTarget entries of type/salt/saltMode,
// each the digest of a plaintext no test brute-force layout here is long
// enough to reach — so every probe and every timed sweep in this file runs
// its FULL candidate count, an honest measurement never cut short by an
// accidental match. All n entries share salt, exactly as one of runBatch's
// per-salt groups (batchSaltGroups) does — that sharing is the precondition
// batchFastLayout/batchStdLayout both document.
func buildUnreachableBatch(t *testing.T, typ, salt, saltMode string, n int) ([]*batchTarget, []int) {
	t.Helper()
	batch := make([]*batchTarget, n)
	active := make([]int, n)
	for i := 0; i < n; i++ {
		plain := fmt.Sprintf("batch-feasibility-unreachable-plaintext-%d", i)
		target, err := hashText(plain, typ, salt, saltMode)
		if err != nil {
			t.Fatalf("hashText(%s): %v", typ, err)
		}
		batch[i] = &batchTarget{norm: target, key: strings.ToLower(target), salt: salt}
		active[i] = i
	}
	return batch, active
}

// batchFeasibilityRecord is the exact `record` closure batchRunType builds
// (see batch.go): CAS-guarded, decrements remaining, reports "everything
// found" only once. Tests use their own remaining counter rather than
// reaching into a real batchRunType call, mirroring how
// feasibilityDispatchProbe builds its own verifyFn instead of doCrack's.
func batchFeasibilityRecord(batch []*batchTarget, remaining *int64) func(string, []int) bool {
	return func(candidate string, idxs []int) bool {
		for _, idx := range idxs {
			if atomic.CompareAndSwapInt32(&batch[idx].flag, 0, 1) {
				batch[idx].password = candidate
				if atomic.AddInt64(remaining, -1) == 0 {
					return true
				}
			}
		}
		return false
	}
}

// batchFeasibilityVerify mirrors the `verify` closure batchRunType builds
// (see batch.go, just above where it constructs the feasibility probe): the
// zero-allocation raw-byte matcher when the type has one, the generic
// hex-digest map otherwise. It is what runLayout's scalar fallback calls
// inside a batch pass, so a probe built from it pays the real verification
// cost — the same reason feasibility_probe_test.go's
// feasibilityScalarVerifier duplicates doCrack's single-target verifyFn
// instead of reaching into it.
func batchFeasibilityVerify(typ, salt, saltMode string, batch []*batchTarget, active []int, record func(string, []int) bool) func(string) bool {
	hashName, pre, suf := typ, "", ""
	if salt != "" {
		if algo, sp, ok := stdSaltedPlanFor(typ, salt, saltMode); ok {
			hashName, pre, suf = algo.name, string(sp.pre), string(sp.suf)
		}
	}
	if h, ok := rawHasher(hashName); ok {
		m := make(map[[64]byte][]int, len(active))
		for _, idx := range active {
			tb, err := hex.DecodeString(strings.TrimSpace(batch[idx].key))
			if err != nil || len(tb) > 64 {
				continue
			}
			var k [64]byte
			copy(k[:], tb)
			m[k] = append(m[k], idx)
		}
		return func(candidate string) bool {
			var buf [64]byte
			h(buf[:], pre+candidate+suf)
			idxs, ok := m[buf]
			if !ok {
				return false
			}
			return record(candidate, idxs)
		}
	}
	digestFn := rawDigest(hashName)
	m := make(map[string][]int, len(active))
	for _, idx := range active {
		m[batch[idx].key] = append(m[batch[idx].key], idx)
	}
	return func(candidate string) bool {
		idxs, ok := m[digestFn(pre+candidate+suf)]
		if !ok {
			return false
		}
		return record(candidate, idxs)
	}
}

// batchFeasibilityDispatchProbe builds a feasibilityProbe that runs
// batchFastLayout / batchStdLayout / runLayout — the SAME dispatch chain
// batchRunType's runPass drives for a real dump pass — exactly as batch.go's
// own probe construction does. Tests use this instead of re-deriving
// eligibility conditions, for the same reason production code does: a second
// copy of "which path would this take" is how the estimate went stale the
// first time (see feasibility.go's package doc).
func batchFeasibilityDispatchProbe(typ, salt, saltMode string, layout *keyspaceLayout,
	active []int, batch []*batchTarget, workers int, record func(string, []int) bool,
	verify func(string) bool) feasibilityProbe {
	return func(ctx context.Context, n int64) (int64, bool) {
		var attempts int64
		if batchFastLayout(ctx, typ, salt, saltMode, layout, active, batch,
			0, n, workers, &attempts, nil, record) {
			return attempts, true
		}
		if batchStdLayout(ctx, typ, layout, active, batch, salt, saltMode,
			0, n, workers, &attempts, nil, record) {
			return attempts, true
		}
		if _, err := runLayout(ctx, layout, 0, n, workers, &attempts, nil, verify); err != nil {
			return 0, false
		}
		return attempts, true
	}
}

// batchFeasibilityScalarOnlyProbe is batchFeasibilityDispatchProbe's twin
// that calls runLayout directly instead of going through the fast/std
// dispatch — i.e. it always takes the scalar path, exactly what the guard
// measured for a dump before this task's fix (and exactly the "probe the
// scalar path again" mutation the task asks to check the tests catch).
func batchFeasibilityScalarOnlyProbe(layout *keyspaceLayout, workers int, verify func(string) bool) feasibilityProbe {
	return func(ctx context.Context, n int64) (int64, bool) {
		var attempts int64
		if _, err := runLayout(ctx, layout, 0, n, workers, &attempts, nil, verify); err != nil {
			return 0, false
		}
		return attempts, true
	}
}

// measureBatchDispatchETA sizes a brute-force layout of `length` from
// feasibilityTestCharset, builds a `numTargets`-target unreachable batch
// sharing type/salt, asks feasibilityProbeRate for its prediction via the
// REAL batch dispatch probe, then times that same dispatch running the full,
// unbounded sweep — so "predicted" and "actual" are the same code path this
// task changed. Mirrors feasibility_probe_test.go's measureDispatchETA for
// the single-target path.
func measureBatchDispatchETA(t *testing.T, typ, salt, saltMode string, length, workers, numTargets int) (predictedETASec, actualElapsedSec float64) {
	t.Helper()
	batch, active := buildUnreachableBatch(t, typ, salt, saltMode, numTargets)
	layout := bruteLayout(feasibilityTestCharset, length, length)
	var remaining int64 = int64(len(batch))
	record := batchFeasibilityRecord(batch, &remaining)
	verify := batchFeasibilityVerify(typ, salt, saltMode, batch, active, record)
	probe := batchFeasibilityDispatchProbe(typ, salt, saltMode, layout, active, batch, workers, record, verify)

	rate, ok := feasibilityProbeRate(probe, time.Nanosecond, feasibilityProbeDuration, workers)
	if !ok || rate <= 0 {
		t.Fatalf("feasibilityProbeRate failed for type=%s salt=%q: rate=%v ok=%v", typ, salt, rate, ok)
	}
	predictedETASec = float64(layout.total) / rate

	var realAttempts int64
	start := time.Now()
	ranFast := batchFastLayout(context.Background(), typ, salt, saltMode, layout, active, batch,
		0, 0, workers, &realAttempts, nil, record)
	if !ranFast {
		ranFast = batchStdLayout(context.Background(), typ, layout, active, batch, salt, saltMode,
			0, 0, workers, &realAttempts, nil, record)
	}
	if !ranFast {
		if _, err := runLayout(context.Background(), layout, 0, 0, workers, &realAttempts, nil, verify); err != nil {
			t.Fatalf("real dispatch run: %v", err)
		}
	}
	actualElapsedSec = time.Since(start).Seconds()
	if realAttempts != layout.total {
		t.Fatalf("real run attempted %d candidates, want the full %d-candidate sweep "+
			"(targets are unreachable, so a short count means something else stopped it)",
			realAttempts, layout.total)
	}
	return predictedETASec, actualElapsedSec
}

// TestBatchFeasibilityETAMatchesRealDispatch is the dump-path headline: the
// predicted ETA (from feasibilityProbeRate over the real batch dispatch) must
// be within a sane factor of the real dispatch's actual wall clock, for both
// salted and unsalted md5/md4/ntlm/sha1/sha256 — exactly the matrix the task
// asks improved. Before this task's fix, batch.go always passed probe=nil,
// so this measured benchTarget's generic per-candidate loop instead of the
// batch fast/std path — the same 3x-pessimism regression the single-target
// path already had fixed.
func TestBatchFeasibilityETAMatchesRealDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("times real runs; run without -short to include it")
	}
	const workers = 4
	const numTargets = 5
	const length = 5
	cases := []struct {
		name     string
		typ      string
		salt     string
		saltMode string
	}{
		{"md5 unsalted", "md5", "", "prefix"},
		{"md5 salted", "md5", "deadbeef", "prefix"},
		{"md4 unsalted", "md4", "", "prefix"},
		{"md4 salted", "md4", "deadbeef", "prefix"},
		{"ntlm unsalted", "ntlm", "", "prefix"},
		{"ntlm salted", "ntlm", "deadbeef", "prefix"},
		{"sha1 unsalted", "sha1", "", "prefix"},
		{"sha1 salted", "sha1", "deadbeef", "prefix"},
		{"sha256 unsalted", "sha256", "", "prefix"},
		{"sha256 salted", "sha256", "deadbeef", "prefix"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const attempts = 3
			var best float64 = math.Inf(1)
			var lastPredicted, lastActual float64
			for i := 0; i < attempts; i++ {
				predicted, actual := measureBatchDispatchETA(t, c.typ, c.salt, c.saltMode, length, workers, numTargets)
				if actual <= 0 {
					t.Fatalf("real sweep reported non-positive elapsed time %v", actual)
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
				t.Errorf("%s: best of %d attempts still predicted a dump ETA (%.4gs) %.1fx the real "+
					"batch dispatch's actual time (%.4gs), exceeding the %.0fx tolerance — the dump "+
					"guard is timing the wrong path", c.name, attempts, lastPredicted, best, lastActual, feasibilityETATolerance)
			}
		})
	}
}

// TestBatchFeasibilityProbeBeatsScalarPath proves the fix's premise for the
// dump path — that dispatching through the real batch fast/std path beats
// timing the scalar verify closure — and doubles as the "probe the scalar
// path again" mutation check: if batch.go's probe were changed to call
// runLayout directly instead of batchFastLayout/batchStdLayout, this fails.
func TestBatchFeasibilityProbeBeatsScalarPath(t *testing.T) {
	if runningTranslated() {
		t.Skip("rate comparison is not meaningful under binary translation")
	}
	if racing() {
		// Race instrumentation's per-access overhead does not fall evenly
		// across the batch fast/std dispatch and the scalar verify closure —
		// observed directly developing this test: md5-salted's dispatch/
		// scalar ratio, reliably >1 natively, dropped under 1 under -race.
		// See racing_on.go's doc comment for why that makes this comparison
		// exactly as unreliable as under binary translation.
		t.Skip("rate comparison is not meaningful under the race detector")
	}
	const workers = 4
	const numTargets = 5
	cases := []struct {
		name     string
		typ      string
		salt     string
		saltMode string
		// See feasibility_probe_test.go's identically-named field for why
		// unsalted floors are modest (0.5) and salted floors demand a real
		// speedup (1.2): the salted scalar baseline is the slow, allocating
		// generic path, while the unsalted baseline already is the
		// zero-alloc fast verifier.
		minRatio float64
	}{
		{"md5 unsalted", "md5", "", "prefix", 0.5},
		{"md5 salted", "md5", "deadbeef", "prefix", 1.2},
		{"sha256 unsalted", "sha256", "", "prefix", 0.5},
		{"sha256 salted", "sha256", "deadbeef", "prefix", 1.2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			batch, active := buildUnreachableBatch(t, c.typ, c.salt, c.saltMode, numTargets)
			layout := bruteLayout(feasibilityTestCharset, 5, 5)
			var remaining int64 = int64(len(batch))
			record := batchFeasibilityRecord(batch, &remaining)
			verify := batchFeasibilityVerify(c.typ, c.salt, c.saltMode, batch, active, record)

			dispatchProbe := batchFeasibilityDispatchProbe(c.typ, c.salt, c.saltMode, layout, active, batch, workers, record, verify)
			scalarProbe := batchFeasibilityScalarOnlyProbe(layout, workers, verify)

			dispatchRate, ok1 := feasibilityProbeRate(dispatchProbe, time.Nanosecond, feasibilityProbeDuration, workers)
			scalarRate, ok2 := feasibilityProbeRate(scalarProbe, time.Nanosecond, feasibilityProbeDuration, workers)
			if !ok1 || !ok2 {
				t.Fatalf("probe measurement failed: dispatch ok=%v rate=%v, scalar ok=%v rate=%v",
					ok1, dispatchRate, ok2, scalarRate)
			}
			t.Logf("%s: dispatch %.4g/s, scalar %.4g/s (%.2fx)", c.name, dispatchRate, scalarRate, dispatchRate/scalarRate)
			if dispatchRate < scalarRate*c.minRatio {
				t.Errorf("%s: dispatching through the real batch fast/std path (%.4g/s) should be at "+
					"least %.2fx the scalar verify closure (%.4g/s) — got only %.2fx",
					c.name, dispatchRate, c.minRatio, scalarRate, dispatchRate/scalarRate)
			}
		})
	}
}

// TestBatchFeasibilityETAThroughRunCrack drives a real multi-target dump
// through the actual CLI entry point (runCrack -> crackTargets -> runBatch ->
// batchRunType), not a hand-assembled probe — the one true end-to-end check
// for the dump path, mirroring feasibility_probe_test.go's
// TestFeasibilityETAThroughRunCrack. Only this test can catch batchRunType's
// own probe-construction wiring breaking (e.g. reverted to probe=nil, or
// wired to call runLayout directly).
func TestBatchFeasibilityETAThroughRunCrack(t *testing.T) {
	if testing.Short() {
		t.Skip("times real runs; run without -short to include it")
	}
	preserveExitCode(t)
	dir := t.TempDir()

	var lines []string
	for i := 0; i < 5; i++ {
		target, err := hashText(fmt.Sprintf("batch-cli-unreachable-%d", i), "md5", "deadbeef", "prefix")
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, target)
	}
	targetsFile := filepath.Join(dir, "dump.txt")
	mustWrite(t, targetsFile, strings.Join(lines, "\n")+"\n")

	// Large enough that tier one's cheap single-call estimate cannot resolve
	// this as feasible on its own (see feasibility_probe_test.go's identical
	// reasoning for the single-target CLI test) — this test has to reach
	// tier two, the mechanism batch.go's probe wiring changed.
	const attemptsN = 3
	best := math.Inf(1)
	var lastPredicted, lastActual float64
	for i := 0; i < attemptsN; i++ {
		start := time.Now()
		out, err := captureStderrResult(t, func() error {
			return runCrack([]string{"-t", "md5", "-s", "deadbeef", "-S", "prefix",
				"-M", "brute", "-C", feasibilityTestCharset, "-n", "6", "-x", "6",
				"-p", "4", "--no-pot", targetsFile})
		})
		elapsed := time.Since(start).Seconds()
		if err != nil {
			t.Fatalf("attempt %d/%d: runCrack: %v\n%s", i+1, attemptsN, err, out)
		}
		if !strings.Contains(out, batchBannerPrefix) {
			t.Fatalf("attempt %d/%d: multi-hash mode did not run:\n%s", i+1, attemptsN, out)
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
		t.Errorf("best of %d attempts through runCrack still predicted a dump ETA (%.4gs) %.1fx the "+
			"real elapsed time (%.4gs), exceeding the %.0fx tolerance — the dump guard is timing the "+
			"wrong path again", attemptsN, lastPredicted, best, lastActual, feasibilityETATolerance)
	}
}

// TestBatchFeasibilityMultiSaltDumpPassesMeasuredIndependently is the
// multi-salt property the task calls out explicitly: runBatch groups a dump
// by salt (batchSaltGroups) and calls batchRunType — and so checkFeasibility,
// and so this task's probe — once per distinct salt. A K-salt dump is
// therefore K independent calls, each building its OWN probe over its OWN
// active/batch group (see the doc comment on the probe construction in
// batch.go), not one aggregate estimate stretched across every salt. This
// test proves that directly: two different salt groups (the same shape a
// 2-salt dump's two passes take) are each measured via measureBatchDispatchETA
// — the same accurate, low-noise methodology TestBatchFeasibilityETAMatches
// RealDispatch already validated for a single group — and each must
// independently land within tolerance.
//
// A full CLI run of an actual multi-salt dump, checked for wall-clock
// accuracy per pass, was tried first and discarded: on this suite's shared,
// heavily loaded hardware (load averages in the 100s were observed during
// development), the FIRST pass of a dump measured consistently pessimistic
// (6x-12x, every attempt) while the second measured accurately — not random
// noise, but some cold-start cost (allocation, GC sizing, cache state) that
// lands on whichever pass happens to run first in a fresh process, on top of
// this environment's already-extreme contention. That cost is real but is a
// property of "the first thing this process measures anything", identical in
// kind to what the single-target CLI test already tolerates via retries (see
// TestFeasibilityETAThroughRunCrack) — not something specific to the salt
// grouping this task changed, and pessimism is the SAFE direction besides
// (see feasibility.go: only an optimistic error can cause a false refusal).
// TestBatchFeasibilityETAThroughRunCrack below still proves the CLI wiring
// end-to-end for one pass; this test isolates the multi-salt claim itself
// from that unrelated noise source.
func TestBatchFeasibilityMultiSaltDumpPassesMeasuredIndependently(t *testing.T) {
	if testing.Short() {
		t.Skip("times real runs; run without -short to include it")
	}
	const workers = 4
	const numTargets = 5
	const length = 5
	salts := []string{"deadbeef", "cafebabe"}
	for _, salt := range salts {
		t.Run("salt="+salt, func(t *testing.T) {
			const attempts = 3
			var best float64 = math.Inf(1)
			var lastPredicted, lastActual float64
			for i := 0; i < attempts; i++ {
				predicted, actual := measureBatchDispatchETA(t, "md5", salt, "prefix", length, workers, numTargets)
				if actual <= 0 {
					t.Fatalf("real sweep reported non-positive elapsed time %v", actual)
				}
				ratio := predicted / actual
				t.Logf("salt=%s: attempt %d/%d predicted ETA %.4gs, actual %.4gs, ratio %.2fx",
					salt, i+1, attempts, predicted, actual, ratio)
				lastPredicted, lastActual = predicted, actual
				if ratio < best {
					best = ratio
				}
				if ratio <= feasibilityETATolerance {
					break
				}
			}
			if best > feasibilityETATolerance {
				t.Errorf("salt=%s: best of %d attempts still predicted an ETA (%.4gs) %.1fx this "+
					"group's real dispatch time (%.4gs), exceeding the %.0fx tolerance", salt, attempts,
					lastPredicted, best, lastActual, feasibilityETATolerance)
			}
		})
	}
}

// TestBatchFeasibilityMultiSaltDumpPrintsOnePassPerSalt is a cheap structural
// check (no timing assertions, so no shared-hardware noise to tolerate): a
// real K-salt dump through the CLI must print K separate "Keyspace ... ->
// ETA" lines, one per batchRunType call — proving runBatch's per-salt loop
// (batchSaltGroups) actually reaches this task's probe once per group,
// rather than collapsing to a single aggregate pass. This is also what
// caught a real bug during development of this task: an earlier version of
// this test built its multi-salt fixture with a type/salt combination that
// silently collapsed to ONE salt group instead of two (saltedBatchType
// requires either a named compat type — e.g. "md5-salt-pass" — or a global
// -s to reach the per-target ":salt" split at all; see batch.go), and this
// exact assertion is what caught it.
func TestBatchFeasibilityMultiSaltDumpPrintsOnePassPerSalt(t *testing.T) {
	if testing.Short() {
		t.Skip("times a real run; run without -short to include it")
	}
	preserveExitCode(t)
	dir := t.TempDir()

	// "md5-salt-pass" (salt||pass, i.e. a prefix-salted construction) is one
	// of compatSaltedDigests' explicitly-named salted types — see
	// saltedBatchType's doc comment: batching a dump of bare "hash:salt"
	// lines under a generic "-t md5 -S prefix" requires a GLOBAL -s (one
	// salt for the whole dump; salt=="" && !isCompat routes bare md5/sha1/
	// sha256 to the per-target leftover path instead, see batch.go). The
	// per-target ":salt" split (compatSaltedTargetParts) that gives a K-salt
	// dump its K distinct groups is reached only via one of these named
	// compat types, or a GLOBAL -s (which collapses to K=1 by construction) —
	// so a named compat type is what this test needs to exercise K>1.
	salts := []string{"deadbeef", "cafebabe"}
	var lines []string
	for si, salt := range salts {
		for i := 0; i < 4; i++ {
			target, err := hashText(fmt.Sprintf("multisalt-unreachable-%d-%d", si, i), "md5-salt-pass", salt, "")
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, target+":"+salt)
		}
	}
	targetsFile := filepath.Join(dir, "multisalt.txt")
	mustWrite(t, targetsFile, strings.Join(lines, "\n")+"\n")

	out, err := captureStderrResult(t, func() error {
		// No -s: each "hash:salt" line carries its own salt (see
		// compatSaltedTargetParts), so this dump groups into 2 passes. A
		// small keyspace: this test only checks the NUMBER of ETA lines, not
		// their timing, so it need not run long.
		return runCrack([]string{"-t", "md5-salt-pass",
			"-M", "brute", "-C", "abc", "-n", "3", "-x", "3",
			"-p", "4", "--no-pot", targetsFile})
	})
	if err != nil {
		t.Fatalf("runCrack: %v\n%s", err, out)
	}
	if !strings.Contains(out, batchBannerPrefix) {
		t.Fatalf("multi-hash mode did not run:\n%s", out)
	}
	if n := strings.Count(out, "-> ETA"); n != len(salts) {
		t.Fatalf("expected %d separate ETA lines (one per salt group), got %d:\n%s", len(salts), n, out)
	}
	for _, salt := range salts {
		if !strings.Contains(out, fmt.Sprintf("salt %q", salt)) {
			t.Errorf("expected a banner for salt %q:\n%s", salt, out)
		}
	}
}

// TestBatchFeasibilityRefusesGenuinelyInfeasibleDump proves the guard has not
// become a rubber stamp on the dump path: a batchable-type dump (sha256, so
// this genuinely exercises the NEW probe wiring rather than falling straight
// to the per-target leftover path) with an astronomically large mask must
// still be refused.
//
// The mask is 9 ?a positions — 95^9 = 630,249,409,724,609,375 candidates,
// safely under int64 (no saturation, so this does not fall into the
// unrelated "a saturated keyspace is a lower bound and is never refused by
// this guard" branch documented in checkFeasibility — an EARLIER, longer
// mask used here saturated int64 and consequently never refused, which is
// correct existing behavior but proved nothing about THIS task's change and
// hung the run). At that count, even an implausibly fast 10 GH/s aggregate
// CPU sha256 rate is ~20 years — comfortably past the 1-year limit for any
// real hardware.
func TestBatchFeasibilityRefusesGenuinelyInfeasibleDump(t *testing.T) {
	preserveExitCode(t)
	dir := t.TempDir()

	var lines []string
	for i := 0; i < 3; i++ {
		target, err := hashText(fmt.Sprintf("infeasible-dump-%d", i), "sha256", "", "prefix")
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, target)
	}
	targetsFile := filepath.Join(dir, "dump.txt")
	mustWrite(t, targetsFile, strings.Join(lines, "\n")+"\n")

	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "sha256", "-M", "mask",
			"--mask", "?a?a?a?a?a?a?a?a?a", "--no-pot", targetsFile})
	})
	if err == nil {
		t.Fatalf("expected a feasibility refusal for an astronomically large sha256 dump, got none:\n%s", out)
	}
	if !isFeasibilityRefusal(err) {
		t.Fatalf("expected a feasibilityRefusal, got a different error: %v\n%s", err, out)
	}
	if !strings.Contains(out, batchBannerPrefix) {
		t.Fatalf("expected the dump path (batch.go) to have run, not the per-target leftover path:\n%s", out)
	}
}

// TestBatchFeasibilityUnchangedForNonBatchableSlowKDFDump proves property 5
// on the dump path: bcrypt is not a batchable type (see batchableTypes), so a
// bcrypt dump never reaches batch.go's new probe wiring at all — every
// bcrypt target comes back from runBatch as a leftover and is refused (or
// not) by the untouched single-target guard, exactly as before this task.
func TestBatchFeasibilityUnchangedForNonBatchableSlowKDFDump(t *testing.T) {
	preserveExitCode(t)
	dir := t.TempDir()

	var lines []string
	for i := 0; i < 2; i++ {
		lines = append(lines, testBcryptTarget(t))
	}
	targetsFile := filepath.Join(dir, "bcrypt_dump.txt")
	mustWrite(t, targetsFile, strings.Join(lines, "\n")+"\n")

	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "bcrypt", "-M", "mask",
			"--mask", impossibleMask, "--no-pot", targetsFile})
	})
	if err == nil {
		t.Fatalf("expected a feasibility refusal for an impossible bcrypt dump, got none:\n%s", out)
	}
	if !isFeasibilityRefusal(err) {
		t.Fatalf("expected a feasibilityRefusal, got a different error: %v\n%s", err, out)
	}
	// bcrypt is not batchable: this must NOT have gone through batch.go's
	// dispatch at all — the per-target path handles it, unaffected by this
	// task's change.
	if strings.Contains(out, batchBannerPrefix) {
		t.Fatalf("bcrypt is not batchable — the dump path should never have engaged for it:\n%s", out)
	}
}

// TestBatchFeasibilityNoFalseRefusalForFastPath is the dump-path twin of
// feasibility_probe_test.go's identically-named test: a dump whose true
// (batch fast/std path) ETA is comfortably under the one-year limit must not
// be refused, even though the OLD (pre-fix, probe=nil) estimate for the same
// candidate count would have refused it.
func TestBatchFeasibilityNoFalseRefusalForFastPath(t *testing.T) {
	if runningTranslated() {
		t.Skip("rate comparison is not meaningful under binary translation")
	}
	if racing() {
		// Same reasoning as TestBatchFeasibilityProbeBeatsScalarPath: this
		// test's fastRate-vs-scalarRate margin check compares two different
		// code paths, which -race's uneven per-access overhead can distort
		// exactly as binary translation does.
		t.Skip("rate comparison is not meaningful under the race detector")
	}
	preserveExitCode(t)
	const workers = 4
	const numTargets = 5
	typ, salt, saltMode := "md5", "deadbeef", "prefix"
	batch, active := buildUnreachableBatch(t, typ, salt, saltMode, numTargets)
	// Long enough that no probe sample can ever run past the layout's own
	// total.
	layout := bruteLayout(feasibilityTestCharset, 8, 8)
	var remaining int64 = int64(len(batch))
	record := batchFeasibilityRecord(batch, &remaining)
	verify := batchFeasibilityVerify(typ, salt, saltMode, batch, active, record)
	fastProbe := batchFeasibilityDispatchProbe(typ, salt, saltMode, layout, active, batch, workers, record, verify)

	fastRate, ok := feasibilityProbeRate(fastProbe, time.Nanosecond, feasibilityProbeDuration, workers)
	if !ok || fastRate <= 0 {
		t.Fatalf("fast-path rate measurement failed: rate=%v ok=%v", fastRate, ok)
	}
	scalarRate, ok := feasibilityRate(1<<62, typ, batch[active[0]].norm, salt, saltMode, workers, nil)
	if !ok || scalarRate <= 0 {
		t.Fatalf("scalar-path rate measurement failed: rate=%v ok=%v", scalarRate, ok)
	}
	t.Logf("fast-path rate %.4g/s, scalar-path rate %.4g/s", fastRate, scalarRate)

	ratio := fastRate / scalarRate
	const marginK = 4
	if ratio < 10*marginK {
		t.Skipf("fast-path rate (%.4g/s) is not usefully faster than the scalar-path rate (%.4g/s) "+
			"on this machine — cannot construct a case that separates them with enough margin", fastRate, scalarRate)
	}
	work := int64(scalarRate * feasibilityLimitSeconds * marginK)

	const attempts = 3
	var out string
	var err error
	for i := 0; i < attempts; i++ {
		out, err = captureStderrResult(t, func() error {
			return checkFeasibility(work, false, typ, batch[active[0]].norm, salt, saltMode, workers, false, fastProbe)
		})
		if err == nil {
			break
		}
		t.Logf("attempt %d/%d: fast-path checkFeasibility refused: %v", i+1, attempts, err)
	}
	if err != nil {
		t.Fatalf("a dump whose real fast-path ETA (%.4gs, %.2f%% of the 1-year limit) must not be "+
			"refused, in %d attempts: %v\n%s", float64(work)/fastRate, 100*float64(work)/fastRate/feasibilityLimitSeconds,
			attempts, err, out)
	}
	if !strings.Contains(out, "-> ETA") {
		t.Errorf("a feasible dump must still print an ETA:\n%s", out)
	}

	var errOld error
	refusedOnce := false
	for i := 0; i < attempts; i++ {
		_, errOld = captureStderrResult(t, func() error {
			return checkFeasibility(work, false, typ, batch[active[0]].norm, salt, saltMode, workers, false, nil)
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

// TestBatchFeasibilityStartupCostUnaffected is a fast sanity check (no -short
// skip; must stay cheap) that a trivial dump pays no measurable probe tax: a
// small keyspace resolves on tier one alone (see feasibility.go), so wiring a
// probe into batch.go must not add startup latency to the common case.
func TestBatchFeasibilityStartupCostUnaffected(t *testing.T) {
	preserveExitCode(t)
	dir := t.TempDir()
	var lines []string
	for i := 0; i < 3; i++ {
		target, err := hashText(fmt.Sprintf("trivial-dump-%d", i), "md5", "", "prefix")
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, target)
	}
	targetsFile := filepath.Join(dir, "trivial_dump.txt")
	mustWrite(t, targetsFile, strings.Join(lines, "\n")+"\n")

	start := time.Now()
	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "brute", "-C", "abc", "-n", "3", "-x", "3",
			"--no-pot", targetsFile})
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("runCrack: %v\n%s", err, out)
	}
	// 26 (well, 3-char charset here: 27) candidates resolves on tier one
	// alone; a generous ceiling well under a second catches a probe firing
	// when it should not, without being a flaky wall-clock assertion.
	if elapsed > 2*time.Second {
		t.Errorf("trivial dump took %v — a probe firing on a run tier one already resolved is a "+
			"startup tax this task must not introduce", elapsed)
	}
}
