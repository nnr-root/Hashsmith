package main

// ── Run feasibility guard ────────────────────────────────────────────────────
//
// Before an attack starts, say how long it will take — and refuse to start the
// ones that cannot finish.
//
// `hashsmith crack -t bcrypt -M mask --mask '?a?a?a?a?a?a?a?a' <hash>` is
// 6,634,204,312,890,625 candidates. bcrypt (cost 10) runs at ~45 H/s on a
// typical 8-core machine, so that run needs roughly 4.7 million years. Without
// this guard it starts, prints 0%, and works forever; whenever the operator
// gives up they see "Not found" — indistinguishable from "the password is not
// in this keyspace". That is a plausible answer to a question the tool never
// answered, which is precisely the failure this guard exists to remove.
//
// Three properties matter more than the guard itself:
//
//  1. The estimate covers the work THIS run will do, not the whole keyspace.
//     --skip/--limit bound a run to one slice, and a distributed job splits an
//     enormous keyspace across many machines where every slice is feasible.
//     Estimating from the full keyspace would refuse every distributed run.
//     doCrack passes its already-bounded count in (see the call site).
//
//  2. It never refuses a run that would actually finish. A false refusal blocks
//     legitimate work, which is worse than no guard at all. So: only a real
//     calibration probe can refuse (the cheap first-order estimate below can
//     only ever permit), an unknown keyspace warns instead of refusing, a
//     saturated one warns instead of refusing, a failed probe warns instead of
//     refusing, and the limit sits a hundredfold beyond any real engagement.
//
//  3. It is not a startup tax. The full probe only runs once the cheap
//     estimate says the run is longer than feasibilityRoughCeiling, so a fast
//     hash on an ordinary keyspace pays a single hash, not 150 ms.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// feasibilityLimitSeconds is the ETA above which a run is refused: one
	// year (365.25 days).
	//
	// The choice is deliberately far past anything real rather than "tight but
	// fair". A false refusal is the expensive error here — it blocks work the
	// operator could actually have completed — while a false permit costs only
	// the honest ETA line that was printed anyway. A password audit, a
	// pentest engagement, or a forensic recovery is bounded by weeks, not
	// years; a run projected to still be going a year from now is not a run
	// anyone is waiting on, it is a mistyped mask or a KDF the operator did not
	// realise was slow. Anything genuinely intended to run for years is a
	// distributed job — and those arrive as --skip/--limit slices, which are
	// measured per slice (see hazard 1 above) and so are not refused.
	feasibilityLimitSeconds = 365.25 * 24 * 60 * 60

	// feasibilityLimitLabel names that limit in the refusal message.
	// formatETA is not used for it: formatETA renders anything under two years
	// in days (which is what an operator wants to read for a real ETA), and
	// "exceeds the 365 days feasibility limit" reads like an arbitrary
	// engineering number rather than the deliberate policy it is.
	feasibilityLimitLabel = "1 year"

	// feasibilityRoughCeiling is how short the cheap one-hash estimate must
	// claim a run is before the full calibration probe is skipped. A run the
	// cheap estimate puts under a minute is six orders of magnitude below the
	// limit, so no plausible error in that estimate could turn it into a
	// refusal — and skipping the probe there is what keeps a fast-hash run
	// (and the test suite) free of any measurable startup cost.
	feasibilityRoughCeiling = 60.0

	// feasibilityProbeDuration is the calibration probe's time budget, paid
	// only by runs the cheap estimate already put above feasibilityRoughCeiling
	// — i.e. runs of a minute or more, for which 150 ms is under 0.25%.
	feasibilityProbeDuration = 150 * time.Millisecond

	// feasibilityWarmup is the time budget for the cheap first-tier estimate.
	// A single cold call to a raw digest is dominated by cache misses and
	// branch mispredicts, not by the hash, and reads hundreds of times slower
	// than steady state — which would print an ETA of "4 seconds" for a run
	// that finishes in 10 ms. 100 microseconds is enough calls to reach steady
	// state for a fast digest while still being far too short to notice, and a
	// KDF whose single call already exceeds it pays exactly one call.
	feasibilityWarmup = 100 * time.Microsecond
)

// feasibilityRefusal is the error a refused run returns. It is a distinct type
// so the callers that otherwise swallow a per-type or per-target error and keep
// going (crackWithDetection trying the next candidate type, crackTargets moving
// to the next target) can tell "this run cannot finish" apart from "this hash
// isn't valid for that algorithm" and stop the whole run instead.
type feasibilityRefusal struct{ msg string }

func (e *feasibilityRefusal) Error() string { return e.msg }

// isFeasibilityRefusal reports whether err is (or wraps) a refusal.
func isFeasibilityRefusal(err error) bool {
	var r *feasibilityRefusal
	return errors.As(err, &r)
}

// feasibilityProbe lets a caller hand feasibilityRate a way to measure this
// run's REAL throughput by running the run's own dispatch — the very function
// that will drive the real attack — for a candidate count feasibilityRate
// chooses, rather than feasibility.go re-deriving which internal path (vector
// fast, contiguous batch, scalar) that dispatch would pick. Duplicating that
// choice here is exactly how the estimate went stale the first time: a fast
// path was added to the dispatcher and nothing told the guard about it.
//
// ctx is a defensive time bound (see feasibilityProbeRate); limit is the
// candidate-count bound that actually stops the call, honoured exactly as
// --limit is. It reports how many candidates were attempted. ok is false only
// when this call could not be probed this way at all (wrong mode, a layout
// that failed to build, the dispatch itself erroring) — never to mean "found
// nothing" or "tried zero candidates because the layout is smaller than
// limit"; both of those are normal outcomes reported through attempts, which
// feasibilityProbeRate is the one that decides whether to trust.
type feasibilityProbe func(ctx context.Context, limit int64) (attempts int64, ok bool)

// checkFeasibility prints the ETA for the work this run will actually do and
// returns a *feasibilityRefusal when that ETA exceeds feasibilityLimitSeconds
// and force is unset.
//
// work is the candidate count this run will attempt — already narrowed to the
// --skip/--limit slice, and already multiplied by the rule expansion in dict
// mode. -1 means "not countable" and math.MaxInt64 means "saturated"; both are
// reported honestly and neither is ever refused.
//
// probe is optional (nil for any caller/mode that has no real-dispatch path
// to offer, e.g. dict, hybrid, markov, combinator, prince, or a brute/mask
// call whose layout could not be built) — feasibilityRate falls back to
// benchTarget exactly as before whenever it is nil.
func checkFeasibility(work int64, bounded bool, typ, target, salt, saltMode string, workers int, force bool, probe feasibilityProbe) error {
	if work == 0 {
		return nil
	}
	if work < 0 {
		clrYellow.Fprintln(os.Stderr,
			"Keyspace unknown (not countable in advance) — cannot estimate an ETA for this run; starting anyway")
		return nil
	}
	if workers < 1 {
		workers = 1
	}
	// A saturated count is a lower bound, not a measurement: the true keyspace
	// is larger than int64 can hold and the engine will only ever cover the
	// first math.MaxInt64 candidates (warnKeyspaceNotExhaustive has already
	// said so). Report the ETA as a floor and do not refuse on a number that
	// isn't the real one.
	lowerBound := work == math.MaxInt64

	rate, ok := feasibilityRate(work, typ, target, salt, saltMode, workers, probe)
	if !ok {
		clrYellow.Fprintf(os.Stderr,
			"Could not measure %s throughput on this machine — no ETA for this run; starting anyway\n", typ)
		return nil
	}
	eta := float64(work) / rate

	atLeast := ""
	if lowerBound {
		atLeast = "at least "
	}
	fmt.Fprintf(os.Stderr, "Keyspace %s%s%s at ~%s -> ETA %s\n",
		atLeast, groupThousands(work), feasibilityScope(bounded),
		formatRate(rate), etaPhrase(eta, lowerBound))

	if eta <= feasibilityLimitSeconds || lowerBound {
		return nil
	}
	if force {
		clrYellow.Fprintln(os.Stderr,
			"--force given — starting a run that is not expected to finish")
		return nil
	}
	return &feasibilityRefusal{msg: fmt.Sprintf(
		"this run cannot finish: ETA %s exceeds the %s feasibility limit "+
			"(%s candidates%s at ~%s).\n"+
			"  Narrow it (a shorter mask, a smaller charset, a wordlist instead of brute force), "+
			"split it across machines with --skip/--limit, or pass --force to start it anyway.",
		etaPhrase(eta, false), feasibilityLimitLabel,
		groupThousands(work), feasibilityScope(bounded), formatRate(rate))}
}

// feasibilityRate estimates this machine's throughput on the REAL target — its
// actual type and, for a KDF, its actual embedded cost — in candidates/second.
//
// It has two tiers, and only the second one can lead to a refusal:
//
//   - One verify call is timed (benchVerifyPath, the same measurement benchType
//     makes to size its stride). Divided into the worker count that gives an
//     optimistic ceiling on throughput, hence an optimistic FLOOR on the ETA.
//     If even that floor puts the run under feasibilityRoughCeiling, the run is
//     feasible by six orders of magnitude and the estimate is returned as-is —
//     one hash, no probe.
//   - Otherwise a real calibration probe runs for about feasibilityProbeDuration
//     against that same target. When the caller supplied one, that probe is
//     `probe` itself — the run's own dispatch, timed by feasibilityProbeRate —
//     since that is the path a brute/mask run actually takes and it can be a
//     batch fast path many times quicker than a per-candidate verify closure
//     (see the package doc at the top of this file). Every other mode has no
//     such dispatch to offer (probe is nil) and falls back to benchTarget: the
//     same timing path `benchmark` uses, which is exactly right for those
//     modes since they always run the generic verify closure anyway.
//
// Because tier one only ever ends in "feasible", an inaccurate cheap estimate
// can never produce a false refusal — it can only cost a probe that wasn't
// needed.
//
// One consequence worth knowing before you go optimizing this. Tier one
// short-circuits whenever its estimate puts the run under
// feasibilityRoughCeiling, so for any run of roughly a minute or less, tier
// two never executes and the PRINTED rate is tier one's — derived from a
// single scalar verify call. Since the batch and vector dispatches are
// several times faster than workers*scalar-verify, that number reads several
// times pessimistic on short runs: a two-second dump sweep announced as five.
// Nobody is harmed (the ETA cannot trigger a refusal from tier one, and the
// run finishes before anyone reads it), but it does mean a short run is the
// WRONG thing to measure when judging this estimator. Measure something that
// takes long enough for tier two to run: on an 8-billion-candidate dump the
// probe lands within about 14% of the real rate, against 5.7x pessimistic
// before it existed.
func feasibilityRate(work int64, typ, target, salt, saltMode string, workers int, probe feasibilityProbe) (float64, bool) {
	_, _, perOp := benchVerifyPath(typ, target, salt, saltMode, feasibilityWarmup)
	if perOp > 0 {
		optimistic := float64(workers) / perOp.Seconds()
		if optimistic > 0 && float64(work)/optimistic < feasibilityRoughCeiling {
			return optimistic, true
		}
	}
	if rate, ok := feasibilityProbeRate(probe, perOp, feasibilityProbeDuration, workers); ok {
		return rate, true
	}
	rate := benchTarget(typ, target, salt, saltMode, workers, feasibilityProbeDuration)
	if rate <= 0 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return 0, false
	}
	return rate, true
}

// feasibilityProbeRate measures this run's real throughput via probe — the
// SAME dispatch the run itself will use — instead of benchTarget's own
// hand-rolled verify loop, so a batch fast path is timed as the batch fast
// path actually runs, not as the generic per-candidate closure it can be many
// times faster than.
//
// perOp (tier one's single-op measurement, on this same target) sizes the
// first attempt's TOTAL candidate limit across every worker: candidates =
// workers x budget/perOp assumes probe can go no faster, per worker, than the
// scalar verify tier one just measured. That is exactly true whenever probe
// ends up on its own scalar fallback, and an UNDERESTIMATE whenever it
// reaches a faster batch path — an underestimate only shortens the call,
// never lengthens it.
//
// The `workers` factor matters because the limit is a shared TOTAL the
// workers race to consume in keyspaceChunk-sized pieces, mirroring
// runBruteOrMaskLayout's own chunk allocator: sizing it as if there were only
// one worker starves the others, which finish their share of a tiny total
// almost immediately and sit idle, collapsing the measured rate toward
// single-worker throughput. But that allocator also sets a floor under what
// this function can safely attempt: a chunk (keyspaceChunk candidates) is the
// smallest unit of work a worker ever claims, so probing at all only makes
// sense when a whole chunk fits inside budget — feasibilityProbeChunkFits
// below is that gate. A slow KDF (bcrypt, sha512crypt, PBKDF2) fails it by
// design: bcrypt alone costs single-digit milliseconds a call, so one 4096-
// candidate chunk would take seconds, far past a 150ms budget. Below that
// gate this function declines outright (ok=false) rather than force a
// limit too small to fill a chunk — which, exactly as sizing without the
// `workers` factor did, would run only one worker and under-measure by
// roughly the worker count — leaving benchTarget (parallel and
// chunk-granularity-free) to measure those exactly as it always did. That is
// what keeps a slow KDF's estimate unchanged by this whole mechanism.
//
// The limit is doubled — exactly as benchVerifyPath doubles its own call
// count — whenever the previous attempt's elapsed time is too short to trust
// (a batch fast path can clear the first, conservative limit in
// microseconds); a ctx shared across every attempt caps the whole loop at
// budget, so a string of doublings cannot add up to more than about one
// budget's worth of wall clock.
//
// ok is false when probe is nil, perOp could not be measured (tier one itself
// found nothing to size from), perOp fails the chunk-fits gate above, or
// budget elapsed without ever producing a trustworthy measurement —
// feasibilityRate falls back to benchTarget in every such case, so a probe
// that cannot answer confidently never turns into a worse estimate than
// today's.
func feasibilityProbeRate(probe feasibilityProbe, perOp, budget time.Duration, workers int) (float64, bool) {
	if probe == nil || perOp <= 0 || budget <= 0 || !feasibilityProbeChunkFits(perOp, budget) {
		return 0, false
	}
	if workers < 1 {
		workers = 1
	}
	limit := int64(workers) * int64(budget.Seconds()/perOp.Seconds())
	if limit < int64(workers) {
		limit = int64(workers)
	}
	// Guards a pathological perOp (e.g. sub-nanosecond, from clock noise on an
	// unusual platform) from sizing an unbounded limit; never reached by any
	// real algorithm.
	const maxLimit = int64(1) << 40
	minElapsed := budget / 8

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	for {
		start := time.Now()
		attempts, ok := probe(ctx, limit)
		elapsed := time.Since(start)
		if !ok {
			return 0, false
		}
		if attempts > 0 && elapsed > 0 && (elapsed >= minElapsed || ctx.Err() != nil) {
			return float64(attempts) / elapsed.Seconds(), true
		}
		if ctx.Err() != nil || limit >= maxLimit {
			return 0, false
		}
		limit *= 2
	}
}

// feasibilityProbeChunkFits reports whether a single keyspaceChunk of
// candidates, at cost perOp each, fits comfortably inside budget. It is
// feasibilityProbeRate's gate for whether probing the real dispatch can work
// at all: runLayout/runLayoutFast/runLayoutStdSingle only ever hand a worker
// a whole chunk at a time (see keyspace.go), so a type whose chunk does not
// fit in budget can never be measured with more than one worker active
// inside budget, no matter how the candidate limit is sized. "Comfortably"
// is a quarter of budget, not all of it: a probe that only just fits one
// chunk still has no room to double if that first attempt is too short to
// trust (see feasibilityProbeRate), so this leaves headroom for at least one
// doubling before the shared ctx would cut it off.
func feasibilityProbeChunkFits(perOp, budget time.Duration) bool {
	return perOp > 0 && perOp*keyspaceChunk <= budget/4
}

// feasibilityScope labels a run narrowed by --skip/--limit, so the printed
// count is not mistaken for the whole keyspace.
func feasibilityScope(bounded bool) string {
	if bounded {
		return " (this run's --skip/--limit slice)"
	}
	return ""
}

// etaPhrase is formatETA with the qualifier the number deserves: "~" for an
// estimate, "at least ~" for one computed from a saturated (lower-bound)
// keyspace, and no tilde at all below a second, where decorating the number
// would be sillier than the number.
func etaPhrase(sec float64, lowerBound bool) string {
	switch {
	case sec < 1:
		return "under 1 second"
	case lowerBound:
		return "at least ~" + formatETA(sec)
	default:
		return "~" + formatETA(sec)
	}
}

// formatETA renders a duration in seconds as a coarse, human phrase. It takes a
// float64 rather than a time.Duration on purpose: a time.Duration tops out at
// ~292 years, and the runs this guard exists to catch are measured in millions.
func formatETA(sec float64) string {
	switch {
	case sec < 1:
		return "under 1 second"
	case sec < 120:
		return plural(sec, "second")
	case sec < 2*60*60:
		return plural(sec/60, "minute")
	case sec < 48*60*60:
		return plural(sec/(60*60), "hour")
	case sec < 2*feasibilityLimitSeconds:
		return plural(sec/(24*60*60), "day")
	default:
		years := sec / feasibilityLimitSeconds
		if years >= 1e18 {
			return fmt.Sprintf("%.3g years", years)
		}
		return plural(years, "year")
	}
}

// plural rounds n to a whole number, groups it, and appends unit with an "s"
// unless the rounded value is exactly one.
func plural(n float64, unit string) string {
	r := int64(n + 0.5)
	if r == 1 {
		return "1 " + unit
	}
	return groupThousands(r) + " " + unit + "s"
}

// groupThousands renders n in decimal with thousands separators, so a
// sixteen-digit keyspace is readable at a glance rather than a wall of digits.
func groupThousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
