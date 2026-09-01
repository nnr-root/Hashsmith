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

// checkFeasibility prints the ETA for the work this run will actually do and
// returns a *feasibilityRefusal when that ETA exceeds feasibilityLimitSeconds
// and force is unset.
//
// work is the candidate count this run will attempt — already narrowed to the
// --skip/--limit slice, and already multiplied by the rule expansion in dict
// mode. -1 means "not countable" and math.MaxInt64 means "saturated"; both are
// reported honestly and neither is ever refused.
func checkFeasibility(work int64, bounded bool, typ, target, salt, saltMode string, workers int, force bool) error {
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

	rate, ok := feasibilityRate(work, typ, target, salt, saltMode, workers)
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
//   - Otherwise a real parallel calibration probe runs for
//     feasibilityProbeDuration against that same target, via benchTarget: the
//     same timing path `benchmark` uses, not a second one.
//
// Because tier one only ever ends in "feasible", an inaccurate cheap estimate
// can never produce a false refusal — it can only cost a probe that wasn't
// needed.
func feasibilityRate(work int64, typ, target, salt, saltMode string, workers int) (float64, bool) {
	if _, _, perOp := benchVerifyPath(typ, target, salt, saltMode, feasibilityWarmup); perOp > 0 {
		optimistic := float64(workers) / perOp.Seconds()
		if optimistic > 0 && float64(work)/optimistic < feasibilityRoughCeiling {
			return optimistic, true
		}
	}
	rate := benchTarget(typ, target, salt, saltMode, workers, feasibilityProbeDuration)
	if rate <= 0 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return 0, false
	}
	return rate, true
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
