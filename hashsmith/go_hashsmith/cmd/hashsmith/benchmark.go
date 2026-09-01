package main

// `hashsmith benchmark [-t <type>] [-p workers]` measures cracking throughput
// (candidates per second) for each hash type on this machine, running the real
// verify path across all cores for a fixed time budget. It is the honest way to
// answer "how fast will this crack?" and reflects the fast-digest optimizations.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/bcrypt"
)

// benchDefaultTypes is the curated set shown when no -t is given: the raw digests
// that dominate real workloads, plus bcrypt as a KDF reference point.
var benchDefaultTypes = []string{
	"md5", "sha1", "sha256", "sha512", "sha3_256", "ripemd160",
	"ntlm", "md4", "blake2b", "blake2s", "whirlpool", "streebog256", "bcrypt",
}

func runBenchmark(args []string) error {
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "benchmark a single hash type (default: a common set)")
	workers := fs.Int("p", 0, "parallel workers (0 = NumCPU)")
	secs := fs.Float64("d", 1.0, "seconds per hash type")
	compare := fs.Bool("compare", false, "compare end-to-end recovery time with John and Hashcat")
	compareGPU := fs.Bool("gpu", false, "use Hashsmith GPU dictionary acceleration with --compare")
	candidates := fs.Int("candidates", 100000, "candidate count for --compare")
	repeats := fs.Int("repeat", 3, "measured runs per tool and format for --compare")
	jsonPath := fs.String("json", "", "write --compare results as JSON")
	hashsmithPath := fs.String("hashsmith", "", "Hashsmith executable for --compare (default: current executable)")
	johnPath := fs.String("john", "john", "John executable for --compare")
	hashcatPath := fs.String("hashcat", "hashcat", "Hashcat executable for --compare")
	timeout := fs.Duration("timeout", 2*time.Minute, "timeout per --compare run")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *compare {
		return runComparisonBenchmark(comparisonConfig{
			typ: *typ, candidates: *candidates, repeats: *repeats, jsonPath: *jsonPath,
			hashsmithPath: *hashsmithPath, johnPath: *johnPath, hashcatPath: *hashcatPath,
			timeout: *timeout, hashsmithGPU: *compareGPU,
		})
	}
	w := *workers
	if w < 1 {
		w = runtime.NumCPU()
	}
	dur := time.Duration(*secs * float64(time.Second))

	types := benchDefaultTypes
	if *typ != "" {
		types = []string{*typ}
	}

	color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
		"Benchmark — %d workers, %.1fs per type\n\n", w, *secs)
	for _, t := range types {
		rate, ok := benchType(t, w, dur)
		if !ok {
			fmt.Fprintf(os.Stderr, "  %-14s %s\n", t, clrYellow.Sprint("(not benchmarkable)"))
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-14s %s\n", t, accentSprint(formatRate(rate)))
	}
	return nil
}

// benchSeed produces a valid non-matching target hash for a type so the verify
// path runs at full cost, or (‑, false) if the type cannot be seeded here.
func benchSeed(typ string) (string, bool) {
	if typ == "bcrypt" {
		h, err := bcrypt.GenerateFromPassword([]byte("benchmarkseed"), 10)
		if err != nil {
			return "", false
		}
		return string(h), true
	}
	t, err := hashText("benchmarkseed", typ, "", "prefix")
	if err != nil {
		return "", false
	}
	return t, true
}

// benchProbeCandidate is the candidate benchVerifyPath times one verify of. It
// is a fixed, meaningless string: the point is to pay the algorithm's real
// per-candidate cost, not to match anything.
const benchProbeCandidate = "benchprobe"

// benchVerifyPath resolves the exact verify path the cracker itself would use
// for this type/salt pair — the zero-allocation fast verifier for a
// salt-independent raw digest, the generic verifier otherwise, matching
// doCrack's own choice — and measures what ONE call to it costs.
//
// perOp is the single number both callers need: benchType sizes its
// deadline-check stride from it (so a slow KDF checks every iteration while a
// fast digest is not distorted by time.Now() in the hot loop), and the run
// feasibility guard uses it as a cheap first-order rate estimate so a fast hash
// pays one hash, not a full calibration probe (see checkFeasibility).
//
// minElapsed is how long the timed batch must run before its result is
// trusted; the call count doubles until it does (capped at 8192 calls). Pass 0
// for "one call is enough as long as the clock resolved it at all" — what
// benchType wants, since it only needs an order of magnitude to pick a stride
// and must not pay more than about one extra op before its workers start.
// A caller that needs the number to be an actual rate should pass a real
// budget: one cold call to a raw digest measures cache misses and branch
// mispredicts far more than it measures the hash, and reads hundreds of times
// slower than steady state.
//
// perOp is 0 only when even 8192 calls did not resolve on the clock, which
// callers must treat as "unknown", never as "instant".
func benchVerifyPath(typ, target, salt, saltMode string, minElapsed time.Duration) (fv *fastVerifier, fast bool, perOp time.Duration) {
	// Only an unsalted target can take the fast verifier — the same condition
	// doCrack applies before swapping its verifyFn.
	if salt == "" {
		fv, fast = newFastVerifier(typ, target)
	}
	probe := []byte(benchProbeCandidate)
	for reps := 1; reps <= 8192; reps *= 2 {
		start := time.Now()
		for i := 0; i < reps; i++ {
			if fast {
				fv.matchBytes(probe)
			} else {
				verifyCandidate(benchProbeCandidate, target, typ, salt, saltMode)
			}
		}
		if el := time.Since(start); el > 0 && el >= minElapsed {
			return fv, fast, el / time.Duration(reps)
		}
	}
	return fv, fast, 0
}

// benchType times how many candidates all workers verify against a seeded target
// in dur, returning candidates/second.
func benchType(typ string, workers int, dur time.Duration) (float64, bool) {
	target, ok := benchSeed(typ)
	if !ok {
		return 0, false
	}
	return benchTarget(typ, target, "", "prefix", workers, dur), true
}

// benchTarget is benchType against a caller-supplied target rather than a
// synthetic seed: it measures throughput on the REAL hash a run is about to
// attack, so a KDF's own embedded cost parameter (a bcrypt record's cost, a
// PBKDF2 record's iteration count) is the one being timed — not benchSeed's
// fixed cost-10 stand-in. The feasibility guard needs that; `benchmark`, which
// reports a per-type figure for the machine, does not and keeps the seed.
func benchTarget(typ, target, salt, saltMode string, workers int, dur time.Duration) float64 {
	// Use the exact verify path the cracker uses, and size the deadline-check
	// stride from the measured cost of one op.
	fv, fast, perOp := benchVerifyPath(typ, target, salt, saltMode, 0)
	stride := int64(1)
	if perOp > 0 {
		stride = int64(time.Millisecond / perOp)
	}
	if stride < 1 {
		stride = 1
	}
	if stride > 1024 {
		stride = 1024
	}
	mask := int64(1)
	for mask < stride {
		mask <<= 1
	}
	mask--

	var count int64
	start := time.Now()
	deadline := start.Add(dur)

	var wg sync.WaitGroup
	for id := 0; id < workers; id++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			buf := []byte("benchAAAA")
			var local int64
			i := seed
			for {
				if local&mask == 0 && time.Now().After(deadline) {
					break
				}
				// vary the candidate so the compiler cannot hoist the hash
				buf[5] = byte('a' + i%26)
				buf[6] = byte('a' + (i/26)%26)
				buf[7] = byte('a' + (i/676)%26)
				if fast {
					fv.matchBytes(buf)
				} else {
					verifyCandidate(string(buf), target, typ, salt, saltMode)
				}
				local++
				i++
			}
			atomic.AddInt64(&count, local)
		}(id)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&count)) / elapsed
}
