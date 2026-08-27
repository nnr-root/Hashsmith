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

// benchType times how many candidates all workers verify against a seeded target
// in dur, returning candidates/second.
func benchType(typ string, workers int, dur time.Duration) (float64, bool) {
	target, ok := benchSeed(typ)
	if !ok {
		return 0, false
	}
	// Use the exact verify path the cracker uses: the zero-allocation fast
	// verifier for raw digests, the generic verifier otherwise.
	fv, fast := newFastVerifier(typ, target)

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
				if local&1023 == 0 && time.Now().After(deadline) {
					break
				}
				// vary the candidate so the compiler cannot hoist the hash
				buf[5] = byte('a' + i%26)
				buf[6] = byte('a' + (i/26)%26)
				buf[7] = byte('a' + (i/676)%26)
				if fast {
					fv.match(string(buf))
				} else {
					verifyCandidate(string(buf), target, typ, "", "prefix")
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
		return 0, true
	}
	return float64(atomic.LoadInt64(&count)) / elapsed, true
}
