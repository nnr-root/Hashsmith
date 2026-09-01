package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// impossibleMask is the motivating case: eight ?a positions is
// 6,634,204,312,890,625 candidates, which at bcrypt speeds is millions of
// years. Before the feasibility guard this run started, printed 0%, and ran
// forever — and whenever the operator gave up, "Not found" was
// indistinguishable from "the password is not in this keyspace".
const impossibleMask = "?a?a?a?a?a?a?a?a"

const impossibleMaskKeyspace = int64(6634204312890625)

// testBcryptTarget is a real bcrypt record at the cheapest cost the algorithm
// allows. Cost matters here: the guard probes the ACTUAL target, so a cost-4
// record keeps the test fast while still being hundreds of thousands of times
// too slow to sweep impossibleMask.
func testBcryptTarget(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("not-the-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt seed: %v", err)
	}
	return string(h)
}

// captureStderrResult is captureStderr for a call that is EXPECTED to fail:
// it returns the error rather than failing the test on it.
func captureStderrResult(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	done := make(chan string)
	go func() {
		var sb strings.Builder
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			sb.WriteString(sc.Text())
			sb.WriteByte('\n')
		}
		done <- sb.String()
	}()
	err := fn()
	w.Close()
	os.Stderr = old
	return <-done, err
}

// preserveExitCode restores the exitCode global, which crackTargets sets as a
// side effect of any run that leaves a target uncracked.
func preserveExitCode(t *testing.T) {
	t.Helper()
	saved := exitCode
	t.Cleanup(func() { exitCode = saved })
}

// keyspaceLineRE matches the ETA line's candidate count, with its thousands
// separators, so a test can assert on the number the guard actually estimated
// over.
var keyspaceLineRE = regexp.MustCompile(`Keyspace ([0-9,]+)`)

// estimatedKeyspace pulls the candidate count out of the guard's ETA line.
func estimatedKeyspace(t *testing.T, stderr string) int64 {
	t.Helper()
	m := keyspaceLineRE.FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("no feasibility ETA line in output:\n%s", stderr)
	}
	n, err := strconv.ParseInt(strings.ReplaceAll(m[1], ",", ""), 10, 64)
	if err != nil {
		t.Fatalf("unparsable keyspace %q: %v", m[1], err)
	}
	return n
}

// TestImpossibleRunIsRefusedWithAnETA is the headline behavior: a run that
// cannot finish is refused before it starts, with the ETA that justifies the
// refusal, rather than running forever and ending in a misleading "Not found".
func TestImpossibleRunIsRefusedWithAnETA(t *testing.T) {
	preserveExitCode(t)
	target := testBcryptTarget(t)

	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "bcrypt", "-M", "mask", "--mask", impossibleMask,
			"--no-pot", target})
	})
	if err == nil {
		t.Fatalf("an attack needing millions of years must be refused, not started; stderr:\n%s", out)
	}
	if !isFeasibilityRefusal(err) {
		t.Fatalf("refusal must be a *feasibilityRefusal so callers can tell it from a "+
			"per-type format error; got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "years") {
		t.Errorf("refusal must state the ETA it is refusing on; got: %v", err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("refusal must name the override that starts the run anyway; got: %v", err)
	}
	if got := estimatedKeyspace(t, out); got != impossibleMaskKeyspace {
		t.Errorf("estimated over %d candidates, want the mask's %d", got, impossibleMaskKeyspace)
	}
}

// TestForceStartsARefusedRun locks --force: the ETA is still measured and
// printed (the guard's honesty is not what --force turns off), but the run is
// permitted.
func TestForceStartsARefusedRun(t *testing.T) {
	target := testBcryptTarget(t)

	out, err := captureStderrResult(t, func() error {
		return checkFeasibility(impossibleMaskKeyspace, false, "bcrypt", target, "", "prefix", 4, true)
	})
	if err != nil {
		t.Fatalf("--force must start the run, got refusal: %v", err)
	}
	if !strings.Contains(out, "-> ETA") {
		t.Errorf("--force must still print the ETA — it suppresses the refusal, not the truth:\n%s", out)
	}
	if !strings.Contains(out, "--force") {
		t.Errorf("a forced run must say it is proceeding on --force:\n%s", out)
	}
}

// TestFeasibilityEstimatesTheSliceNotTheWholeKeyspace is the distributed-run
// guarantee. --skip/--limit bound a run to one slice of a keyspace that may be
// astronomically large in total; every slice may be trivially feasible. An ETA
// computed from the FULL keyspace would refuse every distributed run and break
// the distribution features outright.
//
// This asserts both halves: the estimate is over the slice's size, and the run
// is not refused.
func TestFeasibilityEstimatesTheSliceNotTheWholeKeyspace(t *testing.T) {
	preserveExitCode(t)
	target := testBcryptTarget(t)

	const slice = 3
	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "bcrypt", "-M", "mask", "--mask", impossibleMask,
			"--skip", "4000000000000", "--limit", strconv.Itoa(slice), "--no-pot", target})
	})
	if err != nil {
		t.Fatalf("a %d-candidate slice of a huge keyspace must run, not be refused: %v\n%s",
			slice, err, out)
	}
	got := estimatedKeyspace(t, out)
	if got == impossibleMaskKeyspace {
		t.Fatalf("the ETA was estimated over the whole %d-candidate keyspace instead of the "+
			"--skip/--limit slice — that refuses every distributed run", impossibleMaskKeyspace)
	}
	if got != slice {
		t.Fatalf("estimated over %d candidates, want the slice's %d", got, slice)
	}
	if !strings.Contains(out, "--skip/--limit slice") {
		t.Errorf("a bounded run's count must be labelled as a slice so it is not read as the "+
			"whole keyspace:\n%s", out)
	}
}

// TestFeasibilityETAMultipliesDictWordsByRules locks the deliberate
// disagreement between two numbers that look like they should match:
//
//   - --keyspace reports WORDS. That is --skip/--limit's unit — slicing moves
//     whole words, each carrying its full rule expansion — and
//     TestKeyspaceUnitIsSkipStepsToCoverDictRun locks it.
//   - the ETA is about TIME, and a dict run with rules spends it on
//     words × (1 + rules), because every word is tried with every rule.
//
// Both numbers are right for their own question. This test pins each to its
// own answer, so neither can be "fixed" into the other.
func TestFeasibilityETAMultipliesDictWordsByRules(t *testing.T) {
	preserveExitCode(t)
	dir := t.TempDir()
	wl := filepath.Join(dir, "words.txt")
	words := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	mustWrite(t, wl, strings.Join(words, "\n")+"\n")

	// An md5 target no rule expansion of the list above produces, so the run
	// sweeps the whole thing.
	target, err := hashText("no-word-mangles-to-this-xyzzy", "md5", "", "prefix")
	if err != nil {
		t.Fatal(err)
	}

	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "-r", "--no-pot", target})
	})
	if err != nil {
		t.Fatalf("runCrack: %v\n%s", err, out)
	}
	want := int64(len(words)) * int64(1+NumManglingRules)
	if got := estimatedKeyspace(t, out); got != want {
		t.Fatalf("dict ETA estimated over %d candidates, want words x rules = %d x %d = %d — "+
			"dict-mode TIME is words times rules, even though --keyspace deliberately "+
			"reports words alone", got, len(words), 1+NumManglingRules, want)
	}

	// ...and --keyspace still reports the word count, unmultiplied.
	ks := captureStdout(t, func() error {
		return runCrack([]string{"-M", "dict", "-w", wl, "-r", "--keyspace"})
	})
	if strings.TrimSpace(ks) != strconv.Itoa(len(words)) {
		t.Fatalf("--keyspace must still report %d words (its value is --skip/--limit's unit "+
			"and must not change); got %q", len(words), strings.TrimSpace(ks))
	}
}

// TestFeasibilityNeverRefusesWhatItCannotMeasure covers the bias that matters
// most: a false refusal blocks legitimate work, so anything the guard cannot
// put a trustworthy number on warns and proceeds.
func TestFeasibilityNeverRefusesWhatItCannotMeasure(t *testing.T) {
	target := testBcryptTarget(t)

	t.Run("unknown keyspace", func(t *testing.T) {
		out, err := captureStderrResult(t, func() error {
			// -1 is countWordlistLines' "not countable in advance" sentinel
			// (a pipe, stdin, /dev/fd/N).
			return checkFeasibility(-1, false, "bcrypt", target, "", "prefix", 4, false)
		})
		if err != nil {
			t.Fatalf("an uncountable keyspace must warn, not refuse: %v", err)
		}
		if !strings.Contains(out, "unknown") {
			t.Errorf("an uncountable keyspace must say so:\n%s", out)
		}
	})

	t.Run("saturated keyspace", func(t *testing.T) {
		out, err := captureStderrResult(t, func() error {
			return checkFeasibility(math.MaxInt64, false, "bcrypt", target, "", "prefix", 4, false)
		})
		if err != nil {
			t.Fatalf("a saturated keyspace is a lower bound, not a measurement — it must "+
				"warn, not refuse: %v", err)
		}
		if !strings.Contains(out, "at least") {
			t.Errorf("a saturated count must be reported as a floor:\n%s", out)
		}
	})

	t.Run("empty keyspace", func(t *testing.T) {
		out, err := captureStderrResult(t, func() error {
			return checkFeasibility(0, false, "bcrypt", target, "", "prefix", 4, false)
		})
		if err != nil {
			t.Fatalf("nothing to attempt must never be refused: %v", err)
		}
		if strings.Contains(out, "ETA") {
			t.Errorf("no work means no ETA to print:\n%s", out)
		}
	})
}

// TestNonAttackModesNeverEstimate: --keyspace, --stdout and --show launch no
// attack, so none of them may probe, print an ETA, or be refused — however
// impossible the keyspace they name.
func TestNonAttackModesNeverEstimate(t *testing.T) {
	preserveExitCode(t)
	target := testBcryptTarget(t)

	cases := []struct {
		name string
		args []string
	}{
		{"keyspace", []string{"-t", "bcrypt", "-M", "mask", "--mask", impossibleMask, "--keyspace"}},
		{"stdout", []string{"-M", "mask", "--mask", "?d?d", "--stdout"}},
		{"show", []string{"-t", "bcrypt", "--show", "--no-pot", target}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out string
			var err error
			// --keyspace and --stdout write their real output to stdout;
			// swallow it so it does not pollute the test log.
			_ = captureStdout(t, func() error {
				out, err = captureStderrResult(t, func() error { return runCrack(tc.args) })
				return nil
			})
			if err != nil {
				t.Fatalf("%s must not be refused: %v", tc.name, err)
			}
			if strings.Contains(out, "-> ETA") {
				t.Errorf("%s runs no attack, so it must not print an ETA:\n%s", tc.name, out)
			}
		})
	}
}

// TestFeasibilityProbeIsNotAStartupTax: a fast hash on an ordinary keyspace
// must resolve on the cheap one-shot estimate, never the full calibration
// probe. Without this the guard would add feasibilityProbeDuration to every
// md5 run — and to every test in this suite.
func TestFeasibilityProbeIsNotAStartupTax(t *testing.T) {
	target, err := hashText("startup-tax", "md5", "", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rate, ok := feasibilityRate(1_000_000, "md5", target, "", "prefix", 4)
	elapsed := time.Since(start)
	if !ok || rate <= 0 {
		t.Fatalf("md5 rate estimate failed (rate=%v ok=%v)", rate, ok)
	}
	// Half the probe budget: comfortably above the cheap estimate's ~100us and
	// comfortably below a full probe, so this fails only if the probe ran.
	if limit := feasibilityProbeDuration / 2; elapsed > limit {
		t.Fatalf("estimating a feasible md5 run took %v (limit %v) — the full calibration "+
			"probe ran when the cheap estimate should have settled it", elapsed, limit)
	}
}

// TestFeasibilityAlwaysPrintsAnETA: the ETA line is not just a refusal
// message. A run that IS feasible must still say how long it will take,
// because "how long will this take" is the question a cracker exists to
// answer and the operator should not have to guess.
func TestFeasibilityAlwaysPrintsAnETA(t *testing.T) {
	preserveExitCode(t)
	dir := t.TempDir()
	wl := filepath.Join(dir, "words.txt")
	mustWrite(t, wl, "alpha\nbeta\ngamma\n")
	target, err := hashText("gamma", "md5", "", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot", target})
	})
	if err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if !strings.Contains(out, "-> ETA") {
		t.Fatalf("every attack must announce its ETA before it starts:\n%s", out)
	}
}

func TestFormatETAAndGroupThousands(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		want string
	}{
		{0, "0"}, {7, "7"}, {999, "999"}, {1000, "1,000"},
		{6634204312890625, "6,634,204,312,890,625"}, {-4321, "-4,321"},
	} {
		if got := groupThousands(tc.n); got != tc.want {
			t.Errorf("groupThousands(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
	for _, tc := range []struct {
		sec  float64
		want string
	}{
		{0.4, "under 1 second"},
		{1, "1 second"},
		{95, "95 seconds"},
		{3600, "60 minutes"},
		{3 * 24 * 3600, "3 days"},
		{feasibilityLimitSeconds * 4_700_000, "4,700,000 years"},
	} {
		if got := formatETA(tc.sec); got != tc.want {
			t.Errorf("formatETA(%v) = %q, want %q", tc.sec, got, tc.want)
		}
	}
	// A time.Duration would have overflowed long before this; the guard's
	// whole point is naming numbers that big.
	if got := formatETA(1.48e14); !strings.HasSuffix(got, "years") {
		t.Errorf("formatETA(1.48e14) = %q, want a figure in years", got)
	}
}

// TestBenchTargetTimesTheGivenTarget guards the reuse that makes the estimate
// honest: benchType keeps benchSeed's synthetic cost-10 stand-in (it reports a
// per-type figure for the machine), while the guard measures the operator's
// ACTUAL record — so a cost-12 bcrypt is estimated at cost-12 speed, not
// cost-10 speed.
func TestBenchTargetTimesTheGivenTarget(t *testing.T) {
	cheap, err := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	dear, err := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost+4)
	if err != nil {
		t.Fatal(err)
	}
	_, _, cheapOp := benchVerifyPath("bcrypt", string(cheap), "", "prefix", 0)
	_, _, dearOp := benchVerifyPath("bcrypt", string(dear), "", "prefix", 0)
	// Each extra cost step doubles the work; four steps is 16x, so even a very
	// noisy machine clears 4x.
	if dearOp < 4*cheapOp {
		t.Fatalf("cost %d verify took %v and cost %d took %v — the probe is not timing the "+
			"target's own cost parameter", bcrypt.MinCost, cheapOp, bcrypt.MinCost+4, dearOp)
	}
}

// TestFeasibilityRefusalStopsEveryTarget: a refusal is about the attack, not
// about one target or one candidate type, so it must abort the whole run
// instead of being logged per target and ending in "Not found".
func TestFeasibilityRefusalStopsEveryTarget(t *testing.T) {
	preserveExitCode(t)
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	a := testBcryptTarget(t)
	b, err := bcrypt.GenerateFromPassword([]byte("other"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, targets, fmt.Sprintf("%s\n%s\n", a, string(b)))

	out, err := captureStderrResult(t, func() error {
		return runCrack([]string{"-t", "bcrypt", "-M", "mask", "--mask", impossibleMask,
			"--no-pot", targets})
	})
	if err == nil || !isFeasibilityRefusal(err) {
		t.Fatalf("a multi-target run must surface the refusal, not swallow it per target "+
			"and report Not found; got err=%v\n%s", err, out)
	}
}
