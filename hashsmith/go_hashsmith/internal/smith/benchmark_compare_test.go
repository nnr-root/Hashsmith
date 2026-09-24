package smith

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComparisonCases(t *testing.T) {
	want := map[string][2]string{
		"md5": {"raw-md5", "0"}, "md4": {"raw-md4", "900"}, "ntlm": {"nt", "1000"},
		"sha1": {"raw-sha1", "100"}, "sha256": {"raw-sha256", "1400"},
	}
	for _, c := range comparisonCases {
		if got, ok := want[c.typ]; !ok || got != [2]string{c.johnFormat, c.hashcatMode} {
			t.Errorf("unexpected comparison mapping: %#v", c)
		}
	}
	if _, err := selectComparisonCases("hashcat:0"); err != nil {
		t.Fatalf("Hashcat alias should select MD5: %v", err)
	}
	if _, err := selectComparisonCases("bcrypt"); err == nil {
		t.Fatal("unsupported comparison type was accepted")
	}
}

func TestComparisonWordlistAndMedian(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := writeComparisonWordlist(path, 4); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 4 || lines[3] != comparisonPassword || lines[0] != "hsb000000000" {
		t.Fatalf("unexpected comparison wordlist: %q", lines)
	}
	if got := medianSeconds([]float64{9, 1, 3}); got != 3 {
		t.Fatalf("odd median = %v", got)
	}
	if got := medianSeconds([]float64{4, 2}); got != 3 {
		t.Fatalf("even median = %v", got)
	}
}

func TestComparisonProof(t *testing.T) {
	if !comparisonProof("hashsmith", comparisonPassword, "Found: "+comparisonPassword+"\n") {
		t.Fatal("Hashsmith proof was not recognized")
	}
	proof := filepath.Join(t.TempDir(), "result.txt")
	if err := os.WriteFile(proof, []byte("hash:"+comparisonPassword+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !comparisonProof("john", proof, "") || !comparisonProof("hashcat", proof, "") {
		t.Fatal("file proof was not recognized")
	}
}

func TestComparisonCommandEnablesHashsmithGPUOnly(t *testing.T) {
	c := comparisonCases[0]
	hashsmithArgs, _ := comparisonCommand("hashsmith", c, "target", "target.txt", "words.txt", t.TempDir(), 0, true, 1)
	if !containsString(hashsmithArgs, "--gpu") {
		t.Fatalf("Hashsmith args do not enable GPU: %q", hashsmithArgs)
	}
	johnArgs, _ := comparisonCommand("john", c, "target", "target.txt", "words.txt", t.TempDir(), 0, true, 1)
	if containsString(johnArgs, "--gpu") {
		t.Fatalf("Hashsmith GPU flag leaked into John args: %q", johnArgs)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestComparisonMissingToolsAreSkipped(t *testing.T) {
	jsonPath := filepath.Join(t.TempDir(), "report.json")
	err := runComparisonBenchmark(comparisonConfig{
		typ: "md5", candidates: 2, repeats: 1, jsonPath: jsonPath,
		hashsmithPath: "hashsmith-does-not-exist", johnPath: "john-does-not-exist", hashcatPath: "hashcat-does-not-exist",
		timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var report comparisonReport
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != 1 || report.Cases[0].Tools["hashsmith"].Status != "skipped" || report.Candidates != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

// TestComparisonGivesJohnEveryCore is a fairness property, not a feature test.
// Hashsmith saturates every core by default; John is single-threaded unless
// told otherwise. Timing an 8-core tool against a 1-core tool and publishing
// the ratio would inflate Hashsmith's margin by roughly the core count, so the
// harness must hand John --fork with the same parallelism Hashsmith gets.
func TestComparisonGivesJohnEveryCore(t *testing.T) {
	c := comparisonCases[0]
	johnArgs, _ := comparisonCommand("john", c, "target", "target.txt", "words.txt", t.TempDir(), 0, false, 8)
	if !containsString(johnArgs, "--fork=8") {
		t.Fatalf("John args do not request all cores: %q", johnArgs)
	}
}

// TestComparisonOmitsForkOnSingleCore keeps the flag off where it is invalid.
func TestComparisonOmitsForkOnSingleCore(t *testing.T) {
	c := comparisonCases[0]
	johnArgs, _ := comparisonCommand("john", c, "target", "target.txt", "words.txt", t.TempDir(), 0, false, 1)
	for _, a := range johnArgs {
		if strings.HasPrefix(a, "--fork") {
			t.Fatalf("--fork must not be passed on a single core: %q", johnArgs)
		}
	}
}

// TestComparisonForkAppliesOnlyToJohn guards against the flag leaking into the
// other two tools, which do their own thread management.
func TestComparisonForkAppliesOnlyToJohn(t *testing.T) {
	c := comparisonCases[0]
	for _, name := range []string{"hashsmith", "hashcat"} {
		args, _ := comparisonCommand(name, c, "target", "target.txt", "words.txt", t.TempDir(), 0, false, 8)
		for _, a := range args {
			if strings.HasPrefix(a, "--fork") {
				t.Fatalf("%s args must not contain --fork: %q", name, args)
			}
		}
	}
}

// TestWriteMissWordlist guards the property measureStartupOverhead depends
// on: none of these candidates may equal comparisonPassword (or the
// benchmark harness's target could accidentally get "found" during an
// overhead probe, turning a startup measurement into a real timed run).
func TestWriteMissWordlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "miss.txt")
	if err := writeMissWordlist(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		t.Fatal("miss wordlist is empty")
	}
	for _, line := range lines {
		if line == comparisonPassword {
			t.Fatalf("miss wordlist must never contain the real target password: %q", lines)
		}
		if line == "" {
			t.Fatalf("miss wordlist must not contain a blank candidate: %q", lines)
		}
	}
}

// TestAdjustForStartupNegligibleOverhead covers the common case: a fast
// overhead relative to the run should barely move the throughput number,
// should never be flagged as startup-dominated, and should be reported.
func TestAdjustForStartupNegligibleOverhead(t *testing.T) {
	rate, dominated, measurable := adjustForStartup(1_000_000, 10.0, 0.05)
	if dominated {
		t.Fatalf("5%% overhead of the median must not be flagged startup-dominated")
	}
	if !measurable {
		t.Fatal("5% overhead is well-conditioned and must be reported as measurable")
	}
	want := 1_000_000.0 / (10.0 - 0.05)
	if math.Abs(rate-want) > 1e-6 {
		t.Fatalf("adjusted rate = %v, want %v", rate, want)
	}
}

// TestAdjustForStartupDominatedButMeasurable covers the middle band: overhead
// large enough to be flagged (worth a warning) but not so large relative to
// the run that subtracting it is unreliable — the subtraction is still
// well-conditioned and a number should be reported.
func TestAdjustForStartupDominatedButMeasurable(t *testing.T) {
	// overhead/median = 0.583, above startupDominatedThreshold (0.30) and
	// below startupUnmeasurableThreshold (0.70).
	rate, dominated, measurable := adjustForStartup(200_000, 0.389, 0.227)
	if !dominated {
		t.Fatal("overhead at 58% of median must be flagged startup-dominated")
	}
	if !measurable {
		t.Fatal("overhead at 58% of median is still a well-conditioned subtraction and must be measurable")
	}
	want := 200_000.0 / (0.389 - 0.227)
	if math.Abs(rate-want) > 1e-6 {
		t.Fatalf("adjusted rate = %v, want %v", rate, want)
	}
}

// TestAdjustForStartupUnmeasurable reproduces the motivating case: a GPU
// tool whose ~1.8s Metal init/compile cost is nearly the entirety of a short
// dictionary run's wall time. median-overhead here is a difference of two
// close, noisy quantities, so no number should be fabricated — this is
// exactly the case where an earlier version of this code produced a
// precise-looking figure ~335x below hashcat's real native throughput by
// flooring the denominator instead of admitting the measurement can't
// separate the two.
func TestAdjustForStartupUnmeasurable(t *testing.T) {
	rate, dominated, measurable := adjustForStartup(10_000_000, 1.879, 1.8)
	if !dominated {
		t.Fatal("overhead at 96% of median must be flagged startup-dominated")
	}
	if measurable {
		t.Fatal("overhead at 96% of median must not be reported as a measurable rate")
	}
	if rate != 0 {
		t.Fatalf("an unmeasurable rate must be exactly 0 (so JSON omits it), got %v", rate)
	}
}

// TestAdjustForStartupNeverDividesByZeroOrNegative guards the case where a
// noisy overhead probe lands at or past the timed median entirely: the
// function must recognize this as unmeasurable rather than attempt a
// division that produces an infinite, NaN, or negative throughput.
func TestAdjustForStartupNeverDividesByZeroOrNegative(t *testing.T) {
	for _, overhead := range []float64{0.71, 1.0, 1.0000001, 5.0, 100.0} {
		rate, dominated, measurable := adjustForStartup(1000, 1.0, overhead)
		if !dominated {
			t.Fatalf("overhead %v >= median must be startup-dominated", overhead)
		}
		if measurable {
			t.Fatalf("overhead %v this close to or past the median must not be measurable", overhead)
		}
		if rate != 0 {
			t.Fatalf("overhead %v produced a nonzero rate despite being unmeasurable: %v", overhead, rate)
		}
	}
}
