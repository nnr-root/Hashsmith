package smith

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// startupDominatedThreshold is the fraction of a run's median wall time that
// measured startup overhead must reach before the run is flagged as
// startup-dominated rather than throughput-dominated. Below this fraction the
// raw and adjusted rates are close enough that either is a fair reading;
// above it, the raw "candidates/wall-second" number mostly describes how fast
// a tool starts up, not how fast it hashes, and reporting it unqualified as a
// speed comparison would be misleading (see the GPU kernel-compile case: a
// fixed ~1.8s Metal init/compile cost on every hashcat invocation, regardless
// of candidate count, that a small dictionary run never amortizes).
const startupDominatedThreshold = 0.30

// startupUnmeasurableThreshold: once overhead reaches this fraction of the
// median, median-overhead is a difference of two close, independently noisy
// numbers, and dividing candidates by that difference does not produce a
// trustworthy rate — it produces whatever a floor or a lucky/unlucky sample
// happens to pick. An earlier version of this file floored the denominator
// at 2% of the median in this regime, which for a real hashcat run in this
// package's own test corpus produced a precise-looking "5.5 MH/s" figure
// against a true native GPU throughput (hashcat -b) of ~1,845 MH/s on the
// same machine — a fabricated number wrong by ~335x, not a fix. Past this
// threshold no adjusted rate is reported at all; StartupDominated is still
// set, and callers are pointed at the tool's own native benchmark instead.
const startupUnmeasurableThreshold = 0.70

const comparisonPassword = "hsb-target-final"

type comparisonCase struct {
	typ         string
	johnFormat  string
	hashcatMode string
}

var comparisonCases = []comparisonCase{
	{typ: "md5", johnFormat: "raw-md5", hashcatMode: "0"},
	{typ: "md4", johnFormat: "raw-md4", hashcatMode: "900"},
	{typ: "ntlm", johnFormat: "nt", hashcatMode: "1000"},
	{typ: "sha1", johnFormat: "raw-sha1", hashcatMode: "100"},
	{typ: "sha256", johnFormat: "raw-sha256", hashcatMode: "1400"},
}

type comparisonConfig struct {
	typ, jsonPath                        string
	hashsmithPath, johnPath, hashcatPath string
	candidates, repeats                  int
	timeout                              time.Duration
	hashsmithGPU                         bool
}

type comparisonToolResult struct {
	Status        string  `json:"status"`
	MedianSeconds float64 `json:"median_seconds,omitempty"`
	// CandidatesSec is candidates/median_seconds: the raw, unadjusted rate.
	// It includes each run's own one-time process startup (device init,
	// GPU kernel compile, wordlist load), so at small candidate counts it
	// mostly measures startup latency, not hashing speed. Prefer
	// ThroughputCandidatesSec for a speed comparison; this field is kept
	// for reproducibility and because it is the number an unmodified timer
	// around the command would report.
	CandidatesSec float64 `json:"effective_candidates_per_second,omitempty"`
	// OverheadSeconds is this tool's own one-time startup cost, measured
	// separately by timing the same command against a wordlist too small
	// to contain the target (so real hashing work is negligible). It is
	// not subtracted from MedianSeconds/CandidatesSec above, only used to
	// derive ThroughputCandidatesSec and StartupDominated.
	OverheadSeconds float64 `json:"startup_overhead_seconds,omitempty"`
	// ThroughputCandidatesSec is candidates/(median_seconds - overhead), a
	// better estimate of sustained hashing speed than the raw rate once
	// startup cost is non-trivial. It is zero/omitted whenever overhead is
	// too close to median_seconds for that subtraction to mean anything
	// (see startupUnmeasurableThreshold): subtracting two close, noisy
	// numbers does not get more honest by flooring the result, it just
	// hides the noise behind a plausible-looking figure. When this field
	// is absent, StartupDominated explains why, and a tool's own native
	// benchmark is the only reliable source for its true throughput here.
	ThroughputCandidatesSec float64 `json:"throughput_candidates_per_second,omitempty"`
	// StartupDominated is true when OverheadSeconds accounts for at least
	// startupDominatedThreshold of MedianSeconds — i.e. CandidatesSec for
	// this run is describing startup latency more than hashing speed, and
	// a larger --candidates run (or that tool's own native benchmark) is
	// needed before comparing raw rates means anything.
	StartupDominated bool      `json:"startup_dominated,omitempty"`
	Runs             []float64 `json:"runs_seconds,omitempty"`
	Detail           string    `json:"detail,omitempty"`
}

type comparisonCaseResult struct {
	Type  string                          `json:"type"`
	Tools map[string]comparisonToolResult `json:"tools"`
}

type comparisonReport struct {
	SuiteVersion int                           `json:"suite_version"`
	Scope        string                        `json:"scope"`
	GeneratedAt  string                        `json:"generated_at"`
	Host         string                        `json:"host"`
	GoVersion    string                        `json:"go_version"`
	LogicalCPUs  int                           `json:"logical_cpus"`
	WordlistSHA  string                        `json:"wordlist_sha256"`
	Candidates   int                           `json:"candidates"`
	Repeats      int                           `json:"repeats"`
	HashsmithGPU bool                          `json:"hashsmith_gpu"`
	JohnFork     int                           `json:"john_fork"`
	Tools        map[string]comparisonToolInfo `json:"tools"`
	Cases        []comparisonCaseResult        `json:"cases"`
}

type comparisonToolInfo struct {
	Status  string `json:"status"`
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Version string `json:"version,omitempty"`
}

type comparisonTool struct {
	name, path string
}

func runComparisonBenchmark(cfg comparisonConfig) error {
	if cfg.candidates < 2 || cfg.candidates > 10_000_000 {
		return errors.New("--candidates must be between 2 and 10000000")
	}
	if cfg.repeats < 1 || cfg.repeats > 20 {
		return errors.New("--repeat must be between 1 and 20")
	}
	if cfg.timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	cases, err := selectComparisonCases(cfg.typ)
	if err != nil {
		return err
	}
	if cfg.hashsmithPath == "" {
		cfg.hashsmithPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("locate current Hashsmith executable: %w", err)
		}
	}

	tmp, err := os.MkdirTemp("", "hashsmith-compare-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	wordlist := filepath.Join(tmp, "candidates.txt")
	if err := writeComparisonWordlist(wordlist, cfg.candidates); err != nil {
		return err
	}
	wordlistSHA, err := fileSHA256(wordlist)
	if err != nil {
		return err
	}

	report := comparisonReport{
		SuiteVersion: 1,
		Scope: "end-to-end deterministic dictionary recovery; median wall time includes each " +
			"run's own process startup (launch, device init, GPU kernel compile, wordlist load). " +
			"startup_overhead_seconds isolates that cost per tool via a separate near-instant miss " +
			"run; throughput_candidates_per_second (candidates / (median - overhead)) is the more " +
			"honest figure once startup_dominated is true. This harness still does not measure a " +
			"tool's native peak throughput (e.g. `hashcat -b`) — it drives an ordered file-based " +
			"dictionary through each tool's normal attack mode, so results are also capped by disk " +
			"I/O identically for all three. For sustained large-keyspace throughput, cross-check " +
			"against each tool's own benchmark mode.",
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Host:         runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion:    runtime.Version(),
		LogicalCPUs:  runtime.NumCPU(),
		WordlistSHA:  wordlistSHA,
		Candidates:   cfg.candidates,
		Repeats:      cfg.repeats,
		HashsmithGPU: cfg.hashsmithGPU,
		JohnFork:     johnComparisonCores(),
		Tools:        map[string]comparisonToolInfo{},
	}
	tools := []comparisonTool{
		{name: "hashsmith", path: cfg.hashsmithPath},
		{name: "john", path: cfg.johnPath},
		{name: "hashcat", path: cfg.hashcatPath},
	}
	resolved := map[string]string{}
	for _, tool := range tools {
		if path, lookupErr := exec.LookPath(tool.path); lookupErr == nil {
			resolved[tool.name] = path
			digest, _ := fileSHA256(path)
			report.Tools[tool.name] = comparisonToolInfo{
				Status: "available", Path: path, SHA256: digest, Version: comparisonToolVersion(tool.name, path),
			}
		} else {
			report.Tools[tool.name] = comparisonToolInfo{Status: "missing"}
		}
	}

	fmt.Fprintf(os.Stderr, "Comparison benchmark — %d candidates, %d run(s), startup included\n", cfg.candidates, cfg.repeats)
	fmt.Fprintln(os.Stderr, "Synthetic target only; every tool receives the identical ordered wordlist.")
	for _, c := range cases {
		target, hashErr := hashText(comparisonPassword, c.typ, "", "prefix")
		if hashErr != nil {
			return hashErr
		}
		targetFile := filepath.Join(tmp, c.typ+".hash")
		if err := os.WriteFile(targetFile, []byte(target+"\n"), 0600); err != nil {
			return err
		}
		caseResult := comparisonCaseResult{Type: c.typ, Tools: map[string]comparisonToolResult{}}
		for _, tool := range tools {
			path := resolved[tool.name]
			if path == "" {
				caseResult.Tools[tool.name] = comparisonToolResult{Status: "skipped", Detail: "executable not found"}
				continue
			}
			result := benchmarkComparisonTool(cfg, c, tool.name, path, target, targetFile, wordlist, tmp)
			caseResult.Tools[tool.name] = result
		}
		report.Cases = append(report.Cases, caseResult)
		printComparisonCase(caseResult)
	}
	if cfg.jsonPath != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if err := os.WriteFile(cfg.jsonPath, data, 0600); err != nil {
			return fmt.Errorf("write comparison JSON: %w", err)
		}
		fmt.Fprintf(os.Stderr, "\nJSON: %s\n", cfg.jsonPath)
	}
	return nil
}

// johnComparisonCores is the parallelism handed to John via --fork, matching
// the cores Hashsmith and hashcat already use. John's --fork tops out at
// well beyond any realistic core count, so NumCPU is passed through directly.
func johnComparisonCores() int {
	if n := runtime.NumCPU(); n > 1 {
		return n
	}
	return 1
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func comparisonToolVersion(name, path string) string {
	if name == "hashsmith" {
		return "Hashsmith comparison protocol 1 (" + runtime.Version() + ")"
	}
	args := []string{"--version"}
	if name == "john" {
		args = []string{"--list=build-info"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		return "version unavailable"
	}
	line := strings.TrimSpace(string(out))
	if at := strings.IndexByte(line, '\n'); at >= 0 {
		line = line[:at]
	}
	if len(line) > 160 {
		line = line[:160]
	}
	return line
}

func selectComparisonCases(typ string) ([]comparisonCase, error) {
	if typ == "" {
		return append([]comparisonCase(nil), comparisonCases...), nil
	}
	typ = canonicalHashType(typ)
	for _, c := range comparisonCases {
		if c.typ == typ {
			return []comparisonCase{c}, nil
		}
	}
	return nil, fmt.Errorf("--compare currently supports md5, md4, ntlm, sha1, and sha256; got %q", typ)
}

func writeComparisonWordlist(path string, candidates int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 256*1024)
	for i := 0; i < candidates-1; i++ {
		if _, err = fmt.Fprintf(w, "hsb%09d\n", i); err != nil {
			f.Close()
			return err
		}
	}
	if _, err = fmt.Fprintln(w, comparisonPassword); err == nil {
		err = w.Flush()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func benchmarkComparisonTool(cfg comparisonConfig, c comparisonCase, name, path, target, targetFile, wordlist, tmp string) comparisonToolResult {
	runs := make([]float64, 0, cfg.repeats)
	for run := 0; run < cfg.repeats; run++ {
		args, proof := comparisonCommand(name, c, target, targetFile, wordlist, tmp, run, cfg.hashsmithGPU, johnComparisonCores())
		ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = append(os.Environ(), "NO_COLOR=1")
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		start := time.Now()
		err := cmd.Run()
		elapsed := time.Since(start)
		cancel()
		if ctx.Err() == context.DeadlineExceeded {
			return comparisonToolResult{Status: "failed", Detail: "run timed out"}
		}
		if err != nil {
			return comparisonToolResult{Status: "failed", Detail: conciseCommandError(err, output.String())}
		}
		if !comparisonProof(name, proof, output.String()) {
			return comparisonToolResult{Status: "failed", Detail: "tool exited successfully without proving the target was recovered"}
		}
		runs = append(runs, elapsed.Seconds())
	}
	median := medianSeconds(runs)

	overhead, overheadErr := measureStartupOverhead(cfg, c, name, path, tmp, johnComparisonCores())
	if overheadErr != nil {
		// Overhead measurement is diagnostic, not load-bearing: if it fails
		// (e.g. this tool has no clean "miss" exit path under a timeout),
		// still report the raw, honestly-labeled numbers rather than
		// discarding a successful timed run.
		return comparisonToolResult{
			Status: "ok", MedianSeconds: median, CandidatesSec: float64(cfg.candidates) / median, Runs: runs,
			Detail: "startup overhead not measured: " + overheadErr.Error(),
		}
	}
	throughputRate, dominated, measurable := adjustForStartup(cfg.candidates, median, overhead)
	result := comparisonToolResult{
		Status:           "ok",
		MedianSeconds:    median,
		CandidatesSec:    float64(cfg.candidates) / median,
		OverheadSeconds:  overhead,
		StartupDominated: dominated,
		Runs:             runs,
	}
	if measurable {
		result.ThroughputCandidatesSec = throughputRate
	} else {
		result.Detail = fmt.Sprintf(
			"startup overhead (~%.3fs) is too close to the total run (%.3fs) to estimate a "+
				"hashing-only rate reliably; use this tool's own native benchmark for true throughput",
			overhead, median)
	}
	return result
}

// adjustForStartup turns a raw (candidates, median wall time, measured
// startup overhead) triple into a startup-adjusted throughput, a dominance
// flag, and whether that adjusted rate is trustworthy enough to report at
// all. It is split out from benchmarkComparisonTool purely so the arithmetic
// — the part with room for an off-by-one, a divide-by-zero, or a fabricated
// number dressed up as a measurement — is unit-testable without spawning
// any of the three tools.
//
// Below startupUnmeasurableThreshold, median-overhead is a well-conditioned
// subtraction and the quotient is reported. At or above it, overhead and
// median are two close, independently noisy quantities; a fixed floor on
// the denominator (an earlier version of this function used 2% of the
// median) does not make that subtraction meaningful, it just replaces one
// misleading number with a different, still-fabricated one — measured
// against hashcat's own native GPU benchmark on the machine this was tuned
// on, that floor produced a figure roughly 335x below hashcat's true
// throughput. So past the threshold, measurable is false and
// throughputCandidatesSec is 0: the caller reports no adjusted rate rather
// than a confident-looking guess.
func adjustForStartup(candidates int, median, overhead float64) (throughputCandidatesSec float64, dominated, measurable bool) {
	dominated = overhead >= median*startupDominatedThreshold
	if overhead >= median*startupUnmeasurableThreshold {
		return 0, dominated, false
	}
	return float64(candidates) / (median - overhead), dominated, true
}

// measureStartupOverhead isolates a tool's one-time per-invocation cost
// (process launch, device init, GPU kernel compile, wordlist load) from its
// hashing throughput. It runs the exact same command shape as the timed
// benchmark, but against a three-line wordlist that cannot contain the
// target, so the elapsed time is startup plus a negligible amount of real
// hashing.
//
// It takes the minimum of two probes rather than one: true fixed overhead
// (e.g. a GPU kernel compile) cannot be smaller than the fastest launch
// observed, so noise can only push a single sample up, never down, and the
// minimum of two is a better estimate of the floor than either sample alone.
func measureStartupOverhead(cfg comparisonConfig, c comparisonCase, name, path, tmp string, johnCores int) (float64, error) {
	missWordlist := filepath.Join(tmp, "miss-"+c.typ+".txt")
	if err := writeMissWordlist(missWordlist); err != nil {
		return 0, err
	}
	// A target these candidates cannot produce, so every tool runs its
	// normal attack loop to exhaustion instead of exiting early on a hit.
	missTarget, err := hashText(comparisonPassword+"-overhead-probe-never-matches", c.typ, "", "prefix")
	if err != nil {
		return 0, err
	}
	missTargetFile := filepath.Join(tmp, "miss-"+c.typ+".hash")
	if err := os.WriteFile(missTargetFile, []byte(missTarget+"\n"), 0600); err != nil {
		return 0, err
	}
	best := math.Inf(1)
	for probe := 0; probe < 2; probe++ {
		args, _ := comparisonCommand(name, c, missTarget, missTargetFile, missWordlist, tmp, -1000-probe, cfg.hashsmithGPU, johnCores)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = append(os.Environ(), "NO_COLOR=1")
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		start := time.Now()
		_ = cmd.Run() // a "not found" exit is the expected, successful outcome here
		elapsed := time.Since(start)
		timedOut := ctx.Err() == context.DeadlineExceeded
		cancel()
		if timedOut {
			continue
		}
		if s := elapsed.Seconds(); s < best {
			best = s
		}
	}
	if math.IsInf(best, 1) {
		return 0, errors.New("overhead probe timed out")
	}
	return best, nil
}

// writeMissWordlist writes a small, fixed wordlist that measureStartupOverhead
// pairs with a target none of its entries can hash to, so a tool's attack
// loop runs to completion without finding anything — isolating startup cost
// from the timed run's hashing work.
func writeMissWordlist(path string) error {
	const missCandidates = "hsb-overhead-miss-1\nhsb-overhead-miss-2\nhsb-overhead-miss-3\n"
	return os.WriteFile(path, []byte(missCandidates), 0600)
}

// comparisonCommand builds one tool's argv for a single comparison run.
//
// johnCores is the parallelism John should be given. Hashsmith uses every core
// by default and hashcat manages its own devices, but John runs on a single
// core unless it is passed --fork. Leaving that off does not make the
// comparison "John as it ships" — it makes it an 8-core tool timed against a
// 1-core one, and any ratio published from it is inflated by about the core
// count. So John is given the same machine the others get.
func comparisonCommand(name string, c comparisonCase, target, targetFile, wordlist, tmp string, run int, hashsmithGPU bool, johnCores int) ([]string, string) {
	suffix := fmt.Sprintf("%s-%d", c.typ, run)
	switch name {
	case "hashsmith":
		args := []string{"-N", "crack", "-t", c.typ, target, "-M", "dict", "-w", wordlist, "--no-pot"}
		if hashsmithGPU {
			args = append(args, "--gpu")
		}
		return args, comparisonPassword
	case "john":
		pot := filepath.Join(tmp, "john-"+suffix+".pot")
		session := filepath.Join(tmp, "john-"+suffix)
		args := []string{"--format=" + c.johnFormat, "--wordlist=" + wordlist, "--pot=" + pot, "--session=" + session, "--nolog"}
		if johnCores > 1 {
			args = append(args, fmt.Sprintf("--fork=%d", johnCores))
		}
		return append(args, targetFile), pot
	default:
		out := filepath.Join(tmp, "hashcat-"+suffix+".out")
		return []string{"-m", c.hashcatMode, "-a", "0", targetFile, wordlist, "--potfile-disable", "--restore-disable", "--logfile-disable", "--quiet", "--outfile", out, "--outfile-format", "2"}, out
	}
}

func comparisonProof(name, proof, output string) bool {
	if name == "hashsmith" {
		return strings.Contains(output, "Found: "+proof)
	}
	b, err := os.ReadFile(proof)
	return err == nil && strings.Contains(string(b), comparisonPassword)
}

func conciseCommandError(err error, output string) string {
	output = strings.TrimSpace(output)
	if len(output) > 240 {
		output = output[len(output)-240:]
	}
	if output == "" {
		return err.Error()
	}
	return err.Error() + ": " + strings.ReplaceAll(output, "\n", " ")
}

func medianSeconds(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func printComparisonCase(result comparisonCaseResult) {
	fmt.Fprintf(os.Stderr, "\n  %-8s", result.Type)
	anyDominated := false
	for _, name := range []string{"hashsmith", "john", "hashcat"} {
		tool := result.Tools[name]
		switch tool.Status {
		case "ok":
			mark := " "
			if tool.StartupDominated {
				mark, anyDominated = "*", true
			}
			fmt.Fprintf(os.Stderr, "  %-9s %8.3fs (%s)%s", name, tool.MedianSeconds, formatRate(tool.CandidatesSec), mark)
		case "skipped":
			fmt.Fprintf(os.Stderr, "  %-9s %-20s", name, "skipped")
		default:
			fmt.Fprintf(os.Stderr, "  %-9s %-20s", name, "failed")
		}
	}
	fmt.Fprintln(os.Stderr)
	for _, name := range []string{"hashsmith", "john", "hashcat"} {
		tool := result.Tools[name]
		if tool.Status != "ok" && tool.Detail != "" {
			fmt.Fprintf(os.Stderr, "    %s: %s\n", name, tool.Detail)
		}
	}
	if anyDominated {
		fmt.Fprintln(os.Stderr, "    * this run's time is mostly one-time startup (device init / kernel compile), not")
		fmt.Fprintln(os.Stderr, "      hashing speed — the rate above is not a fair speed comparison at this --candidates")
		fmt.Fprintln(os.Stderr, "      size; see throughput_candidates_per_second in --json, or use a larger run.")
		for _, name := range []string{"hashsmith", "john", "hashcat"} {
			tool := result.Tools[name]
			if tool.Status != "ok" || !tool.StartupDominated {
				continue
			}
			if tool.ThroughputCandidatesSec > 0 {
				fmt.Fprintf(os.Stderr, "        %-9s startup ~%.3fs of %.3fs -> adjusted %s\n",
					name, tool.OverheadSeconds, tool.MedianSeconds, formatRate(tool.ThroughputCandidatesSec))
			} else {
				fmt.Fprintf(os.Stderr, "        %-9s startup ~%.3fs of %.3fs -> not reliably measurable at this scale; "+
					"use %s's native benchmark\n", name, tool.OverheadSeconds, tool.MedianSeconds, name)
			}
		}
	}
}
