package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

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
	Status        string    `json:"status"`
	MedianSeconds float64   `json:"median_seconds,omitempty"`
	CandidatesSec float64   `json:"effective_candidates_per_second,omitempty"`
	Runs          []float64 `json:"runs_seconds,omitempty"`
	Detail        string    `json:"detail,omitempty"`
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
		Scope:        "end-to-end deterministic dictionary recovery; process startup included",
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Host:         runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion:    runtime.Version(),
		LogicalCPUs:  runtime.NumCPU(),
		WordlistSHA:  wordlistSHA,
		Candidates:   cfg.candidates,
		Repeats:      cfg.repeats,
		HashsmithGPU: cfg.hashsmithGPU,
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
		args, proof := comparisonCommand(name, c, target, targetFile, wordlist, tmp, run, cfg.hashsmithGPU)
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
	return comparisonToolResult{
		Status: "ok", MedianSeconds: median, CandidatesSec: float64(cfg.candidates) / median, Runs: runs,
	}
}

func comparisonCommand(name string, c comparisonCase, target, targetFile, wordlist, tmp string, run int, hashsmithGPU bool) ([]string, string) {
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
		return []string{"--format=" + c.johnFormat, "--wordlist=" + wordlist, "--pot=" + pot, "--session=" + session, "--nolog", targetFile}, pot
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
	for _, name := range []string{"hashsmith", "john", "hashcat"} {
		tool := result.Tools[name]
		switch tool.Status {
		case "ok":
			fmt.Fprintf(os.Stderr, "  %-9s %8.3fs (%s)", name, tool.MedianSeconds, formatRate(tool.CandidatesSec))
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
}
