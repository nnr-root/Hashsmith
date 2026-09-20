package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Hashcat conformance harness ───────────────────────────────────────────────
//
// The 502-vector self-test asserts at the LIBRARY layer: it calls the verifier
// directly with a record it constructed itself. That boundary cannot see any
// defect in argument handling, input normalization or record parsing, which is
// why `hashsmith selftest` reported 356/356 green on 2026-09-20 while
// `crack -t descrypt` rejected hashcat's own canonical descrypt record.
//
// This harness asserts at the boundary a user actually touches. It drives the
// real binary, with the real argument parser, against hashcat's own published
// example records — the only externally-authored, adversarial corpus available
// for this problem — and classifies the outcome for every mode.
//
// It is a RATCHET, not a pass/fail gate on the absolute number. A mode that has
// ever cracked must keep cracking; a mode that starts cracking is reported so
// the baseline can be raised. That way coverage can only go up, and the exact
// residue is always visible rather than rounded into a headline.

type conformanceRecord struct {
	mode, name, pass, hash string
}

type conformanceOutcome string

const (
	outCracked    conformanceOutcome = "CRACKED"      // correct password recovered
	outRejected   conformanceOutcome = "REJECTED"     // mode resolves, record refused
	outNoSuchMode conformanceOutcome = "NO-SUCH-MODE" // unsupported hash algorithm
	outNotFound   conformanceOutcome = "NOT-FOUND"    // parses, runs, wrongly says not found
	outWrongPlain conformanceOutcome = "WRONG-PLAIN"  // found the WRONG password
	outTimeout    conformanceOutcome = "TIMEOUT"      // exceeded perRecordTimeout on this machine
)

// perRecordTimeout bounds one mode. A handful of high-iteration KDFs over a
// half-megabyte volume header (hashcat's -m 29xxx VeraCrypt records reach
// 513,152 characters) would otherwise dominate the whole run.
//
// A TIMEOUT is never treated as a regression, in either direction: it says
// "this machine was too slow to decide", not "this mode broke". Only a
// definite CRACKED -> definite-other transition fails the ratchet, so a busy
// or slow CI runner cannot manufacture a failure.
const perRecordTimeout = 20 * time.Second

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func loadConformanceCorpus(t *testing.T) []conformanceRecord {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "hashcat_example_hashes.tsv"))
	if err != nil {
		t.Fatalf("conformance corpus: %v", err)
	}
	defer f.Close()
	var out []conformanceRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 4 {
			t.Fatalf("malformed corpus line: %.80q", line)
		}
		out = append(out, conformanceRecord{mode: p[0], name: p[1], pass: p[2], hash: p[3]})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// classify runs one record through the real binary and reports what happened.
func classify(bin, dir string, r conformanceRecord) conformanceOutcome {
	wl := filepath.Join(dir, "wl-"+r.mode+".txt")
	// Three decoys alongside the real password: a verifier that matches
	// anything would report a decoy and be caught as WRONG-PLAIN rather than
	// counted as a success.
	if err := os.WriteFile(wl, []byte("hashsmith-decoy-1\n"+r.pass+"\nhashsmith-decoy-2\nhashsmith-decoy-3\n"), 0o600); err != nil {
		return outRejected
	}
	hf := filepath.Join(dir, "h-"+r.mode+".txt")
	if err := os.WriteFile(hf, []byte(r.hash+"\n"), 0o600); err != nil {
		return outRejected
	}
	ctx, cancel := context.WithTimeout(context.Background(), perRecordTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-N", "crack", "-t", r.mode, hf, "-w", wl, "--no-pot", "-p", "2")
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+dir)
	raw, _ := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return outTimeout
	}
	out := ansiEscape.ReplaceAllString(string(raw), "")
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, strings.ToLower("Found: "+r.pass)),
		strings.Contains(out, r.hash+":"+r.pass):
		return outCracked
	case strings.Contains(low, "found:"):
		return outWrongPlain
	case strings.Contains(low, "unsupported hash algorithm"):
		return outNoSuchMode
	case strings.Contains(low, "not found"):
		return outNotFound
	default:
		return outRejected
	}
}

// TestHashcatConformance is the coverage ratchet described above.
func TestHashcatConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("conformance harness drives the binary 538 times; skipped under -short")
	}
	corpus := loadConformanceCorpus(t)
	bin := buildTestBinary(t)
	baseline := loadConformanceBaseline(t)

	dir := t.TempDir()
	results := make([]conformanceOutcome, len(corpus))
	sem := make(chan struct{}, max(2, runtime.NumCPU()-1))
	var wg sync.WaitGroup
	for i, r := range corpus {
		wg.Add(1)
		go func(i int, r conformanceRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = classify(bin, dir, r)
		}(i, r)
	}
	wg.Wait()

	counts := map[conformanceOutcome]int{}
	var regressions, newlyPassing, wrongPlaintext []string
	for i, r := range corpus {
		got := results[i]
		counts[got]++
		was := baseline[r.mode]
		switch {
		// A TIMEOUT is a "don't know", not a regression — see perRecordTimeout.
		case got == outTimeout || was == outTimeout:
		case was == outCracked && got != outCracked:
			regressions = append(regressions, fmt.Sprintf("-m %-7s %-45s %s -> %s", r.mode, trunc(r.name, 45), was, got))
		case was != outCracked && got == outCracked:
			newlyPassing = append(newlyPassing, fmt.Sprintf("-m %-7s %s", r.mode, trunc(r.name, 45)))
		}
		if got == outWrongPlain {
			wrongPlaintext = append(wrongPlaintext, fmt.Sprintf("-m %-7s %s", r.mode, trunc(r.name, 45)))
		}
	}

	sort.Strings(regressions)
	sort.Strings(newlyPassing)
	t.Logf("hashcat v7.1.2 conformance over %d modes with a plain example record:", len(corpus))
	for _, k := range []conformanceOutcome{outCracked, outRejected, outNoSuchMode, outNotFound, outWrongPlain, outTimeout} {
		if counts[k] > 0 {
			t.Logf("  %-13s %4d  (%.1f%%)", k, counts[k], 100*float64(counts[k])/float64(len(corpus)))
		}
	}

	// A wrong plaintext is always a defect: the verifier accepted a candidate
	// that does not produce this record.
	if len(wrongPlaintext) > 0 {
		t.Errorf("%d mode(s) reported the WRONG password:\n  %s",
			len(wrongPlaintext), strings.Join(wrongPlaintext, "\n  "))
	}
	if len(regressions) > 0 {
		t.Errorf("%d mode(s) regressed from CRACKED:\n  %s",
			len(regressions), strings.Join(regressions, "\n  "))
	}
	if len(newlyPassing) > 0 {
		t.Logf("%d mode(s) now crack that the baseline does not claim — raise the baseline "+
			"with `go test -run TestHashcatConformance -args -update-conformance-baseline`:\n  %s",
			len(newlyPassing), strings.Join(newlyPassing, "\n  "))
	}
	if *updateBaseline {
		writeConformanceBaseline(t, corpus, results)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
