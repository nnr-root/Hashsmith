package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── John the Ripper conformance harness ──────────────────────────────────────
//
// The hashcat harness next door measures one thing well: given a mode number,
// does this tool crack that mode's record. It cannot measure the other half of
// the goal, because it always passes -t. Whether a record is RECOGNISED is
// never tested there.
//
// John is the right corpus for that half. It publishes a test vector for every
// format it supports (`john --list=format-tests`) and — unlike hashcat — has no
// mode numbers, so a user presents John's records to this tool with nothing but
// the bytes. That makes auto-detection the honest thing to measure, and it also
// exposes the gap that matters between the two projects: the same algorithm
// spelled differently. Hashsmith cracks LM, scrypt and PBKDF2-HMAC-SHA1, but
// John writes them "$LM$a9c604d244c4e99d", "$7$C6..../...." and
// "$pbkdf2-hmac-sha1$1000.fd11cde0...." and those spellings are what a John
// user has in hand.
//
// So this harness drives the real binary with NO -t, exactly as someone
// switching tools would, and classifies every format. Like its hashcat
// counterpart it is a RATCHET: a format that has ever cracked must keep
// cracking, and the residue stays visible rather than rounded into a headline.
//
// Two things it deliberately does not do. It does not treat a low number as a
// failure — most of the gap is dialect, not capability, and pretending
// otherwise would make the baseline a scoreboard instead of a regression guard.
// And it does not call John: the corpus is checked in, so the test needs no
// second tool installed.

type johnRecord struct{ format, hash, pass string }

type johnOutcome string

const (
	johnCracked     johnOutcome = "CRACKED"      // correct password recovered
	johnNotDetected johnOutcome = "NOT-DETECTED" // nothing claimed the record
	johnNotFound    johnOutcome = "NOT-FOUND"    // a type claimed it, then failed
	johnWrongPlain  johnOutcome = "WRONG-PLAIN"  // found the WRONG password
	johnTimeout     johnOutcome = "TIMEOUT"      // exceeded johnPerRecordTimeout
	johnRejected    johnOutcome = "REJECTED"     // refused before any attempt
)

// johnPerRecordTimeout bounds one format. As with hashcat, a TIMEOUT is a
// "this machine was too slow to decide", never a regression in either
// direction.
const johnPerRecordTimeout = 20 * time.Second

var updateJohnBaseline = flag.Bool("update-john-baseline", false,
	"rewrite testdata/john_conformance_baseline.tsv from this run")

func loadJohnCorpus(t *testing.T) []johnRecord {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "john_format_tests.tsv"))
	if err != nil {
		t.Fatalf("john corpus: %v", err)
	}
	defer f.Close()
	var out []johnRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}
		out = append(out, johnRecord{format: parts[0], hash: parts[1], pass: parts[2]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("john corpus: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("john corpus is empty")
	}
	return out
}

func loadJohnBaseline(t *testing.T) map[string]johnOutcome {
	t.Helper()
	path := filepath.Join("testdata", "john_conformance_baseline.tsv")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return map[string]johnOutcome{}
	}
	if err != nil {
		t.Fatalf("john baseline: %v", err)
	}
	defer f.Close()
	out := map[string]johnOutcome{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if parts := strings.Split(line, "\t"); len(parts) == 2 {
			out[parts[0]] = johnOutcome(parts[1])
		}
	}
	return out
}

func writeJohnBaseline(t *testing.T, corpus []johnRecord, results []johnOutcome) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# John the Ripper format-test conformance, one line per format.\n")
	b.WriteString("# Regenerate with `go test -run TestJohnFormatConformance -args -update-john-baseline`.\n")
	for i, r := range corpus {
		fmt.Fprintf(&b, "%s\t%s\n", r.format, results[i])
	}
	path := filepath.Join("testdata", "john_conformance_baseline.tsv")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write john baseline: %v", err)
	}
	t.Logf("wrote %s", path)
}

// classifyJohn runs one record through the real binary with no -t.
func classifyJohn(bin, dir string, i int, r johnRecord) johnOutcome {
	tag := fmt.Sprintf("%04d", i)
	wl := filepath.Join(dir, "jwl-"+tag+".txt")
	// Decoys around the real password, so a verifier that matches anything
	// is caught as WRONG-PLAIN rather than counted as a success.
	if err := os.WriteFile(wl, []byte("hashsmith-decoy-1\n"+r.pass+"\nhashsmith-decoy-2\n"), 0o600); err != nil {
		return johnRejected
	}
	hf := filepath.Join(dir, "jh-"+tag+".txt")
	if err := os.WriteFile(hf, []byte(r.hash+"\n"), 0o600); err != nil {
		return johnRejected
	}
	ctx, cancel := context.WithTimeout(context.Background(), johnPerRecordTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-N", "crack", hf, "-w", wl, "--no-pot", "-p", "2")
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb", "HOME="+dir)
	raw, _ := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return johnTimeout
	}
	out := ansiEscape.ReplaceAllString(string(raw), "")
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, strings.ToLower("found: "+r.pass)),
		strings.Contains(out, r.hash+":"+r.pass):
		return johnCracked
	case strings.Contains(low, "found:"):
		return johnWrongPlain
	case strings.Contains(low, "could not auto-detect"):
		return johnNotDetected
	case strings.Contains(low, "not found"):
		return johnNotFound
	default:
		return johnRejected
	}
}

// TestJohnFormatConformance is the recognition ratchet described above.
func TestJohnFormatConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("john conformance drives the binary once per format; skipped under -short")
	}
	corpus := loadJohnCorpus(t)
	bin := buildTestBinary(t)
	baseline := loadJohnBaseline(t)

	dir := t.TempDir()
	results := make([]johnOutcome, len(corpus))
	sem := make(chan struct{}, max(2, runtime.NumCPU()-1))
	var wg sync.WaitGroup
	for i, r := range corpus {
		wg.Add(1)
		go func(i int, r johnRecord) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = classifyJohn(bin, dir, i, r)
		}(i, r)
	}
	wg.Wait()

	counts := map[johnOutcome]int{}
	var regressions, newlyPassing, wrongPlaintext []string
	for i, r := range corpus {
		got := results[i]
		counts[got]++
		was := baseline[r.format]
		switch {
		case got == johnTimeout || was == johnTimeout:
		case was == johnCracked && got != johnCracked:
			regressions = append(regressions, fmt.Sprintf("%-28s %s -> %s", r.format, was, got))
		case was != johnCracked && got == johnCracked:
			newlyPassing = append(newlyPassing, r.format)
		}
		if got == johnWrongPlain {
			wrongPlaintext = append(wrongPlaintext, r.format)
		}
	}

	sort.Strings(regressions)
	sort.Strings(newlyPassing)
	t.Logf("John format-test conformance over %d formats, auto-detected from the record alone:", len(corpus))
	for _, k := range []johnOutcome{johnCracked, johnNotDetected, johnNotFound, johnRejected, johnWrongPlain, johnTimeout} {
		if counts[k] > 0 {
			t.Logf("  %-13s %4d  (%.1f%%)", k, counts[k], 100*float64(counts[k])/float64(len(corpus)))
		}
	}

	if len(wrongPlaintext) > 0 {
		t.Errorf("%d format(s) reported the WRONG password:\n  %s",
			len(wrongPlaintext), strings.Join(wrongPlaintext, "\n  "))
	}
	if len(regressions) > 0 {
		t.Errorf("%d format(s) regressed from CRACKED:\n  %s",
			len(regressions), strings.Join(regressions, "\n  "))
	}
	if len(newlyPassing) > 0 {
		t.Logf("%d format(s) now crack that the baseline does not claim — raise it with "+
			"`go test -run TestJohnFormatConformance -args -update-john-baseline`:\n  %s",
			len(newlyPassing), strings.Join(newlyPassing, "\n  "))
	}
	if *updateJohnBaseline {
		writeJohnBaseline(t, corpus, results)
	}
}
