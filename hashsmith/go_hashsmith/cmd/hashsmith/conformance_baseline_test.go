package main

import (
	"bufio"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// updateBaseline rewrites the pinned conformance baseline from the current run.
// Run it deliberately, after reading what changed:
//
//	go test ./cmd/hashsmith -run TestHashcatConformance -args -update-conformance-baseline
//
// The baseline is a ratchet, so raising it is a commit that says "these modes
// work now and must keep working". It must never be regenerated to make a
// failure go away — that is precisely the failure it exists to catch.
var updateBaseline = flag.Bool("update-conformance-baseline", false,
	"rewrite testdata/hashcat_conformance_baseline.tsv from this run")

const baselineFile = "hashcat_conformance_baseline.tsv"

func baselinePath() string { return filepath.Join("testdata", baselineFile) }

func loadConformanceBaseline(t *testing.T) map[string]conformanceOutcome {
	t.Helper()
	out := map[string]conformanceOutcome{}
	f, err := os.Open(baselinePath())
	if err != nil {
		if os.IsNotExist(err) {
			return out // first run: every mode is "new"
		}
		t.Fatalf("conformance baseline: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.SplitN(line, "\t", 2)
		if len(p) != 2 {
			continue
		}
		out[p[0]] = conformanceOutcome(p[1])
	}
	return out
}

func writeConformanceBaseline(t *testing.T, corpus []conformanceRecord, results []conformanceOutcome) {
	t.Helper()
	type row struct {
		mode string
		out  conformanceOutcome
	}
	rows := make([]row, 0, len(corpus))
	for i, r := range corpus {
		rows = append(rows, row{r.mode, results[i]})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, _ := strconv.Atoi(rows[i].mode)
		b, _ := strconv.Atoi(rows[j].mode)
		return a < b
	})
	var b strings.Builder
	b.WriteString("# Pinned outcome per hashcat mode for TestHashcatConformance.\n")
	b.WriteString("# A mode recorded as CRACKED here must keep cracking: the test fails if it\n")
	b.WriteString("# stops. Any other value is a known gap and is free to improve.\n")
	b.WriteString("# Regenerate deliberately with:\n")
	b.WriteString("#   go test ./cmd/hashsmith -run TestHashcatConformance -args -update-conformance-baseline\n")
	for _, r := range rows {
		b.WriteString(r.mode + "\t" + string(r.out) + "\n")
	}
	if err := os.WriteFile(baselinePath(), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("writing baseline: %v", err)
	}
	t.Logf("wrote %s (%d modes)", baselinePath(), len(rows))
}
