package smith

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
//	go test ./internal/smith -run TestHashcatConformance -args -update-conformance-baseline
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

// writeConformanceBaseline rewrites the pinned baseline, with one rule that
// keeps a regeneration from quietly weakening it.
//
// A TIMEOUT means "this machine was too slow to decide", not "this mode
// broke" — which is why the ratchet ignores it in both directions. But a
// regeneration WRITES it, and a mode pinned CRACKED that is rewritten as
// TIMEOUT stops being held to anything: the next real break in it passes.
// Regenerating on a busy laptop would silently unpin whichever slow KDFs
// happened to run while something else had the CPU, and nothing in the diff
// would say so beyond one line among hundreds.
//
// This happened. A run that added six modes also rewrote -m 29441 from CRACKED
// to TIMEOUT, on a machine that was compiling at the time.
//
// So a mode already pinned CRACKED keeps that pin through a TIMEOUT. Nothing
// else is preserved: a CRACKED that becomes NOT-FOUND or REJECTED is a real
// regression and must show up in the diff as one.
func writeConformanceBaseline(t *testing.T, corpus []conformanceRecord, results []conformanceOutcome) {
	t.Helper()
	previous := loadConformanceBaseline(t)
	type row struct {
		mode string
		out  conformanceOutcome
	}
	rows := make([]row, 0, len(corpus))
	kept := 0
	for i, r := range corpus {
		got := results[i]
		if got == outTimeout && previous[r.mode] == outCracked {
			got = outCracked
			kept++
		}
		rows = append(rows, row{r.mode, got})
	}
	if kept > 0 {
		t.Logf("kept %d mode(s) pinned CRACKED that timed out on this machine; a timeout says "+
			"the machine was too slow to decide, not that the mode broke", kept)
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
	b.WriteString("#   go test ./internal/smith -run TestHashcatConformance -args -update-conformance-baseline\n")
	for _, r := range rows {
		b.WriteString(r.mode + "\t" + string(r.out) + "\n")
	}
	if err := os.WriteFile(baselinePath(), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("writing baseline: %v", err)
	}
	t.Logf("wrote %s (%d modes)", baselinePath(), len(rows))
}
