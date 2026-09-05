package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"

	"hashsmith-go/internal/hashid"
)

// batchStats is the tally over a dump. ByType counts LINES, so the percentages
// rendered from it are measured proportions rather than heuristic scores.
type batchStats struct {
	Total      int
	Identified int
	ByType     map[string]int
	Confidence map[string]string
	Lines      map[string][]string
	Unmatched  []string
}

// batchLineScanBuffer matches scan2smith's, so a dump one command can read is
// readable by the other.
const batchLineScanBuffer = 4 * 1024 * 1024

// scanBatch classifies every non-blank, non-comment line of r by its best
// unsuppressed candidate. A line counts as identified only when that best
// candidate reaches certain or likely; a line whose best candidate is merely
// possible counts as unidentified, matching identify's own confidence bar
// rather than a looser one invented for the summary.
//
// The returned error is non-nil only when the scan itself failed — most
// notably bufio.ErrTooLong when a line exceeds batchLineScanBuffer, at which
// point Scan() stops for good and everything after that line goes unread.
// A summary whose denominator can be silently short is worse than no
// summary, so a truncated scan must be reported rather than rendered as if
// it were complete.
func scanBatch(r io.Reader) (batchStats, error) {
	s := batchStats{
		ByType:     map[string]int{},
		Confidence: map[string]string{},
		Lines:      map[string][]string{},
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), batchLineScanBuffer)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.Total++

		var best *hashid.Candidate
		for _, c := range identifyCandidates(line) {
			if c.Suppressed {
				continue
			}
			if c.Confidence == hashid.Certain || c.Confidence == hashid.Likely {
				candidate := c
				best = &candidate
				break
			}
		}
		if best == nil {
			s.Unmatched = append(s.Unmatched, line)
			continue
		}
		s.Identified++
		s.ByType[best.Type]++
		s.Confidence[best.Type] = best.Confidence.String()
		s.Lines[best.Type] = append(s.Lines[best.Type], line)
	}
	if err := sc.Err(); err != nil {
		return s, fmt.Errorf("scanning dump after %d line(s): %w", s.Total, err)
	}
	return s, nil
}

// renderBatchSummary is identify --summary's rendering: a scanned/identified/
// unidentified headline, then one row per detected type with its line count,
// its share of Total (a measured proportion, not a heuristic score), the
// confidence tier its lines matched at, and the hashcat mode to feed crack.
func renderBatchSummary(s batchStats) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %d lines scanned · %d identified · %d unidentified\n\n",
		s.Total, s.Identified, len(s.Unmatched))

	types := make([]string, 0, len(s.ByType))
	for t := range s.ByType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		if s.ByType[types[i]] != s.ByType[types[j]] {
			return s.ByType[types[i]] > s.ByType[types[j]]
		}
		return types[i] < types[j]
	})

	for _, t := range types {
		pct := 0.0
		if s.Total > 0 {
			pct = float64(s.ByType[t]) / float64(s.Total) * 100
		}
		mode := "-"
		if m, ok := universalHashRegistry.hashcatMode(t); ok {
			mode = fmt.Sprintf("-m %d", m)
		}
		fmt.Fprintf(&sb, "  %-16s %6d  %5.1f%%   %-9s %s\n",
			t, s.ByType[t], pct, s.Confidence[t], mode)
	}
	if len(s.Unmatched) > 0 {
		fmt.Fprintf(&sb, "\n  Unidentified lines: --unmatched <file>\n")
	}
	if len(types) > 1 {
		fmt.Fprintf(&sb, "  Split by type:      --split-by-type <dir>\n")
	}
	return sb.String()
}

// runIdentifyBatch is --summary's wiring into runIdentify: it resolves the
// dump's file path, scans it, renders the summary, and honours
// --split-by-type / --unmatched when they are given alongside it.
//
// --json is refused outright rather than silently ignored: batchStats has no
// schema-versioned JSON rendering (unlike the per-hash identifyReport that
// --json normally produces), and inventing one as a side effect of a bug fix
// would be scope creep this task didn't ask for. -o and -c are honoured,
// same as the ordinary per-line path, since redirecting plain text output is
// unambiguous and costs nothing to support.
//
// The exit code mirrors the per-line path's 0/1 contract (Task 14): 0 when
// every scanned line was identified, 1 when any line was not.
func runIdentifyBatch(filePath, text string, positional []string, splitDir, unmatchedFile, outFile string, copyRes, asJSON bool) error {
	if asJSON {
		return errors.New("identify --summary --json is not supported: --summary has no JSON rendering (batchStats is not the versioned identifyReport schema); drop --json or drop --summary")
	}

	path, err := resolveBatchFile(filePath, text, positional)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	stats, err := scanBatch(f)
	if err != nil {
		return err
	}
	result := strings.TrimRight(renderBatchSummary(stats), "\n")

	if outFile == "" && !copyRes {
		color.New(themeAttr).Fprintln(os.Stdout, result)
	} else if err := outputResult(result, outFile, copyRes); err != nil {
		return err
	}

	if splitDir != "" {
		if err := splitByType(stats, splitDir); err != nil {
			return err
		}
	}
	if unmatchedFile != "" {
		if err := writeUnmatched(unmatchedFile, stats.Unmatched); err != nil {
			return err
		}
	}
	if len(stats.Unmatched) > 0 {
		return identifyExitError(1)
	}
	return nil
}

// resolveBatchFile picks --summary's target path: -f, else -i, else the
// first positional argument. Batch mode only makes sense against a file —
// unlike the ordinary per-line path there is no inline-text or comma-list
// fallback — so whichever candidate is picked is handed to os.Open as-is
// rather than pre-checked here, letting a bad path surface its own real
// "no such file" error instead of a generic one.
func resolveBatchFile(filePath, text string, positional []string) (string, error) {
	for _, c := range append([]string{filePath, text}, positional...) {
		if c = strings.TrimSpace(c); c != "" {
			return c, nil
		}
	}
	return "", errors.New("identify --summary requires a file path")
}

// writeUnmatched writes one unidentified line per line to path. An empty
// Unmatched slice writes an empty file rather than a lone blank line.
func writeUnmatched(path string, lines []string) error {
	var body string
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

// splitByType writes one file per detected type, named for the canonical -t
// type, so the result can be fed straight back to `crack -t <type>`.
func splitByType(s batchStats, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for typ, lines := range s.Lines {
		path := filepath.Join(dir, typ+".txt")
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}
