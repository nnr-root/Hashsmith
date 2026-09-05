package main

import (
	"strings"
	"testing"
)

const sampleDump = `5f4dcc3b5aa765d61d8327deb882cf99
$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS
5f4dcc3b5aa765d61d8327deb882cf99

# a comment line
not a hash at all
root:$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/
`

func TestScanBatchCountsAndClassifies(t *testing.T) {
	s, err := scanBatch(strings.NewReader(sampleDump))
	if err != nil {
		t.Fatalf("scanBatch returned an error for a well-formed dump: %v", err)
	}
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5 (blank and comment lines are skipped)", s.Total)
	}
	if s.ByType["md5"] != 2 {
		t.Errorf("md5 count = %d, want 2", s.ByType["md5"])
	}
	if s.ByType["bcrypt"] != 1 {
		t.Errorf("bcrypt count = %d, want 1", s.ByType["bcrypt"])
	}
	if s.ByType["sha512crypt"] != 1 {
		t.Errorf("sha512crypt count = %d, want 1 (a shadow line must be peeled)", s.ByType["sha512crypt"])
	}
	if len(s.Unmatched) != 1 || s.Unmatched[0] != "not a hash at all" {
		t.Errorf("Unmatched = %v, want exactly the non-hash line", s.Unmatched)
	}
}

// The percentages here are counts over lines — measured quantities, unlike the
// normalized scores the old identify printed.
func TestBatchSummaryPercentagesAreLineCounts(t *testing.T) {
	s, err := scanBatch(strings.NewReader(sampleDump))
	if err != nil {
		t.Fatalf("scanBatch returned an error for a well-formed dump: %v", err)
	}
	out := renderBatchSummary(s)
	if !strings.Contains(out, "5 lines scanned") {
		t.Errorf("summary missing the scanned count\n---\n%s", out)
	}
	if !strings.Contains(out, "40.0%") {
		t.Errorf("summary missing md5's 2/5 = 40.0%%\n---\n%s", out)
	}
}

func TestEmptyInputDoesNotDivideByZero(t *testing.T) {
	s, err := scanBatch(strings.NewReader(""))
	if err != nil {
		t.Fatalf("scanBatch returned an error for empty input: %v", err)
	}
	out := renderBatchSummary(s)
	if !strings.Contains(out, "0 lines scanned") {
		t.Errorf("empty input summary = %q", out)
	}
}

// A line longer than scanBatch's scan buffer makes bufio.Scanner give up for
// good (Scan returns false, Err returns bufio.ErrTooLong) — everything after
// that line goes unread. scanBatch must surface that as an error rather than
// silently reporting a short Total: a summary whose denominator can be wrong
// without warning is worse than no summary.
func TestScanBatchSurfacesTruncationError(t *testing.T) {
	tooLong := strings.Repeat("a", batchLineScanBuffer+1)
	dump := "5f4dcc3b5aa765d61d8327deb882cf99\n" + tooLong + "\nnever read\n"

	_, err := scanBatch(strings.NewReader(dump))
	if err == nil {
		t.Fatal("scanBatch returned no error for a line exceeding the scan buffer, want an error")
	}
}
