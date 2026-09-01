package main

// Tests for --skip/--limit's core correctness property: disjoint slices of the
// keyspace, run separately (as separate machines would), must union back to
// exactly the unsplit enumeration — no candidate missed, none tried twice.

import (
	"context"
	"runtime"
	"testing"
)

// collect runs the bounded layout [skip, skip+limit) single-threaded, calling
// fn for every candidate tried and accumulating the attempt count into
// *attempts. verify never reports a match, so the run always covers its whole
// bounded slice — that's what lets the tests assert on the candidate stream
// itself rather than on timing or an early stop.
func collect(t *testing.T, l *keyspaceLayout, skip, limit int64, attempts *int64, fn func(string)) {
	t.Helper()
	_, err := runLayout(context.Background(), l, skip, limit, 1, attempts, nil, func(c string) bool {
		fn(c)
		return false
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
}

// The union of disjoint --skip/--limit slices must cover the whole keyspace
// exactly once: no candidate tried twice, none missed. A gap here means a
// password that was never tried but was reported "not found".
func TestSkipLimitSlicesTileTheKeyspace(t *testing.T) {
	l := bruteLayout("abc", 1, 3) // 3 + 9 + 27 = 39
	const slices = 4
	sliceSize := (l.total + slices - 1) / slices

	seen := map[string]int{}
	for s := int64(0); s < slices; s++ {
		skip := s * sliceSize
		if skip >= l.total {
			break
		}
		limit := sliceSize
		var attempts int64
		collect(t, l, skip, limit, &attempts, func(c string) { seen[c]++ })
	}

	if len(seen) != int(l.total) {
		t.Errorf("slices covered %d distinct candidates, want %d", len(seen), l.total)
	}
	for cand, n := range seen {
		if n != 1 {
			t.Errorf("candidate %q tried %d times, want exactly 1", cand, n)
		}
	}
	// And the union must equal the unsplit enumeration, not merely match in count.
	for i := int64(0); i < l.total; i++ {
		if _, ok := seen[l.candidate(i)]; !ok {
			t.Errorf("candidate %q (index %d) was never tried", l.candidate(i), i)
		}
	}
}

// --limit must bound the work actually done, not just the reported total.
func TestLimitStopsEarly(t *testing.T) {
	l := bruteLayout("abcdefghij", 5, 5) // 100,000
	var attempts int64
	collect(t, l, 0, 250, &attempts, func(string) {})
	if attempts > 250+int64(runtime.NumCPU()*keyspaceChunk) {
		t.Errorf("attempts = %d, expected close to the 250 limit", attempts)
	}
	if attempts < 250 {
		t.Errorf("attempts = %d, fewer than the 250 requested", attempts)
	}
}

// --skip past the end is a no-op, not an error or a panic.
func TestSkipBeyondKeyspace(t *testing.T) {
	l := bruteLayout("ab", 1, 2) // 6
	var attempts int64
	n := 0
	collect(t, l, 999, 10, &attempts, func(string) { n++ })
	if n != 0 {
		t.Errorf("tried %d candidates past the end of the keyspace, want 0", n)
	}
}
