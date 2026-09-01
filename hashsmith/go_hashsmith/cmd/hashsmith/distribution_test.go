package main

// Tests for --skip/--limit's core correctness property: disjoint slices of the
// keyspace, run separately (as separate machines would), must union back to
// exactly the unsplit enumeration — no candidate missed, none tried twice.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// A --limit-bounded run that exhausts its SLICE (not the whole keyspace) must
// SAVE its session checkpoint, not discard it. Losing the checkpoint would let
// an operator mistake a slice's "Not found" for the whole keyspace having
// been searched — the same failure the tiling property exists to prevent,
// arriving by a different route (session bookkeeping instead of the runner).
func TestSessionSavedWhenLimitBoundedSliceExhausts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	l := bruteLayout("abc", 1, 3) // total 39
	var targetIdx int64 = -1
	for i := int64(0); i < l.total; i++ {
		if l.candidate(i) == "cab" {
			targetIdx = i
			break
		}
	}
	if targetIdx < 0 {
		t.Fatal("test setup: \"cab\" not found in the brute layout")
	}

	const sessName = "distsess-limit-test"
	cc, err := newCrackCtx("", true, sessName, false, "", false, 0, targetIdx) // --limit targetIdx, slice = [0, targetIdx)
	if err != nil {
		t.Fatalf("newCrackCtx: %v", err)
	}

	found, err := doCrack(md5hex("cab"), "md5", "brute", "", "abc", 1, 3, 2, "", "prefix", "", false, nil, nil, cc)
	if err != nil {
		t.Fatalf("doCrack: %v", err)
	}
	if found {
		t.Fatalf("target sits at index %d, outside the bounded [0,%d) slice; must not be found", targetIdx, targetIdx)
	}

	s, err := loadSession(sessName)
	if err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if s == nil {
		t.Fatal("bounded slice exhausted short of the true keyspace total, but no session file " +
			"was saved — a --limit 'Not found' must not be silently indistinguishable from " +
			"'the whole keyspace was searched'")
	}
	defer s.remove()
	if s.Total != l.total {
		t.Errorf("session Total = %d, want %d (the true, unbounded keyspace)", s.Total, l.total)
	}
	if s.Checkpoint != targetIdx {
		t.Errorf("session Checkpoint = %d, want %d (where the --limit bound stopped it)", s.Checkpoint, targetIdx)
	}
}

// A negative --skip or --limit has no sensible meaning and, left uncaught,
// silently coerces to "unbounded" — the opposite of a deliberately narrowed
// distributed slice from a typo'd flag. Both must be rejected outright.
func TestNegativeSkipOrLimitRejected(t *testing.T) {
	if err := runCrack([]string{"-M", "brute", "-C", "ab", "--skip", "-1", "--keyspace"}); err == nil {
		t.Error("negative --skip should be rejected, got nil error")
	}
	if err := runCrack([]string{"-M", "brute", "-C", "ab", "--limit", "-5", "--keyspace"}); err == nil {
		t.Error("negative --limit should be rejected, got nil error")
	}
}

// ── --stdout / dict-attack candidate equivalence ────────────────────────────
//
// --stdout exists so an operator can preview exactly what a distributed
// --skip/--limit slice will try before launching it. That only holds if
// --stdout applies the identical bound the real attack applies, so this
// checks the equivalence directly rather than by proxy: for several
// skip/limit combinations (with and without rules), the ordered candidate
// list streamCandidates prints in dict mode must equal the ordered sequence
// of candidates dictAttack actually attempts for the identical slice.

// collectDictAttempts runs dictAttack for the [skip, skip+limit) word slice
// with a verifier that never matches, so the whole slice is always attempted,
// and records every candidate offered to verify, in order. workers is pinned
// to 1 (as collect() above pins runLayout to 1 worker) so the sequence is
// deterministic and directly comparable to streamCandidates' single-threaded
// output.
func collectDictAttempts(t *testing.T, wordlistPath string, rules *ruleEngine, skip, limit int64) []string {
	t.Helper()
	var got []string
	var attempts int64
	_, err := dictAttack(context.Background(), wordlistPath, skip, limit, 1, &attempts, rules, func(pw string) bool {
		got = append(got, pw)
		return false
	})
	if err != nil {
		t.Fatalf("dictAttack(skip=%d,limit=%d): %v", skip, limit, err)
	}
	return got
}

func TestStdoutDictMatchesAttackSlicing(t *testing.T) {
	dir := t.TempDir()
	wordlistPath := filepath.Join(dir, "words.txt")
	words := []string{"alpha", "beta", "gamma", "delta"}
	if err := os.WriteFile(wordlistPath, []byte(strings.Join(words, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stacked := stackedEngine(t, []string{"c", "l"}, []string{"$1", "$2"})

	cases := []struct {
		name        string
		skip, limit int64
	}{
		{"unbounded", 0, 0},
		{"one word from start", 0, 1},
		{"middle slice", 1, 2},
		{"limit past end", 2, 100},
		{"skip past end", 4, 1},
		{"whole list explicit", 0, 4},
		{"single last word", 3, 1},
	}

	engines := []struct {
		name string
		e    *ruleEngine
	}{
		{"no rules", nil},
		{"stacked rules", stacked},
	}

	for _, eng := range engines {
		for _, c := range cases {
			t.Run(eng.name+"/"+c.name, func(t *testing.T) {
				attempted := collectDictAttempts(t, wordlistPath, eng.e, c.skip, c.limit)

				out := captureStdout(t, func() error {
					return streamCandidates("dict", wordlistPath, "", "", 0, 0, nil, eng.e, c.skip, c.limit)
				})
				var printed []string
				if out != "" {
					printed = strings.Split(strings.TrimRight(out, "\n"), "\n")
				}

				if len(printed) != len(attempted) {
					t.Fatalf("stdout printed %d candidates, attack attempted %d\nstdout=%v\nattack=%v",
						len(printed), len(attempted), printed, attempted)
				}
				for i := range attempted {
					if printed[i] != attempted[i] {
						t.Errorf("candidate %d: stdout=%q attack=%q", i, printed[i], attempted[i])
					}
				}
			})
		}
	}
}
