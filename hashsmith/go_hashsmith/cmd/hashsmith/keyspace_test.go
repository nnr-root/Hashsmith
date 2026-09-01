package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func md5x(s string) string { d := md5.Sum([]byte(s)); return hex.EncodeToString(d[:]) }

func TestBruteLayoutOrder(t *testing.T) {
	l := bruteLayout("ab", 1, 2)
	// length 1: a,b  then length 2: aa,ab,ba,bb  → total 6
	if l.total != 6 {
		t.Fatalf("total: want 6 got %d", l.total)
	}
	want := []string{"a", "b", "aa", "ab", "ba", "bb"}
	for i, w := range want {
		if got := l.candidate(int64(i)); got != w {
			t.Errorf("candidate(%d): want %q got %q", i, w, got)
		}
	}
}

func TestRunLayoutResumeFindsAndSkips(t *testing.T) {
	// Answer "zy" is at global index 700 of a-z length-2 (total 702).
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 1, 2)
	target := md5x("zy")
	verify := func(c string) bool { return md5x(c) == target }

	// Full run from 0 finds it.
	var n1 int64
	pw, err := runLayout(context.Background(), l, 0, 0, 4, &n1, nil, verify)
	if err != nil || pw != "zy" {
		t.Fatalf("full run: got %q err %v", pw, err)
	}

	// Resuming past the answer (index 701 > 700) must MISS it, proving resumeFrom
	// genuinely skips the earlier keyspace.
	var n2 int64
	pw, _ = runLayout(context.Background(), l, 701, 0, 4, &n2, nil, verify)
	if pw == "zy" {
		t.Fatal("resume past the answer should not find it")
	}

	// Resuming just before the answer still finds it, with far fewer tries.
	var n3 int64
	pw, _ = runLayout(context.Background(), l, 699, 0, 4, &n3, nil, verify)
	if pw != "zy" {
		t.Fatalf("resume before answer: want zy got %q", pw)
	}
	if atomic.LoadInt64(&n3) > 100 {
		t.Errorf("resume should skip most of the keyspace, tried %d", n3)
	}
}

func TestSessionMatch(t *testing.T) {
	s := &sessionState{Mode: "brute", Type: "md5", Target: "x", Charset: "ab",
		MinLen: 1, MaxLen: 3, SaltMode: "prefix"}
	if !s.matches("brute", "md5", "x", "ab", 1, 3, "", [4]string{}, false, "", "prefix", "", "", 0) {
		t.Error("identical params should match")
	}
	if s.matches("brute", "md5", "x", "ab", 1, 4, "", [4]string{}, false, "", "prefix", "", "", 0) {
		t.Error("different maxLen must not match")
	}
	if s.matches("brute", "md5", "x", "ab", 1, 3, "", [4]string{}, false, "", "prefix", "other.txt", "", 0) {
		t.Error("different wordlist must not match")
	}
}

// ── --keyspace's dict-mode unit (regression lock) ───────────────────────────
//
// --keyspace in dict mode deliberately reports the WORD count, not
// words*rules: --skip/--limit slice a dict run by word index, with each
// word's full rule expansion staying inside its slice, so a keyspace of N
// words is exactly the number of --skip steps a scheduler needs to cover the
// whole run. This locks that invariant so nobody "fixes" --keyspace into
// words*rules later and silently breaks every distributed dict script: the
// property under test is that slicing the run into `keyspace` slices of
// --limit 1 (one per --skip value 0..keyspace-1) covers every candidate —
// base words AND their full (here: stacked) rule expansion — exactly once,
// with nothing left over at skip==keyspace.
func TestKeyspaceUnitIsSkipStepsToCoverDictRun(t *testing.T) {
	dir := t.TempDir()
	wordlistPath := filepath.Join(dir, "words.txt")
	words := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	if err := os.WriteFile(wordlistPath, []byte(strings.Join(words, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Two stacked layers (as --rules given twice would build), cross-producted
	// — the case a naive words*rules multiply would be most tempting, and
	// wrong, to apply to.
	rules := stackedEngine(t, []string{"c", "l"}, []string{"$1", "$2", ":"})

	// --keyspace's own reported value, via the real --keyspace code path.
	out := captureStdout(t, func() error {
		return printKeyspace("dict", wordlistPath, "", "", 0, 0, princeDefaultElems, nil)
	})
	var keyspace int64
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "%d", &keyspace); err != nil {
		t.Fatalf("--keyspace printed non-numeric output %q: %v", out, err)
	}
	if keyspace != int64(len(words)) {
		t.Fatalf("dict --keyspace must report the word count (%d), got %d — this is the "+
			"documented, deliberate unit; do not multiply by the rule count", len(words), keyspace)
	}

	// Unsplit baseline: every candidate (base word + all stacked-rule
	// expansions) the real attack path would try.
	baseline := map[string]int{}
	if _, err := dictAttack(context.Background(), wordlistPath, 0, 0, 1, new(int64), rules,
		func(pw string) bool { baseline[pw]++; return false }); err != nil {
		t.Fatalf("baseline dictAttack: %v", err)
	}
	if len(baseline) <= len(words) {
		t.Fatalf("test setup produced no rule-expanded candidates (only %d distinct), "+
			"the rules layer isn't exercising anything", len(baseline))
	}

	// Slice into `keyspace` --limit-1 slices, one per --skip value 0..keyspace-1.
	union := map[string]int{}
	for skip := int64(0); skip < keyspace; skip++ {
		var attempts int64
		_, err := dictAttack(context.Background(), wordlistPath, skip, 1, 1, &attempts, rules,
			func(pw string) bool { union[pw]++; return false })
		if err != nil {
			t.Fatalf("dictAttack(skip=%d,limit=1): %v", skip, err)
		}
		if attempts == 0 {
			t.Errorf("skip=%d produced no attempts, but skip < keyspace=%d — a word slice went missing", skip, keyspace)
		}
	}

	for pw, n := range baseline {
		if union[pw] != n {
			t.Errorf("candidate %q: baseline (unsplit) count %d, union of keyspace slices count %d — lost", pw, n, union[pw])
		}
	}
	for pw, n := range union {
		if baseline[pw] != n {
			t.Errorf("candidate %q: keyspace slices produced it %d times, baseline only %d — duplicated across slices", pw, n, baseline[pw])
		}
	}

	// keyspace is not merely "enough" slices, it is exactly the number needed:
	// one more --skip step past it must cover nothing new.
	var trailing int64
	if _, err := dictAttack(context.Background(), wordlistPath, keyspace, 1, 1, &trailing, rules,
		func(string) bool { return false }); err != nil {
		t.Fatalf("dictAttack(skip=keyspace): %v", err)
	}
	if trailing != 0 {
		t.Errorf("skip=keyspace(%d) attempted %d candidates, want 0 — keyspace undercounts the slices needed", keyspace, trailing)
	}
}
