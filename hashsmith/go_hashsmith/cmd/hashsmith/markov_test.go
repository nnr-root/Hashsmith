package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestMarkovBijection(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "t.txt")
	os.WriteFile(wl, []byte("abc\ncab\nbca\n"), 0644)
	m, err := trainMarkov("abc", wl)
	if err != nil {
		t.Fatal(err)
	}
	// length 2 over "abc" → 9 candidates; Markov reordering must still be a
	// bijection onto the full brute keyspace (no dupes, complete coverage).
	layout := markovLayout(m, 2, 2)
	if layout.total != 9 {
		t.Fatalf("total: want 9 got %d", layout.total)
	}
	seen := map[string]bool{}
	for i := int64(0); i < layout.total; i++ {
		seen[layout.candidate(i)] = true
	}
	if len(seen) != 9 {
		t.Fatalf("want 9 unique candidates, got %d", len(seen))
	}
	got := make([]string, 0, 9)
	for k := range seen {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"aa", "ab", "ac", "ba", "bb", "bc", "ca", "cb", "cc"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("coverage mismatch at %d: %q vs %q", i, got[i], want[i])
		}
	}
}

func TestMarkovOrdersLikelyFirst(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "t.txt")
	// every word starts with 'z'; 'z' must therefore rank first for position 0.
	os.WriteFile(wl, []byte("za\nzb\nzc\nzz\n"), 0644)
	m, err := trainMarkov("abz", wl)
	if err != nil {
		t.Fatal(err)
	}
	if m.first[0] != 'z' {
		t.Errorf("most common start char should be 'z', got %q", m.first[0])
	}
	// candidate(0) is the greedy most-likely string → must start with 'z'.
	layout := markovLayout(m, 2, 2)
	if c := layout.candidate(0); c[0] != 'z' {
		t.Errorf("candidate(0) should start with 'z', got %q", c)
	}
}
