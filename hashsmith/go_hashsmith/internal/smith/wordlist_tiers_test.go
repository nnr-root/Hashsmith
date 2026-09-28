package smith

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Discovery looked for exactly two filenames, rockyou.txt and rockyou.txt.gz.
// The people who run this tool very often have john or hashcat installed
// already, and both ship a real password list — but neither was ever found, so
// a machine without rockyou fell back to the built-in English dictionary.
func TestDiscoveryFindsTheCompetitorsBundledLists(t *testing.T) {
	var sawJohn, sawHashcat bool
	for _, p := range wordlistCandidatePaths {
		if strings.HasSuffix(p, "password.lst") {
			sawJohn = true
		}
		if strings.HasSuffix(p, "example.dict") {
			sawHashcat = true
		}
	}
	if !sawJohn {
		t.Error("john's password.lst is not searched for")
	}
	if !sawHashcat {
		t.Error("hashcat's example.dict is not searched for")
	}
}

// A 3,546-entry list found in a well-ranked directory must not beat a
// 14-million-entry one found in a lower-ranked directory. The file decides
// first; the directory decides among equals.
func TestBigCorporaOutrankSmallBundledLists(t *testing.T) {
	first := map[string]int{}
	for i, p := range wordlistCandidatePaths {
		base := filepath.Base(p)
		if _, seen := first[base]; !seen {
			first[base] = i
		}
	}
	rockyou, ok := first["rockyou.txt"]
	if !ok {
		t.Fatal("rockyou.txt is not searched for at all")
	}
	for _, small := range []string{"password.lst", "example.dict"} {
		at, ok := first[small]
		if !ok {
			continue
		}
		if at < rockyou {
			t.Errorf("%s is searched at position %d, before rockyou.txt at %d", small, at, rockyou)
		}
	}
	// And every rockyou entry must precede every bundled-list entry, not just
	// the first one — tiering, not a single lucky ordering.
	lastRockyou := -1
	firstSmall := len(wordlistCandidatePaths)
	for i, p := range wordlistCandidatePaths {
		switch b := filepath.Base(p); b {
		case "rockyou.txt", "rockyou.txt.gz":
			lastRockyou = i
		case "password.lst", "example.dict":
			if i < firstSmall {
				firstSmall = i
			}
		}
	}
	if lastRockyou > firstSmall {
		t.Errorf("tiers interleave: a bundled list appears at %d, before the last rockyou entry at %d",
			firstSmall, lastRockyou)
	}
}

// The tier flattening must not emit the same path twice, or `hashsmith
// wordlists` would list duplicates and stat them twice.
func TestCandidatePathsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range wordlistCandidatePaths {
		if seen[p] {
			t.Errorf("duplicate candidate path %q", p)
		}
		seen[p] = true
	}
}

// End to end: a directory holding only john's list must be discovered and used.
func TestDiscoveryUsesABundledListWhenNoRockyouExists(t *testing.T) {
	dir := t.TempDir()
	lst := filepath.Join(dir, "password.lst")
	if err := os.WriteFile(lst, []byte("#!comment\nletmein\nhunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	savedTiers, savedPaths := wordlistCandidateTiers, wordlistCandidatePaths
	t.Cleanup(func() { wordlistCandidateTiers, wordlistCandidatePaths = savedTiers, savedPaths })

	wordlistCandidateTiers = []wordlistTier{
		{names: []string{"rockyou.txt"}, dirs: []string{filepath.Join(dir, "absent")}},
		{names: []string{"password.lst"}, dirs: []string{dir}},
	}
	wordlistCandidatePaths = buildWordlistCandidateTiers(wordlistCandidateTiers, nil)

	got := wordlistCandidateStatus()
	var found string
	for _, c := range got {
		if c.exists {
			found = c.path
			break
		}
	}
	if found != lst {
		t.Errorf("discovered %q; want %q", found, lst)
	}
}
