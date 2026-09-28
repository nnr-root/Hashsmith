package smith

// Tests for -M association (hashcat's -a 9): per-line target/wordlist
// pairing (loadAssociationWordlist) and the mode's end-to-end CLI wiring.

import (
	"path/filepath"
	"strings"
	"testing"
)

// ── loadAssociationWordlist: line-count validation ──────────────────────────

func TestLoadAssociationWordlistAcceptsMatchingLineCount(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "aaa\nbbb\nccc\n")

	got, err := loadAssociationWordlist(wl, 3)
	if err != nil {
		t.Fatalf("loadAssociationWordlist: %v", err)
	}
	want := []string{"aaa", "bbb", "ccc"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadAssociationWordlistRefusesLineCountMismatch(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "aaa\nbbb\n") // 2 lines

	_, err := loadAssociationWordlist(wl, 3) // wants 3
	if err == nil {
		t.Fatal("expected a refusal for a line-count mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "2") || !strings.Contains(err.Error(), "3") {
		t.Errorf("error should mention both the actual (2) and wanted (3) counts, got: %v", err)
	}
}

// ── THE PROPERTY THAT MATTERS: no cross-contamination between targets ──────

// Mirrors TestSingleCrackDoesNotCrossContaminate's leak-bait shape: target0's
// real password is the word paired with target1, and vice versa. If pairing
// were done by anything other than strict line position (e.g. tried every
// word against every target), both targets would crack. Correct pairing
// means BOTH remain uncracked.
func TestAssociationCrackDoesNotCrossContaminate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wordA := "correcthorse"
	wordB := "sunshine1985"

	target0 := md5hex(wordB) // needs line 1's word, not its own line 0's word
	target1 := md5hex(wordA) // needs line 0's word, not its own line 1's word

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target0+"\n"+target1+"\n")

	assocWl := filepath.Join(dir, "assoc.txt")
	mustWrite(t, assocWl, wordA+"\n"+wordB+"\n")

	leftFile := filepath.Join(dir, "left.txt")
	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "association",
		"--assoc-wordlist", assocWl, "--no-pot", "--left", "-o", leftFile, targetsFile}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}

	left := mustRead(t, leftFile)
	if !strings.Contains(left, target0) {
		t.Errorf("target0 should remain uncracked (its own paired word does not match it), got left:\n%s", left)
	}
	if !strings.Contains(left, target1) {
		t.Errorf("target1 should remain uncracked (its own paired word does not match it), got left:\n%s", left)
	}
	if exitCode == 0 {
		t.Errorf("exitCode = 0, want nonzero (both targets must remain uncracked)")
	}
}

// The straightforward positive case: each target's own paired word IS its
// real password, and both must crack.
func TestAssociationCrackFindsOwnPairedWord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wordA := "correcthorse"
	wordB := "sunshine1985"

	target0 := md5hex(wordA)
	target1 := md5hex(wordB)

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target0+"\n"+target1+"\n")

	assocWl := filepath.Join(dir, "assoc.txt")
	mustWrite(t, assocWl, wordA+"\n"+wordB+"\n")

	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "association",
			"--assoc-wordlist", assocWl, "--no-pot", targetsFile})
	})
	if !strings.Contains(stderr, wordA) {
		t.Errorf("target0 should have cracked to %q, stderr:\n%s", wordA, stderr)
	}
	if !strings.Contains(stderr, wordB) {
		t.Errorf("target1 should have cracked to %q, stderr:\n%s", wordB, stderr)
	}
}

// ── Rules apply to each per-target seed ─────────────────────────────────────

func TestAssociationCrackAppliesRules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	// Real password is the capitalized word, not the literal paired word —
	// only reachable via a rule that uppercases the first letter.
	target := md5hex("Correcthorse")

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target+"\n")

	assocWl := filepath.Join(dir, "assoc.txt")
	mustWrite(t, assocWl, "correcthorse\n")

	ruleFile := filepath.Join(dir, "cap.rule")
	mustWrite(t, ruleFile, "c\n") // JtR/hashcat "c": capitalize

	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "association",
			"--assoc-wordlist", assocWl, "--rules", ruleFile, "--no-pot", targetsFile})
	})
	if !strings.Contains(stderr, "Correcthorse") {
		t.Errorf("rule-mangled candidate should have cracked the target, stderr:\n%s", stderr)
	}
}

// ── Multiple companion wordlists, each independently paired ────────────────

// Two --assoc-wordlist files; target0's real password lives in the SECOND
// wordlist's line 0, not the first's — proving both wordlists are searched,
// not just the first one given.
func TestAssociationMultipleWordlistsEachIndependentlyPaired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	target := md5hex("fromSecondList")

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target+"\n")

	wl1 := filepath.Join(dir, "wl1.txt")
	mustWrite(t, wl1, "fromFirstList\n")
	wl2 := filepath.Join(dir, "wl2.txt")
	mustWrite(t, wl2, "fromSecondList\n")

	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "association",
			"--assoc-wordlist", wl1, "--assoc-wordlist", wl2, "--no-pot", targetsFile})
	})
	if !strings.Contains(stderr, "fromSecondList") {
		t.Errorf("target should have cracked via the second wordlist's paired word, stderr:\n%s", stderr)
	}
}

// ── A hash repeated at two lines gets each line's own word, not a dedup ────

// runSingleCrack deliberately dedupes by hash (a shared hash needs only one
// pass, since every username sharing it contributes to the SAME seed set).
// Association attack must NOT do that: two lines with the same hash have two
// DIFFERENT paired words, and dropping either would drop a real candidate.
func TestAssociationRepeatedHashTriesEachLinesOwnWord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	shared := md5hex("onlyReachableFromLine2")

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, shared+"\n"+shared+"\n") // same hash, two lines

	assocWl := filepath.Join(dir, "assoc.txt")
	// Line 0's word does not crack it; line 1's word does.
	mustWrite(t, assocWl, "wrongGuess\nonlyReachableFromLine2\n")

	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "association",
			"--assoc-wordlist", assocWl, "--no-pot", targetsFile})
	})
	if !strings.Contains(stderr, "onlyReachableFromLine2") {
		t.Errorf("the second occurrence's own paired word should have cracked the shared hash, stderr:\n%s", stderr)
	}
}

// ── Composes correctly with existing contracts ──────────────────────────────

func TestAssociationRequiresWordlist(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, md5hex("password")+"\n")

	err := runCrack([]string{"-t", "md5", "-M", "association", "--no-pot", targetsFile})
	if err == nil {
		t.Fatal("association mode without --assoc-wordlist should refuse")
	}
	if !strings.Contains(err.Error(), "assoc-wordlist") {
		t.Errorf("refusal error should name the missing --assoc-wordlist flag, got: %v", err)
	}
}

func TestAssociationWordlistLengthMismatchRefuses(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, md5hex("a")+"\n"+md5hex("b")+"\n") // 2 targets

	assocWl := filepath.Join(dir, "assoc.txt")
	mustWrite(t, assocWl, "onlyone\n") // 1 line

	err := runCrack([]string{"-t", "md5", "-M", "association",
		"--assoc-wordlist", assocWl, "--no-pot", targetsFile})
	if err == nil {
		t.Fatal("a wordlist/target line-count mismatch should refuse")
	}
}

// --show's contract is that it never attacks — only reports potfile hits.
// Association mode must not reintroduce the "--show secretly attacks" bug
// fixed elsewhere in this project.
func TestAssociationNeverAttacksUnderShow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	potPath := filepath.Join(dir, "test.pot")
	mustWrite(t, potPath, "")

	target := md5hex("correcthorse")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target+"\n")

	assocWl := filepath.Join(dir, "assoc.txt")
	mustWrite(t, assocWl, "correcthorse\n")

	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "association",
			"--assoc-wordlist", assocWl, "--pot", potPath, "--show", targetsFile})
	})
	if strings.Contains(stderr, "correcthorse") {
		t.Fatalf("--show must never attack, but the target appears cracked; stderr:\n%s", stderr)
	}
}

func TestAssociationKeyspaceRefusesClearly(t *testing.T) {
	dir := t.TempDir()
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, md5hex("a")+"\n")

	err := runCrack([]string{"-t", "md5", "-M", "association", "--keyspace", targetsFile})
	if err == nil {
		t.Fatal("--keyspace with association mode should refuse, not print a misleading number")
	}
	if !strings.Contains(err.Error(), "association") {
		t.Errorf("refusal should name association mode specifically, got: %v", err)
	}
}

func TestAssociationStdoutRefusesClearly(t *testing.T) {
	dir := t.TempDir()
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, md5hex("a")+"\n")

	err := runCrack([]string{"-t", "md5", "-M", "association", "--stdout", targetsFile})
	if err == nil {
		t.Fatal("--stdout with association mode should refuse, not preview a nonexistent shared stream")
	}
	if !strings.Contains(err.Error(), "association") {
		t.Errorf("refusal should name association mode specifically, got: %v", err)
	}
}
