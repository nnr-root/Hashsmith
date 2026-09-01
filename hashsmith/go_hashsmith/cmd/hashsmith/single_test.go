package main

// Tests for --single (John the Ripper's "single-crack" mode): per-account
// seed generation (singleSeeds) and the --single flag's per-target wiring.

import (
	"path/filepath"
	"strings"
	"testing"
)

// keys returns the keys of a map[string]bool, unordered — a small test
// helper for error messages that want to show what a seed set actually
// contained.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ── singleSeeds: seed generation from a login name ──────────────────────────

// Seeds must derive from the login name, including its components, so
// "john.smith" reaches both halves — a very common password base.
func TestSingleSeedsFromUsername(t *testing.T) {
	got := map[string]bool{}
	for _, s := range singleSeeds("john.smith") {
		got[s] = true
	}
	for _, want := range []string{"john.smith", "john", "smith", "John.smith", "JOHN.SMITH"} {
		if !got[want] {
			t.Errorf("seeds for john.smith missing %q (got %v)", want, keys(got))
		}
	}
}

// An empty or absent username must yield no seeds rather than a seed of "" —
// an empty candidate would be tried against a target for no reason.
func TestSingleSeedsEmptyUsername(t *testing.T) {
	if s := singleSeeds(""); len(s) != 0 {
		t.Errorf("empty username produced %d seeds, want 0: %v", len(s), s)
	}
}

// Whitespace-only is just as empty as "" — must not slip through as a
// single all-whitespace seed.
func TestSingleSeedsWhitespaceUsername(t *testing.T) {
	if s := singleSeeds("   \t  "); len(s) != 0 {
		t.Errorf("whitespace-only username produced %d seeds, want 0: %v", len(s), s)
	}
}

// The verbatim login name must be the FIRST seed produced — cheapest-first
// ordering, since a hit ends the attack for that target and the verbatim
// login is by far the most common real-world password base.
func TestSingleSeedsVerbatimIsFirst(t *testing.T) {
	seeds := singleSeeds("jsmith")
	if len(seeds) == 0 || seeds[0] != "jsmith" {
		t.Fatalf("first seed = %v, want \"jsmith\" first", seeds)
	}
}

// Digit boundaries split too, e.g. an account name that already embeds a
// year or number ("jsmith2024") should also yield the letter-only part.
func TestSingleSeedsSplitsOnDigitBoundary(t *testing.T) {
	got := map[string]bool{}
	for _, s := range singleSeeds("jsmith2024") {
		got[s] = true
	}
	if !got["jsmith"] {
		t.Errorf("seeds for jsmith2024 missing %q (got %v)", "jsmith", keys(got))
	}
}

// Seeds must be deduplicated — a username whose case variants collapse
// (already all lowercase, say) must not produce repeats.
func TestSingleSeedsDeduplicated(t *testing.T) {
	seeds := singleSeeds("bob")
	seen := map[string]bool{}
	for _, s := range seeds {
		if seen[s] {
			t.Fatalf("seed %q produced more than once: %v", s, seeds)
		}
		seen[s] = true
	}
}

// ── THE PROPERTY THAT MATTERS: no cross-contamination between targets ──────

// Two accounts. alice's password IS bob's username — so if seeds leak across
// targets, alice's hash cracks from bob's seed and the bug shows immediately
// as a WRONG SUCCESS, not merely a slowdown. bob's password is his own
// username, capitalised — reachable from his own seed list with no rules
// needed, so a correct run cracks him and nothing else.
//
// With correct isolation: bob is cracked (from his own seed), alice is not
// (her real password, "alice"/"Alice"/"ALICE", never matches "bob"), and the
// decoy wordlist used for the main attack contains neither name, so nothing
// beyond single-crack's own seeds could account for either result.
func TestSingleCrackDoesNotCrossContaminate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	// A decoy wordlist for the MAIN attack that follows --single: it must
	// contain neither "bob"/"Bob" nor "alice"/"Alice", so any crack in this
	// test is attributable to single-crack's own per-account seeds, not an
	// ordinary dictionary hit.
	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "hunter2\nqwerty\nsunshine\ncorrecthorse\n")

	aliceDigest := mustHash(t, "bob", "md5-pass-salt", "saltAlice") // leak bait
	bobDigest := mustHash(t, "Bob", "md5-pass-salt", "saltBob")     // bob's own seed
	aliceLine := "alice:" + aliceDigest + ":saltAlice"
	bobLine := "bob:" + bobDigest + ":saltBob"

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, aliceLine+"\n"+bobLine+"\n")

	leftFile := filepath.Join(dir, "left.txt")
	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", "--left", "-o", leftFile, targetsFile})
	})

	if !strings.Contains(stderr, "user: bob") {
		t.Fatalf("bob should have been cracked from his own username seed; stderr:\n%s", stderr)
	}
	if strings.Contains(stderr, "user: alice") {
		t.Fatalf("CROSS-CONTAMINATION: alice's hash was cracked — bob's seed leaked "+
			"across targets; stderr:\n%s", stderr)
	}

	left := mustRead(t, leftFile)
	if !strings.Contains(left, aliceLine) {
		t.Errorf("--left should still report alice as uncracked, got:\n%s", left)
	}
	if strings.Contains(left, bobLine) {
		t.Errorf("bob should not appear in --left output — he was cracked; got:\n%s", left)
	}
	if exitCode == 0 {
		t.Errorf("exitCode = 0, want nonzero (alice must remain uncracked)")
	}
}

// ── --single composes correctly with existing contracts ────────────────────

// --single without --username has no usernames to derive seeds from. It must
// refuse loudly rather than silently running zero single-crack passes and
// reporting the target as simply "not found" — the exact failure mode this
// project keeps finding bugs in.
func TestSingleRequiresUsername(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\n")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, md5hex("password")+"\n")

	err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot", "--single", targetsFile})
	if err == nil {
		t.Fatal("--single without --username should refuse, not silently run zero single-crack passes")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("refusal error should explain the --username prerequisite, got: %v", err)
	}
}

// --show's contract is that it never attacks — only reports potfile hits.
// --single adds a new attack path, and must not reintroduce the "--show
// secretly attacks" bug fixed elsewhere in this project. carol's hash is
// trivially single-crackable (password == capitalised username) but is NOT
// in the potfile, so a correct --show run reports her as not-in-potfile and
// launches no single-crack pass at all.
func TestSingleNeverAttacksUnderShow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	potPath := filepath.Join(dir, "test.pot")

	carolDigest := mustHash(t, "Carol", "md5-pass-salt", "saltCarol")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "carol:"+carolDigest+":saltCarol\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "--pot", potPath,
			"--username", "--single", "--show", targetsFile})
	})
	if strings.Contains(stderr, "Single-crack:") {
		t.Fatalf("--show must never launch a single-crack pass:\n%s", stderr)
	}
	if strings.Contains(stderr, batchBannerPrefix) {
		t.Fatalf("--show must never launch a real attack at all:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Not in potfile") {
		t.Errorf("--show should report the target as not in the potfile, got:\n%s", stderr)
	}
}

// --left must reflect single-crack's own results: an account cracked by
// --single is not "left" for a follow-up pass, even when the main attack's
// wordlist would never have reached it either.
func TestSingleResultsReflectedInLeft(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "totally-unrelated-word\n")

	daveDigest := mustHash(t, "Dave", "md5-pass-salt", "saltDave")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "dave:"+daveDigest+":saltDave\n")

	leftFile := filepath.Join(dir, "left.txt")
	exitCode = 0
	if err := runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
		"--no-pot", "--username", "--single", "--left", "-o", leftFile, targetsFile}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (single-crack should have cracked dave)", exitCode)
	}
	left := mustRead(t, leftFile)
	if strings.TrimSpace(left) != "" {
		t.Errorf("--left should be empty (dave was cracked by --single), got:\n%s", left)
	}
}
