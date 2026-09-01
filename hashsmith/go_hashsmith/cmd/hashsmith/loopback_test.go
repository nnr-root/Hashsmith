package main

// Tests for --loopback: feeding cracked plaintexts back as candidates within
// the same run (Task 3 of the distribution-and-pipeline plan).
//
// The central design fact these tests lean on: within ONE crackTargets call,
// every target that shares a mode/wordlist/rules configuration is tested
// against the SAME candidate stream already (multi-hash batching for raw
// digests, or an identical per-target dict/rules pass for salted ones). So a
// plaintext reachable by applying the configured rule(s) ONCE to a wordlist
// word is already found in the main pass, with no help from --loopback. To
// prove loopback earns its place, a test target's plaintext must be reachable
// only by applying a rule to a word that ISN'T itself in the wordlist — i.e.
// a plaintext recovered mid-run (or already sitting in the potfile) and fed
// back as a brand new candidate. That's what the rule-chain scenario below
// constructs, deliberately.

import (
	"path/filepath"
	"strings"
	"testing"
)

// twoLineLoopbackRules: rule 1 appends "2024" to a word; rule 2 capitalises
// and appends "!". Applied independently to wordlist word "summer" in a
// normal dict+rules pass, they give "summer2024" and "Summer!" — never
// "Summer2024!", which needs BOTH rules chained. Rule 2 applied to "summer",
// though, i.e. the word "summer2024" that only exists once rule 1 has
// already fired on some earlier pass, does yield "Summer2024!" — which is
// exactly what --loopback's second pass supplies: rule 2 re-applied, this
// time to the newly cracked "summer2024" rather than to the original word.
const twoLineLoopbackRules = "$2$0$2$4\nc$!\n"

// mustHash is a small helper for the salted-digest targets used throughout:
// hashCompatSaltedDigest already exists (pipeline_test.go) but returns an
// error this file wants to fail loudly on, not thread through every caller.
func mustHash(t *testing.T, plain, algo, salt string) string {
	t.Helper()
	h, err := hashCompatSaltedDigest(plain, algo, salt)
	if err != nil {
		t.Fatalf("hashCompatSaltedDigest(%q, %q, %q): %v", plain, algo, salt, err)
	}
	return h
}

// ── correctness: loopback reaches a target the main pass genuinely misses ──

// The main pass cracks target A ("summer2024", via wordlist word "summer" +
// rule 1). Target B ("Summer2024!") is unreachable in that same pass — it
// needs rule 2 applied to A's plaintext, not to any wordlist word. Baseline
// (no --loopback) leaves B uncracked; --loopback recovers it in exactly one
// extra pass, and --left must no longer report it once loopback does.
func TestLoopbackCracksViaRuleChain(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "decoy1\nsummer\ndecoy2\n")
	rulesFile := filepath.Join(dir, "rules.txt")
	mustWrite(t, rulesFile, twoLineLoopbackRules)

	targetA := mustHash(t, "summer2024", "md5-pass-salt", "saltA") + ":saltA"
	targetB := mustHash(t, "Summer2024!", "md5-pass-salt", "saltB") + ":saltB"
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, targetA+"\n"+targetB+"\n")

	// Baseline: without --loopback, B must NOT crack — proving this really is
	// a target the main pass can't reach on its own, not a coincidence.
	exitCode = 0
	stderrBase := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--rules", rulesFile, "--no-pot", targetsFile})
	})
	if exitCode == 0 {
		t.Fatalf("baseline (no --loopback): expected target B to remain uncracked, got exitCode=0")
	}
	if strings.Contains(stderrBase, "Loopback pass") {
		t.Fatalf("baseline (no --loopback flag) must never run a loopback pass:\n%s", stderrBase)
	}

	// With --loopback: A cracks in the main pass, its plaintext feeds a
	// second pass where rule 2 reaches B.
	exitCode = 0
	leftFile := filepath.Join(dir, "left.txt")
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--rules", rulesFile, "--no-pot", "--loopback",
			"--left", "-o", leftFile, targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("--loopback: expected both targets cracked (exitCode=0), got %d\nstderr:\n%s", exitCode, stderr)
	}
	passes := strings.Count(stderr, "Loopback pass")
	if passes != 1 {
		t.Errorf("expected exactly 1 loopback pass, got %d\nstderr:\n%s", passes, stderr)
	}
	left := strings.TrimSpace(mustRead(t, leftFile))
	if left != "" {
		t.Errorf("--left after --loopback cracked everything should be empty, got %q", left)
	}
}

// ── termination: a pass that finds nothing new stops the loop, exactly once ─

// Target A cracks in the main pass exactly as above, feeding "summer2024" to
// loopback. Target C's plaintext is unrelated to anything reachable from
// "summer2024" through either rule, so loopback's one pass must find nothing
// — and, critically, must not spin a second, redundant pass once its feed
// drains empty.
func TestLoopbackStopsAfterOneEmptyPass(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "summer\n")
	rulesFile := filepath.Join(dir, "rules.txt")
	mustWrite(t, rulesFile, twoLineLoopbackRules)

	targetA := mustHash(t, "summer2024", "md5-pass-salt", "saltA") + ":saltA"
	targetC := mustHash(t, "totally-unrelated-xyz", "md5-pass-salt", "saltC") + ":saltC"
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, targetA+"\n"+targetC+"\n")

	leftFile := filepath.Join(dir, "left.txt")
	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--rules", rulesFile, "--no-pot", "--loopback",
			"--left", "-o", leftFile, targetsFile})
	})
	if exitCode == 0 {
		t.Fatalf("target C should remain uncracked (unrelated plaintext), got exitCode=0\nstderr:\n%s", stderr)
	}
	passes := strings.Count(stderr, "Loopback pass")
	if passes != 1 {
		t.Errorf("a pass that recovers nothing new must stop the loop after exactly 1 pass, got %d\nstderr:\n%s",
			passes, stderr)
	}
	left := strings.TrimSpace(mustRead(t, leftFile))
	if left != targetC {
		t.Errorf("--left = %q, want just target C (%q) left over", left, targetC)
	}
}

// ── multi-pass: a real chain runs more than one pass, and stops once done ──

// Extends the A -> B chain with a third target D reachable only from B's
// plaintext via a third rule — so loopback must run TWO productive passes
// (pass 1: A's plaintext cracks B; pass 2: B's plaintext, freshly recovered,
// cracks D) and then stop, since nothing remains.
func TestLoopbackRunsMultiplePassesUntilExhausted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "summer\n")
	rulesFile := filepath.Join(dir, "rules.txt")
	// rule 3 appends "42" — reaches D only when applied to B's plaintext.
	mustWrite(t, rulesFile, twoLineLoopbackRules+"$4$2\n")

	targetA := mustHash(t, "summer2024", "md5-pass-salt", "saltA") + ":saltA"
	targetB := mustHash(t, "Summer2024!", "md5-pass-salt", "saltB") + ":saltB"
	targetD := mustHash(t, "Summer2024!42", "md5-pass-salt", "saltD") + ":saltD"
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, targetA+"\n"+targetB+"\n"+targetD+"\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--rules", rulesFile, "--no-pot", "--loopback", targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("expected all three targets cracked across the chain, exitCode=%d\nstderr:\n%s", exitCode, stderr)
	}
	passes := strings.Count(stderr, "Loopback pass")
	if passes != 2 {
		t.Errorf("expected exactly 2 loopback passes (A->B, then B->D), got %d\nstderr:\n%s", passes, stderr)
	}
}

// ── --show must never attack, --loopback included ──────────────────────────

func TestLoopbackNeverRunsUnderShow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	potPath := filepath.Join(dir, "test.pot")

	p, err := loadPotfile(potPath)
	if err != nil {
		t.Fatal(err)
	}
	crackedHash := md5hex("password")
	p.add(crackedHash, "password")
	uncrackedHash := md5hex("zzz-never-attacked")

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, crackedHash+"\n"+uncrackedHash+"\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"--pot", potPath, "--show", "--loopback", targetsFile})
	})
	if strings.Contains(stderr, "Loopback pass") {
		t.Fatalf("--show must never launch a loopback pass:\n%s", stderr)
	}
	if strings.Contains(stderr, batchBannerPrefix) {
		t.Fatalf("--show must never launch a real attack at all:\n%s", stderr)
	}
}

// ── the potfile is an explicit, testable loopback source ───────────────────

// A plaintext already on record in the potfile — from some earlier,
// unrelated crack, not this run — must be fed to loopback's first pass
// verbatim (no rule required: the base candidate is always tried). This also
// proves --skip/--limit, set here to values that would starve the tiny
// one-word loopback candidate file if wrongly forwarded into it, bound only
// the MAIN attack's keyspace, never a loopback pass.
func TestLoopbackSeedsFromPotfileIgnoringSkipLimit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	potPath := filepath.Join(dir, "test.pot")

	p, err := loadPotfile(potPath)
	if err != nil {
		t.Fatal(err)
	}
	// An unrelated hash/plaintext pair already sitting in the potfile before
	// this run starts.
	p.add(md5hex("some-other-account-password"), "known-plain")

	target := mustHash(t, "known-plain", "md5-pass-salt", "saltX") + ":saltX"
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target+"\n")

	// A wordlist with nothing relevant, so the main pass truly cannot crack
	// the target on its own — only the potfile-seeded loopback pass can.
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "irrelevant1\nirrelevant2\nirrelevant3\nirrelevant4\nirrelevant5\nirrelevant6\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		// --skip 5 --limit 1 would, if wrongly threaded into the loopback
		// pass, skip past the single candidate ("known-plain") in that
		// pass's one-word temp wordlist (index 0 < skip 5) and find nothing.
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--pot", potPath, "--loopback", "--skip", "5", "--limit", "1", targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("potfile-seeded loopback pass should have cracked the target, exitCode=%d\nstderr:\n%s",
			exitCode, stderr)
	}
	passes := strings.Count(stderr, "Loopback pass")
	if passes != 1 {
		t.Errorf("expected exactly 1 loopback pass, got %d\nstderr:\n%s", passes, stderr)
	}
}
