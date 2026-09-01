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

// ── shared hashes: two accounts, one unsalted digest ────────────────────────
//
// cc.userOf/cc.rawOf are keyed by HASH, not by input line, so when two
// different usernames map to the same hash (a shared weak password on an
// unsalted digest — common in real dumps, and exactly why multi-hash mode and
// --loopback exist), a naive lookup keyed by hash only ever sees ONE of them.
// runSingleCrack must seed from every username associated with a hash, or it
// silently misses a password reachable from an account it simply didn't pick.
//
// The password below is reachable only from carol's login (capitalised),
// never mallory's. The two tests below swap which one is parsed first, so
// neither a "last username wins" bug (the one actually found) nor a
// hypothetical "first username wins" fix can pass both.

// carol parsed FIRST, mallory SECOND. A "last username wins" implementation
// seeds only from mallory and must miss this.
func TestSingleCrackSharedHashSeedsFromAllUsernames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "totally-unrelated-word\n")

	hash := md5hex("Carol") // carol's own capitalised-username seed
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "carol:"+hash+"\nmallory:"+hash+"\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("shared hash should have cracked from carol's (first-parsed) seed; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Found: Carol") {
		t.Errorf("expected the shared hash to crack as %q; stderr:\n%s", "Carol", stderr)
	}
}

// Same shared hash, opposite parse order: mallory FIRST, carol SECOND. This
// guards against the test only passing by accident of a "first username
// wins" fix rather than a true union of every associated username.
func TestSingleCrackSharedHashSeedsFromAllUsernamesReversed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "totally-unrelated-word\n")

	hash := md5hex("Carol")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "mallory:"+hash+"\ncarol:"+hash+"\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("shared hash should have cracked from carol's (second-parsed) seed; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Found: Carol") {
		t.Errorf("expected the shared hash to crack as %q; stderr:\n%s", "Carol", stderr)
	}
}

// ── gecosSeeds: seed generation from a GECOS/real-name field ───────────────

// The full derivation set for a two-word name, mirroring JtR's own
// single-crack behaviour for "John Smith".
func TestGecosSeedsFromFullName(t *testing.T) {
	got := map[string]bool{}
	for _, s := range gecosSeeds("John Smith", nil) {
		got[s] = true
	}
	want := []string{"john", "smith", "johnsmith", "smithjohn", "jsmith", "johns", "smithj", "john.smith"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("gecosSeeds(%q) missing %q (got %v)", "John Smith", w, keys(got))
		}
	}
	if len(got) != len(want) {
		t.Errorf("gecosSeeds(%q) = %v, want exactly %v (extra/unexpected seeds)", "John Smith", keys(got), want)
	}
}

// GECOS is comma-separated (name,room,work-phone,home-phone); only the FIRST
// field is a name. A room number or phone extension in a later field must
// never leak into the seed list.
func TestGecosSeedsIgnoresTrailingCommaFields(t *testing.T) {
	got := map[string]bool{}
	for _, s := range gecosSeeds("John Smith,Room 5,x1234,555-0100", nil) {
		got[s] = true
	}
	if !got["jsmith"] {
		t.Errorf("gecosSeeds with trailing comma fields missing %q (got %v)", "jsmith", keys(got))
	}
	for bad := range got {
		if strings.Contains(bad, "room") || strings.Contains(bad, "1234") || strings.Contains(bad, "0100") {
			t.Errorf("gecosSeeds leaked a trailing comma field into a seed: %q (got %v)", bad, keys(got))
		}
	}
}

// An empty GECOS field yields no seeds — never a seed derived from "".
func TestGecosSeedsEmpty(t *testing.T) {
	if s := gecosSeeds("", nil); len(s) != 0 {
		t.Errorf("gecosSeeds(\"\") = %v, want none", s)
	}
}

// A GECOS field that is only room/phone info, with an empty name field
// (",Room 12,555-1234"), must also yield no seeds — there is no name to
// derive anything from.
func TestGecosSeedsRoomOnlyNoName(t *testing.T) {
	if s := gecosSeeds(",Room 12,555-1234", nil); len(s) != 0 {
		t.Errorf("gecosSeeds with no name field = %v, want none", s)
	}
}

// A single-word name has no second part to pair with — only the "part
// alone" seed is produced, and derivation must not panic reaching for a
// nonexistent parts[1].
func TestGecosSeedsSingleWordName(t *testing.T) {
	got := gecosSeeds("Cher", nil)
	if len(got) != 1 || got[0] != "cher" {
		t.Errorf("gecosSeeds(%q) = %v, want exactly [\"cher\"]", "Cher", got)
	}
}

// Non-ASCII names must split and lowercase correctly (rune-aware, not byte
// indexing) rather than mangling multi-byte runes.
func TestGecosSeedsNonASCII(t *testing.T) {
	got := map[string]bool{}
	for _, s := range gecosSeeds("José García", nil) {
		got[s] = true
	}
	if !got["josé"] || !got["garcía"] {
		t.Errorf("gecosSeeds(%q) missing base name parts, got %v", "José García", keys(got))
	}
	if !got["josé.garcía"] {
		t.Errorf("gecosSeeds(%q) missing dot-joined form, got %v", "José García", keys(got))
	}
}

// A very long GECOS field (many extra words: middle names, titles, suffixes)
// must not explode the seed list — only the first two name parts are ever
// used, keeping the count bounded regardless of field length.
func TestGecosSeedsVeryLongFieldStaysBounded(t *testing.T) {
	long := "John Quincy Adams Smith Jones Williams Brown Davis Miller Wilson Moore Taylor Anderson Thomas Jackson"
	got := gecosSeeds(long, nil)
	if len(got) > 8 {
		t.Errorf("gecosSeeds on a very long name produced %d seeds (%v), want <= 8 (only first two parts used)", len(got), got)
	}
	for _, s := range got {
		if strings.Contains(s, "jackson") || strings.Contains(s, "thomas") {
			t.Errorf("gecosSeeds used a part beyond the first two: %q in %v", s, got)
		}
	}
}

// gecosSeeds must skip anything already in the caller's existing set — a
// name that reduces to the same candidate as a username-derived seed must
// not double the work.
func TestGecosSeedsDedupesAgainstExisting(t *testing.T) {
	existing := map[string]bool{"jsmith": true}
	got := map[string]bool{}
	for _, s := range gecosSeeds("John Smith", existing) {
		got[s] = true
	}
	if got["jsmith"] {
		t.Errorf("gecosSeeds should have skipped %q (already in existing), got %v", "jsmith", keys(got))
	}
	if !got["johnsmith"] {
		t.Errorf("gecosSeeds over-filtered: %q should still appear, got %v", "johnsmith", keys(got))
	}
}

// Every gecosSeeds candidate is lowercase — unlike singleSeeds, this
// function does not hand-generate case variants; the rule engine (-r) is
// relied on for that when it's used.
func TestGecosSeedsAllLowercase(t *testing.T) {
	for _, s := range gecosSeeds("John Smith", nil) {
		if s != strings.ToLower(s) {
			t.Errorf("gecosSeeds produced non-lowercase seed %q", s)
		}
	}
}

// ── --passwd: GECOS-derived seeds wired through runSingleCrack ─────────────

// passwdLine builds one /etc/passwd-format line: user:passwd:uid:gid:gecos:home:shell.
func passwdLine(user, gecos string) string {
	return user + ":x:1000:1000:" + gecos + ":/home/" + user + ":/bin/bash"
}

// The headline scenario: an account whose password derives from the
// person's NAME, not their login, is reached only once --passwd supplies
// the GECOS field. john's login is "john"; his password is "jdoe"
// (first-initial + GECOS surname "Doe") — unreachable from any
// username-derived seed ("john"/"John"/"JOHN"), reachable only via his own
// GECOS entry "John Doe".
func TestSingleCrackGecosReachesNameDerivedPassword(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "totally-unrelated-word\n")

	passwdFile := filepath.Join(dir, "passwd")
	mustWrite(t, passwdFile, passwdLine("john", "John Doe")+"\n")

	johnDigest := mustHash(t, "jdoe", "md5-pass-salt", "saltJohn")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "john:"+johnDigest+":saltJohn\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", "--passwd", passwdFile, targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("--single --passwd should have cracked john from his GECOS entry; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "user: john") {
		t.Errorf("expected john to be reported cracked, stderr:\n%s", stderr)
	}
}

// The same target, without --passwd: the GECOS-derived password must NOT be
// reachable — proving the previous test's success is actually attributable
// to --passwd, not to some other path.
func TestSingleCrackWithoutGecosMissesNameDerivedPassword(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "totally-unrelated-word\n")

	johnDigest := mustHash(t, "jdoe", "md5-pass-salt", "saltJohn")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "john:"+johnDigest+":saltJohn\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", targetsFile})
	})
	if exitCode == 0 {
		t.Fatalf("--single without --passwd should NOT have cracked john's GECOS-only password; stderr:\n%s", stderr)
	}
}

// THE PROPERTY THAT MATTERS, for GECOS: a name-derived seed from one
// account must never be tried against a different account's hash. mary's
// password is deliberately set to "jdoe" — the seed john's own GECOS entry
// ("John Doe") derives — while mary's own login ("mary") and her own GECOS
// ("Mary Smith") never produce "jdoe". If GECOS seeds leak across targets
// (or get pooled instead of kept per-account), mary's hash cracks; if
// isolation holds, she stays uncracked and john alone is found.
func TestSingleCrackGecosDoesNotCrossContaminate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "hunter2\nqwerty\nsunshine\ncorrecthorse\n")

	passwdFile := filepath.Join(dir, "passwd")
	mustWrite(t, passwdFile, passwdLine("john", "John Doe")+"\n"+passwdLine("mary", "Mary Smith")+"\n")

	johnDigest := mustHash(t, "jdoe", "md5-pass-salt", "saltJohn") // john's own GECOS seed
	maryDigest := mustHash(t, "jdoe", "md5-pass-salt", "saltMary") // leak bait: only john's GECOS produces "jdoe"
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "john:"+johnDigest+":saltJohn\nmary:"+maryDigest+":saltMary\n")

	leftFile := filepath.Join(dir, "left.txt")
	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", "--passwd", passwdFile,
			"--left", "-o", leftFile, targetsFile})
	})

	if !strings.Contains(stderr, "user: john") {
		t.Fatalf("john should have been cracked from his own GECOS seed; stderr:\n%s", stderr)
	}
	if strings.Contains(stderr, "user: mary") {
		t.Fatalf("CROSS-CONTAMINATION: mary's hash was cracked — john's GECOS seed leaked "+
			"across targets; stderr:\n%s", stderr)
	}

	left := mustRead(t, leftFile)
	if !strings.Contains(left, "mary:"+maryDigest+":saltMary") {
		t.Errorf("--left should still report mary as uncracked, got:\n%s", left)
	}
	if strings.Contains(left, "john:"+johnDigest+":saltJohn") {
		t.Errorf("john should not appear in --left output — he was cracked; got:\n%s", left)
	}
	if exitCode == 0 {
		t.Errorf("exitCode = 0, want nonzero (mary must remain uncracked)")
	}
}

// An account whose username is not a key in --passwd's map must still work
// via its ordinary username-derived seeds — no crash, no skip, no silent
// drop of that account. carol is absent from the passwd file entirely
// (which only lists unrelated accounts); her password is her own
// capitalised username, reachable with no GECOS help at all.
func TestSingleCrackPasswdAbsentAccountFallsBackToUsername(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "totally-unrelated-word\n")

	passwdFile := filepath.Join(dir, "passwd")
	mustWrite(t, passwdFile, passwdLine("root", "root")+"\n"+passwdLine("daemon", "")+"\n")

	carolDigest := mustHash(t, "Carol", "md5-pass-salt", "saltCarol")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "carol:"+carolDigest+":saltCarol\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", "--passwd", passwdFile, targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("carol (absent from --passwd) should still crack via her username seed; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "user: carol") {
		t.Errorf("expected carol to be reported cracked, stderr:\n%s", stderr)
	}
}

// Users present in --passwd with no matching target must simply be ignored
// — a real /etc/passwd has dozens of system accounts with no corresponding
// hash target at all. A passwd file full of such accounts must not cause a
// crash or an errant crack.
func TestSingleCrackPasswdIgnoresUsersWithNoTarget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "decoy.txt")
	mustWrite(t, wl, "totally-unrelated-word\n")

	passwdFile := filepath.Join(dir, "passwd")
	var lines []string
	for _, u := range []string{"root", "daemon", "bin", "sys", "mail", "nobody"} {
		lines = append(lines, passwdLine(u, u+" System Account"))
	}
	mustWrite(t, passwdFile, strings.Join(lines, "\n")+"\n")

	daveDigest := mustHash(t, "Dave", "md5-pass-salt", "saltDave")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "dave:"+daveDigest+":saltDave\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl,
			"--no-pot", "--username", "--single", "--passwd", passwdFile, targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("dave (not in passwd at all) should still crack via his username seed; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "user: dave") {
		t.Errorf("expected dave to be reported cracked, stderr:\n%s", stderr)
	}
}

// --show's contract is that it never attacks. --passwd adds a new input
// path (reading a passwd file); it must not reintroduce the "--show
// secretly attacks" bug this exact guarantee already exists to prevent for
// --single. carol's hash is trivially crackable via her GECOS entry but is
// NOT in the potfile, so a correct --show run reports her as not-in-potfile
// and launches no attack at all — with or without --passwd on the command
// line.
func TestSingleNeverAttacksUnderShowWithPasswd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	potPath := filepath.Join(dir, "test.pot")

	passwdFile := filepath.Join(dir, "passwd")
	mustWrite(t, passwdFile, passwdLine("carol", "Carol Jones")+"\n")

	carolDigest := mustHash(t, "cjones", "md5-pass-salt", "saltCarol") // reachable via GECOS, if attacked
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "carol:"+carolDigest+":saltCarol\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5-pass-salt", "--pot", potPath,
			"--username", "--single", "--passwd", passwdFile, "--show", targetsFile})
	})
	if strings.Contains(stderr, "Single-crack:") {
		t.Fatalf("--show must never launch a single-crack pass, even with --passwd:\n%s", stderr)
	}
	if strings.Contains(stderr, batchBannerPrefix) {
		t.Fatalf("--show must never launch a real attack at all:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Not in potfile") {
		t.Errorf("--show should report the target as not in the potfile, got:\n%s", stderr)
	}
}

// --passwd without --single is not an error — merely a no-op the run warns
// about instead of silently accepting. The ordinary dict attack (which does
// contain the password) must still run and succeed exactly as if --passwd
// had never been given.
func TestPasswdWithoutSingleWarnsAndIsNotError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password123\n")

	passwdFile := filepath.Join(dir, "passwd")
	mustWrite(t, passwdFile, passwdLine("someone", "Some One")+"\n")

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, md5hex("password123")+"\n")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl,
			"--no-pot", "--passwd", passwdFile, targetsFile})
	})
	if exitCode != 0 {
		t.Fatalf("--passwd without --single should not block the ordinary attack; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--passwd") || !strings.Contains(stderr, "ignored") {
		t.Errorf("expected a warning that --passwd is ignored without --single, got stderr:\n%s", stderr)
	}
}
