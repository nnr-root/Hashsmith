package main

// Tests for --username, --left and --outfile-format — the "fit into a
// pipeline" half of distributed cracking: consuming user:hash input and
// handing uncracked targets to the next tool.

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── --username: first-colon-only split ──────────────────────────────────────

func TestUsernameSplitsFirstColonOnly(t *testing.T) {
	cases := []struct{ raw, user, hash string }{
		{"alice:5f4dcc3b5aa765d61d8327deb882cf99", "alice", "5f4dcc3b5aa765d61d8327deb882cf99"},
		// Everything after the FIRST colon is the hash, further colons
		// included — required for IKE/IPMI/CHAP/CMS/1Password/etc., which
		// embed colons in the target itself.
		{"bob:hash:with:colons:in:it", "bob", "hash:with:colons:in:it"},
		{"5f4dcc3b5aa765d61d8327deb882cf99", "", "5f4dcc3b5aa765d61d8327deb882cf99"},
		{"", "", ""},
	}
	for _, c := range cases {
		u, h := splitUsername(c.raw)
		if u != c.user || h != c.hash {
			t.Errorf("splitUsername(%q) = (%q, %q), want (%q, %q)", c.raw, u, h, c.user, c.hash)
		}
	}
}

// A "user:hash" input, cracked with --username, must crack the hash and show
// the username alongside the result.
func TestUsernameCracksAndRecordsResult(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\n")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, "alice:"+md5hex("password")+"\n")
	out := filepath.Join(dir, "out.txt")

	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot",
		"--username", "-o", out, targetsFile}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (the hash was crackable)", exitCode)
	}
	got := mustRead(t, out)
	if strings.TrimSpace(got) != "password" {
		t.Errorf("-o content = %q, want %q (default format is unchanged by --username)", got, "password")
	}
}

// TRAP 1: --username against username-less "hash:salt" input (a real shape —
// many of hashsmith's formats embed colons in the target itself) must refuse
// outright rather than silently treating the hash as a username and the salt
// as a bogus hash, which would make every target quietly "fail to crack".
func TestUsernameMisuseGuardRefusesHashSaltLine(t *testing.T) {
	digest, err := hashCompatSaltedDigest("password", "md5-pass-salt", "abc123salt")
	if err != nil {
		t.Fatal(err)
	}
	line := digest + ":abc123salt" // a legitimate hash:salt target — NOT user:hash

	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\n")
	t.Setenv("HOME", t.TempDir())

	// Baseline: without --username this cracks normally.
	exitCode = 0
	if err := runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl, "--no-pot", line}); err != nil {
		t.Fatalf("baseline crack (no --username) failed: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("baseline should have cracked, exitCode=%d", exitCode)
	}

	// Same line, --username added: must refuse rather than misread the hash
	// as a username and the salt as the "hash".
	exitCode = 0
	err = runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl, "--no-pot", "--username", line})
	if err == nil {
		t.Fatal("--username against a hash:salt line (no real username) should refuse, " +
			"not silently crack garbage")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("refusal error should explain the --username misuse, got: %v", err)
	}
}

// The auto-detect form of the same guard: no -t given, so the guard relies on
// detectHashTypes rather than a specific type's verifyCandidate probe.
func TestUsernameMisuseGuardAutoDetect(t *testing.T) {
	// "not-a-hash-at-all" doesn't look like any known hash type.
	_, err := parseUsernameLines([]string{"realuser:not-a-hash-at-all"}, "", "", "prefix")
	if err == nil {
		t.Fatal("splitting off a hash portion that detects as no known type should refuse")
	}
	// But a plain, colon-free line (no username at all) must still pass
	// through untouched even when it wouldn't detect as anything either —
	// there was nothing to misread here.
	lines, err := parseUsernameLines([]string{"not-a-hash-at-all"}, "", "", "prefix")
	if err != nil {
		t.Fatalf("a colon-free line must never be refused: %v", err)
	}
	if len(lines) != 1 || lines[0].username != "" || lines[0].hash != "not-a-hash-at-all" {
		t.Errorf("unexpected parse: %+v", lines)
	}
}

// ── TRAP 2: -o must not truncate across multiple results ───────────────────

// Cracking several targets with -o must leave every result in the file, not
// just the last one written — the bug this task's brief calls out at
// crack.go:653-655 (doCrack) and its twin in emitResult: both used a single
// os.WriteFile per call, which O_TRUNCs, so the batch path's write and each
// subsequent per-target write clobbered everything before it.
func TestOutfileDoesNotTruncateAcrossResults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	words := []string{"password", "admin", "letmein", "qwerty", "dragon"}
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, strings.Join(words, "\n")+"\n")

	hashes := make([]string, len(words))
	for i, w := range words {
		hashes[i] = md5hex(w)
	}
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, strings.Join(hashes, "\n")+"\n")
	out := filepath.Join(dir, "out.txt")

	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot",
		"-o", out, targetsFile}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("all %d targets should have cracked, exitCode=%d", len(words), exitCode)
	}

	got := strings.TrimRight(mustRead(t, out), "\n")
	lines := strings.Split(got, "\n")
	if len(lines) != len(words) {
		t.Fatalf("-o has %d line(s), want %d — every result must survive, not just the last:\n%s",
			len(lines), len(words), got)
	}
	want := map[string]bool{}
	for i, w := range words {
		want[hashes[i]+":"+w] = true
	}
	for _, l := range lines {
		if !want[l] {
			t.Errorf("unexpected line in -o output: %q", l)
		}
		delete(want, l)
	}
	if len(want) != 0 {
		t.Errorf("missing from -o output: %v", want)
	}
}

// The same truncation fix must hold on the single-target / per-target code
// path (not just the batch path) — several DIFFERENT-type targets (so none
// qualify for multi-hash batching) cracked in one run must all land in -o.
func TestOutfileDoesNotTruncatePerTargetPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\nadmin\n")

	// A salt forces every target down the slower per-target path in
	// crackTargets (see the `salt == ""` batch-mode gate), so this exercises
	// doCrack's own -o write, once per target, on the same file.
	t1, err := hashCompatSaltedDigest("password", "md5-pass-salt", "saltone")
	if err != nil {
		t.Fatal(err)
	}
	t2, err := hashCompatSaltedDigest("admin", "md5-pass-salt", "salttwo")
	if err != nil {
		t.Fatal(err)
	}
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, t1+":saltone\n"+t2+":salttwo\n")
	out := filepath.Join(dir, "out.txt")

	exitCode = 0
	if err := runCrack([]string{"-t", "md5-pass-salt", "-M", "dict", "-w", wl, "--no-pot",
		"-o", out, targetsFile}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("both targets should have cracked, exitCode=%d", exitCode)
	}
	got := strings.TrimRight(mustRead(t, out), "\n")
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("-o has %d line(s), want 2 (both per-target results), got:\n%s", len(lines), got)
	}
	foundPassword, foundAdmin := false, false
	for _, l := range lines {
		switch l {
		case "password":
			foundPassword = true
		case "admin":
			foundAdmin = true
		}
	}
	if !foundPassword || !foundAdmin {
		t.Errorf("-o output missing a result: %q", got)
	}
}

// ── --outfile-format ─────────────────────────────────────────────────────────

func TestOutfileFormatFields(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\n")
	target := md5hex("password")

	cases := []struct{ spec, want string }{
		{"2", "password"},
		{"1,2", target + ":password"},
		{"3", hex.EncodeToString([]byte("password"))},
		{"1,2,3", target + ":password:" + hex.EncodeToString([]byte("password"))},
	}
	for _, c := range cases {
		out := filepath.Join(dir, "out-"+strings.ReplaceAll(c.spec, ",", "_")+".txt")
		exitCode = 0
		if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot",
			"--outfile-format", c.spec, "-o", out, target}); err != nil {
			t.Fatalf("runCrack(--outfile-format %s): %v", c.spec, err)
		}
		got := strings.TrimSpace(mustRead(t, out))
		if got != c.want {
			t.Errorf("--outfile-format %s: got %q, want %q", c.spec, got, c.want)
		}
	}
}

func TestOutfileFormatRejectsUnsupportedField(t *testing.T) {
	if err := runCrack([]string{"--outfile-format", "4", "-t", "md5", "--no-pot", "deadbeef"}); err == nil {
		t.Error("--outfile-format 4 (unsupported field) should be rejected")
	}
	if err := runCrack([]string{"--outfile-format", "not-a-number", "-t", "md5", "--no-pot", "deadbeef"}); err == nil {
		t.Error("--outfile-format with a non-numeric field should be rejected")
	}
}

// --outfile-format's default (flag not given) must reproduce the exact -o
// shape that existed before this flag did: bare password for a single
// target, "hash:password" for the multi-hash batch path.
func TestOutfileFormatDefaultUnchanged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\n")
	target := md5hex("password")
	out := filepath.Join(dir, "out.txt")

	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot", "-o", out, target}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if got := strings.TrimSpace(mustRead(t, out)); got != "password" {
		t.Errorf("default single-target -o = %q, want %q", got, "password")
	}
}

// ── --left: the round-trip correctness property ─────────────────────────────

// The core property: --left's output, re-fed as input, must produce exactly
// the set of targets that weren't cracked — no more, no fewer.
func TestLeftRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\nadmin\n")

	findable := []string{md5hex("password"), md5hex("admin")}
	notFindable := []string{md5hex("zzz-not-in-list-1"), md5hex("zzz-not-in-list-2")}
	all := append(append([]string{}, findable...), notFindable...)
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, strings.Join(all, "\n")+"\n")

	leftFile := filepath.Join(dir, "left1.txt")
	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot",
		"--left", "-o", leftFile, targetsFile}); err != nil {
		t.Fatalf("runCrack pass 1: %v", err)
	}
	gotSet := readLineSet(t, leftFile)
	wantSet := toSet(notFindable)
	assertSetsEqual(t, "pass 1 --left", gotSet, wantSet)

	// Round trip: feed pass 1's --left output back in as pass 2's input.
	leftFile2 := filepath.Join(dir, "left2.txt")
	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot",
		"--left", "-o", leftFile2, leftFile}); err != nil {
		t.Fatalf("runCrack pass 2: %v", err)
	}
	got2Set := readLineSet(t, leftFile2)
	assertSetsEqual(t, "pass 2 --left (round trip)", got2Set, wantSet)
}

// --username input must round-trip through --left with its usernames intact
// — the leftover line is the ORIGINAL "user:hash" text, not just the hash.
func TestLeftRoundTripPreservesUsernames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\n")

	crackedLine := "alice:" + md5hex("password")
	uncrackedHash := md5hex("zzz-nobody-guesses-this")
	uncrackedLine := "bob:" + uncrackedHash
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, crackedLine+"\n"+uncrackedLine+"\n")

	leftFile := filepath.Join(dir, "left.txt")
	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot",
		"--username", "--left", "-o", leftFile, targetsFile}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	got := strings.TrimSpace(mustRead(t, leftFile))
	if got != uncrackedLine {
		t.Fatalf("--left output = %q, want %q (the ORIGINAL user:hash line, verbatim)", got, uncrackedLine)
	}
	// Confirm the username actually survives a second --username split, not
	// merely as incidental text in the line.
	u, h := splitUsername(got)
	if u != "bob" || h != uncrackedHash {
		t.Errorf("re-split of leftover line: user=%q hash=%q, want user=%q hash=%q", u, h, "bob", uncrackedHash)
	}
}

// A potfile hit must count as cracked for --left, even when nothing is
// attacked this run (e.g. a hash cracked by an earlier invocation) — a second
// pass must not redo work the first pass already recorded.
func TestLeftTreatsPotfileHitAsCracked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	potPath := filepath.Join(dir, "test.pot")
	crackedHash := md5hex("password")
	uncrackedHash := md5hex("zzz-uncracked-xyz")

	p, err := loadPotfile(potPath)
	if err != nil {
		t.Fatal(err)
	}
	p.add(crackedHash, "password")

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, crackedHash+"\n"+uncrackedHash+"\n")
	// An empty wordlist (no matches at all) proves the uncracked hash lands
	// in --left because it's genuinely not cracked, not by coincidence.
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "not-the-password\n")
	leftFile := filepath.Join(dir, "left.txt")

	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--pot", potPath,
		"--left", "-o", leftFile, targetsFile}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	got := strings.TrimSpace(mustRead(t, leftFile))
	if got != uncrackedHash {
		t.Fatalf("--left output = %q, want %q (the potfile hit must not reappear as \"left\")", got, uncrackedHash)
	}
}

// --left composes with --show: a multi-target --show run must still never
// attack (see the showOnly gate in crackTargets), and --left reports exactly
// the targets --show didn't find in the potfile.
//
// IMPORTANT: the leftover set alone cannot prove --show skipped the attack —
// an unfindable hash produces the identical "not found" leftover whether or
// not a real attack was launched against it (the built-in wordlist won't
// crack "zzz-never-attacked" either way). A version of this test that only
// checked the leftover set passed even after the showOnly gate in
// crackTargets was reverted, silently reintroducing the bug it exists to
// catch. So this also asserts on something that DOES differ between the two
// worlds: runBatch's own batchBannerPrefix banner, which is only ever
// printed when a real attack is actually launched — its presence in stderr
// is direct proof an attack ran, not just a coincidental "not found".
func TestShowComposesWithLeft(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	potPath := filepath.Join(dir, "test.pot")
	crackedHash := md5hex("password")
	uncrackedHash := md5hex("zzz-never-attacked")

	p, err := loadPotfile(potPath)
	if err != nil {
		t.Fatal(err)
	}
	p.add(crackedHash, "password")

	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, crackedHash+"\n"+uncrackedHash+"\n")
	leftFile := filepath.Join(dir, "left.txt")

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"--pot", potPath, "--show", "--left", "-o", leftFile, targetsFile})
	})

	if strings.Contains(stderr, batchBannerPrefix) {
		t.Fatalf("--show launched a real attack (the multi-hash batch banner is in stderr) — "+
			"--show must only report potfile hits, never attack:\n%s", stderr)
	}

	got := strings.TrimSpace(mustRead(t, leftFile))
	if got != uncrackedHash {
		t.Fatalf("--show --left output = %q, want %q", got, uncrackedHash)
	}
}

// --left with no -o writes to stdout.
func TestLeftWritesToStdoutWithoutOutfile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "password\n")
	uncrackedHash := md5hex("zzz-not-found-here")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, md5hex("password")+"\n"+uncrackedHash+"\n")

	exitCode = 0
	out := captureStdout(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot", "--left", targetsFile})
	})
	if strings.TrimSpace(out) != uncrackedHash {
		t.Errorf("stdout --left output = %q, want %q", out, uncrackedHash)
	}
}

// ── test helpers ─────────────────────────────────────────────────────────────

// captureStderr runs fn while capturing everything written to os.Stderr —
// the mirror of stdout_test.go's captureStdout. Used where the thing that
// actually distinguishes two behaviors is what gets logged, not the final
// on-disk result (see TestShowComposesWithLeft: an unfindable hash's
// "not found" leftover looks identical whether or not an attack was ever
// launched against it, so the leftover set alone can't prove --show skipped
// the attack — only the absence of the attack's own log output can).
func captureStderr(t *testing.T, fn func() error) string {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	done := make(chan string)
	go func() {
		var sb strings.Builder
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			sb.WriteString(sc.Text())
			sb.WriteByte('\n')
		}
		done <- sb.String()
	}()
	err := fn()
	w.Close()
	os.Stderr = old
	out := <-done
	if err != nil {
		t.Fatalf("captureStderr: %v", err)
	}
	return out
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func readLineSet(t *testing.T, path string) map[string]bool {
	t.Helper()
	content := mustRead(t, path)
	out := map[string]bool{}
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if l != "" {
			out[l] = true
		}
	}
	return out
}

func toSet(items []string) map[string]bool {
	out := map[string]bool{}
	for _, i := range items {
		out[i] = true
	}
	return out
}

func assertSetsEqual(t *testing.T, label string, got, want map[string]bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %d item(s), want %d — got=%v want=%v", label, len(got), len(want), got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("%s: missing %q", label, k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s: unexpected %q", label, k)
		}
	}
}
