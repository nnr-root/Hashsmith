package main

// Every test here injects wordlistCandidatePaths (and, where "~" is involved,
// wordlistUserHomeDir) so nothing depends on what happens to be installed on
// the machine running the suite. A discovery test that only passes on a box
// with /usr/share/wordlists/rockyou.txt proves nothing on CI, where that file
// does not exist.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// useCandidates points discovery at an explicit list for the duration of a
// test and restores the real one afterwards.
func useCandidates(t *testing.T, paths ...string) {
	t.Helper()
	orig := wordlistCandidatePaths
	wordlistCandidatePaths = paths
	t.Cleanup(func() { wordlistCandidatePaths = orig })
}

// writeWordlist creates a wordlist file and returns its path.
func writeWordlist(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeGzipWordlist writes body gzip-compressed under the given name — which
// deliberately need not end in ".gz".
func writeGzipWordlist(t *testing.T, path, body string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeWordlist(t, path, buf.String())
}

// TestWordlistResolutionOrderIsDeterministic walks the candidate list from the
// bottom up, asserting at every step that the EARLIEST existing entry wins.
// The order is the contract: two machines that resolve differently produce
// --skip/--limit slices that do not line up, so a silent reordering is a real
// bug and not a cosmetic one.
func TestWordlistResolutionOrderIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(wordlistEnvVar, "")

	paths := []string{
		filepath.Join(dir, "1-usr-share.txt"),
		filepath.Join(dir, "2-usr-share-gz.txt"),
		filepath.Join(dir, "3-seclists.txt"),
		filepath.Join(dir, "4-usr-share-seclists.txt"),
		filepath.Join(dir, "5-homebrew.txt"),
		filepath.Join(dir, "6-usr-local.txt"),
		filepath.Join(dir, "7-home-wordlists.txt"),
		filepath.Join(dir, "8-home-local-share.txt"),
		filepath.Join(dir, "9-cwd.txt"),
	}
	useCandidates(t, paths...)

	// Nothing exists yet → the embedded list, and never an error.
	c, err := resolveWordlist("", false)
	if err != nil {
		t.Fatalf("no candidates present must not error: %v", err)
	}
	if c.path != "" || c.origin != wordlistEmbeddedDefault {
		t.Fatalf("empty machine: got %#v, want the embedded default", c)
	}

	// Create the candidates from last to first; after each one, resolution
	// must pick the newly created (earlier) entry.
	for i := len(paths) - 1; i >= 0; i-- {
		writeWordlist(t, paths[i], "word\n")
		c, err := resolveWordlist("", false)
		if err != nil {
			t.Fatalf("candidate %d: %v", i, err)
		}
		if c.path != paths[i] {
			t.Fatalf("with candidates %d..%d present, resolution picked %q; want %q "+
				"(the earlier entry must always win)", i, len(paths)-1, c.path, paths[i])
		}
		if c.origin != wordlistAutoDetected {
			t.Fatalf("candidate %d: origin = %v, want wordlistAutoDetected", i, c.origin)
		}
	}
}

// TestDefaultCandidateListIsTheDocumentedCrossProduct pins the real, shipped
// list. The list itself is the interface operators script against ("put it in
// /usr/share/wordlists and hashsmith finds it"), so a silent edit to it is a
// change in behaviour that a test should have to acknowledge.
//
// It is asserted as the STRUCTURE (dirs x filenames, directory-major) rather
// than as fifty-six literal strings, because that is the property that has to
// hold: every directory must be tried for both filenames, and adding a
// directory must not silently skip the gzip variant.
func TestDefaultCandidateListIsTheDocumentedCrossProduct(t *testing.T) {
	if got := len(wordlistCandidatePaths); got != len(wordlistCandidateDirs)*len(wordlistCandidateFilenames) {
		t.Fatalf("candidate list has %d entries; want %d dirs x %d filenames = %d",
			got, len(wordlistCandidateDirs), len(wordlistCandidateFilenames),
			len(wordlistCandidateDirs)*len(wordlistCandidateFilenames))
	}
	if len(wordlistCandidateFilenames) != 2 ||
		wordlistCandidateFilenames[0] != "rockyou.txt" ||
		wordlistCandidateFilenames[1] != "rockyou.txt.gz" {
		t.Fatalf("filenames = %q, want plain text before gzip", wordlistCandidateFilenames)
	}
	// Directory-major: both filenames in one directory before the next.
	i := 0
	for _, dir := range wordlistCandidateDirs {
		for _, name := range wordlistCandidateFilenames {
			want := joinWordlistCandidate(dir, name)
			if wordlistCandidatePaths[i] != want {
				t.Fatalf("candidate %d = %q, want %q (the cross product must be "+
					"directory-major: the ranking that matters is which install is "+
					"more trustworthy, not whether it is gzipped)",
					i, wordlistCandidatePaths[i], want)
			}
			i++
		}
	}
	// No duplicates: a repeated directory is a merge accident and would make
	// the listing lie about how many places were actually checked.
	seen := map[string]int{}
	for i, p := range wordlistCandidatePaths {
		if prev, dup := seen[p]; dup {
			t.Errorf("candidate %d duplicates candidate %d: %q", i, prev, p)
		}
		seen[p] = i
	}
	// The stat budget: this list is walked once per run, on the attack path.
	if len(wordlistCandidatePaths) > 80 {
		t.Errorf("%d candidates is beyond the \"a few dozen stats\" budget this list "+
			"is allowed to cost", len(wordlistCandidatePaths))
	}
}

// TestCandidateDirectoriesCoverTheKnownInstallLocations: the locations an
// operator is entitled to expect hashsmith to find on its own.
func TestCandidateDirectoriesCoverTheKnownInstallLocations(t *testing.T) {
	must := []string{
		"/usr/share/wordlists",                                     // Kali, Parrot, BlackArch
		"/usr/share/seclists/Passwords/Leaked-Databases",           // apt install seclists
		"/usr/share/SecLists/Passwords/Leaked-Databases",           // capitalisation varies
		"/usr/share/wordlists/seclists/Passwords/Leaked-Databases", // Kali symlink layout
		"/opt/SecLists/Passwords/Leaked-Databases",
		"~/SecLists/Passwords/Leaked-Databases",
		"/opt/wordlists",
		"/data/wordlists",
		"/usr/share/dict",
		"/usr/share/john",
		"/usr/share/hashcat",
		"/opt/homebrew/share/wordlists", // macOS brew
		"/opt/homebrew/share/seclists/Passwords/Leaked-Databases",
		"/usr/local/share/wordlists",
		"/usr/local/share/seclists/Passwords/Leaked-Databases",
		"~/wordlists",
		"~/.local/share/wordlists",
		"~/Downloads",
		"~/Desktop",
		".",
		`C:\wordlists`,
		`C:\Tools\wordlists`,
		"/mnt/c/wordlists", // WSL reaching the Windows side
		"/mnt/c/Tools/wordlists",
	}
	have := map[string]bool{}
	for _, d := range wordlistCandidateDirs {
		have[d] = true
	}
	for _, d := range must {
		if !have[d] {
			t.Errorf("candidate directories no longer cover %q", d)
		}
	}
	// No globbing, ever: a glob over /mnt/c/Users/*/Downloads would make the
	// order non-deterministic (which user's copy wins depends on directory
	// order) and would reach into other accounts' download folders.
	for _, d := range wordlistCandidateDirs {
		if strings.ContainsAny(d, "*?[") {
			t.Errorf("candidate directory %q contains a glob; the list must be a "+
				"deterministic stat list", d)
		}
	}
}

// TestCandidateDirectoryOrderPutsSystemInstallsFirst is the ordering contract,
// and it is a security property rather than a cosmetic one. ~/Downloads and
// the working directory are where a TRUNCATED or unofficial copy lands — the
// half-finished browser download, the 5 MiB "rockyou" from a random gist. If
// one of those outranked /usr/share/wordlists, a machine with both would
// quietly attack the small one and report "not found" for a keyspace it never
// searched.
func TestCandidateDirectoryOrderPutsSystemInstallsFirst(t *testing.T) {
	idx := map[string]int{}
	for i, d := range wordlistCandidateDirs {
		idx[d] = i
	}
	system := []string{
		"/usr/share/wordlists",
		"/usr/share/seclists/Passwords/Leaked-Databases",
		"/opt/SecLists/Passwords/Leaked-Databases",
		"/opt/homebrew/share/wordlists",
		"/usr/local/share/wordlists",
		"/opt/wordlists",
		"/data/wordlists",
	}
	user := []string{"~/wordlists", "~/.local/share/wordlists", "~/SecLists/Passwords/Leaked-Databases"}
	last := []string{"~/Downloads", "~/Desktop", "."}

	for _, s := range system {
		for _, u := range user {
			if idx[s] > idx[u] {
				t.Errorf("%s (system-wide, curated) must be checked before %s (user directory)", s, u)
			}
		}
	}
	for _, earlier := range append(append([]string{}, system...), user...) {
		for _, l := range last {
			if idx[earlier] > idx[l] {
				t.Errorf("%s must be checked before %s — %s is where a truncated or "+
					"unofficial copy lands, so it must lose to every deliberate install",
					earlier, l, l)
			}
		}
	}
	// And the three "last" entries really are last in the whole list.
	for _, l := range last {
		if idx[l] < len(wordlistCandidateDirs)-len(last) {
			t.Errorf("%s is at position %d of %d; the download/desktop/cwd entries must "+
				"be the final ones", l, idx[l], len(wordlistCandidateDirs))
		}
	}
	// The one pre-existing ordering promise: Homebrew's prefix before
	// /usr/local, as the shipped list has always had it.
	if idx["/opt/homebrew/share/wordlists"] > idx["/usr/local/share/wordlists"] {
		t.Error("/opt/homebrew/share/wordlists must stay ahead of /usr/local/share/wordlists")
	}
}

// TestJoinWordlistCandidateUsesThePlatformShape: filepath.Join would turn
// `C:\wordlists` into `C:\wordlists/rockyou.txt` on Unix and Clean "." down to
// a bare filename, losing the "./" that tells a reader of `hashsmith
// wordlists` the entry means the working directory.
func TestJoinWordlistCandidateUsesThePlatformShape(t *testing.T) {
	cases := map[[2]string]string{
		{"/usr/share/wordlists", "rockyou.txt"}: "/usr/share/wordlists/rockyou.txt",
		{".", "rockyou.txt"}:                    "./rockyou.txt",
		{"~/Downloads", "rockyou.txt.gz"}:       "~/Downloads/rockyou.txt.gz",
		{`C:\wordlists`, "rockyou.txt"}:         `C:\wordlists\rockyou.txt`,
		{`C:\Tools\wordlists`, "rockyou.txt"}:   `C:\Tools\wordlists\rockyou.txt`,
		{"/mnt/c/wordlists", "rockyou.txt"}:     "/mnt/c/wordlists/rockyou.txt",
		{"/opt/wordlists/", "rockyou.txt"}:      "/opt/wordlists/rockyou.txt",
	}
	for in, want := range cases {
		if got := joinWordlistCandidate(in[0], in[1]); got != want {
			t.Errorf("joinWordlistCandidate(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

// TestCandidateScanStaysCheap: the list is walked once per run, on the attack
// path, so widening it must not turn startup into a measurable cost. This is a
// floor-level assertion (it would catch a candidate list that started doing
// I/O per entry, or a glob), not a benchmark.
func TestCandidateScanStaysCheap(t *testing.T) {
	t.Setenv(wordlistEnvVar, "")
	start := time.Now()
	const iterations = 50
	for i := 0; i < iterations; i++ {
		wordlistCandidateStatus()
	}
	per := time.Since(start) / iterations
	if per > 50*time.Millisecond {
		t.Errorf("one full candidate scan took %s; %d stat calls should be well under a "+
			"millisecond and this list is resolved once per run", per, len(wordlistCandidatePaths))
	}
}

// TestWordlistFlagAlwaysWins: -w must skip discovery entirely — no env, no
// candidate, no --no-auto-wordlist may displace it. This is the compatibility
// guarantee: every invocation that worked before this feature behaves
// identically.
func TestWordlistFlagAlwaysWins(t *testing.T) {
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	env := writeWordlist(t, filepath.Join(dir, "env.txt"), "env\n")
	flagList := writeWordlist(t, filepath.Join(dir, "flag.txt"), "flag\n")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, env)

	c, err := resolveWordlist(flagList, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.path != flagList {
		t.Fatalf("-w %q was displaced by %q", flagList, c.path)
	}
	if c.origin != wordlistFromFlag {
		t.Fatalf("origin = %v, want wordlistFromFlag", c.origin)
	}
	if c.autoDetected() {
		t.Error("-w must never be reported as auto-detected (it drives the distributed warning)")
	}

	// Even with --no-auto-wordlist, -w still wins.
	c, err = resolveWordlist(flagList, true)
	if err != nil || c.path != flagList {
		t.Fatalf("-w with --no-auto-wordlist: got (%#v, %v), want the flag path", c, err)
	}
}

// TestWordlistFlagIsNotValidatedAtResolveTime: a nonexistent -w must fail at
// open time with the same error it always produced, not at resolution with a
// new one, and it must NEVER fall through to a discovered list — that would
// silently attack a different keyspace than the operator named.
func TestWordlistFlagIsNotValidatedAtResolveTime(t *testing.T) {
	dir := t.TempDir()
	useCandidates(t, writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n"))
	t.Setenv(wordlistEnvVar, "")

	missing := filepath.Join(dir, "does-not-exist.txt")
	c, err := resolveWordlist(missing, false)
	if err != nil {
		t.Fatalf("resolution must not validate -w: %v", err)
	}
	if c.path != missing {
		t.Fatalf("a missing -w resolved to %q — it must never fall through to discovery", c.path)
	}
	if _, _, oerr := openWordlist(missing); oerr == nil {
		t.Error("opening a missing -w should still fail")
	}
}

// TestWordlistEnvOverride: $HASHSMITH_WORDLIST beats every candidate.
func TestWordlistEnvOverride(t *testing.T) {
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	env := writeWordlist(t, filepath.Join(dir, "env.txt"), "env\n")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, env)

	c, err := resolveWordlist("", false)
	if err != nil {
		t.Fatal(err)
	}
	if c.path != env || c.origin != wordlistFromEnv {
		t.Fatalf("got %#v, want the env path %q with origin wordlistFromEnv", c, env)
	}
	if c.autoDetected() {
		t.Error("an explicit env override is not auto-detection")
	}
}

// TestWordlistEnvUnreadableIsAnError: the operator named that file. Falling
// through to a candidate (or to the built-in list) would attack a different
// keyspace than they asked for and report "not found" as if it meant
// something.
func TestWordlistEnvUnreadableIsAnError(t *testing.T) {
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	useCandidates(t, cand)

	for _, bad := range []string{
		filepath.Join(dir, "no-such-file.txt"),
		dir, // a directory is not a wordlist
	} {
		t.Setenv(wordlistEnvVar, bad)
		c, err := resolveWordlist("", false)
		if err == nil {
			t.Fatalf("%s=%q resolved to %#v; want an error rather than a silent fall-through",
				wordlistEnvVar, bad, c)
		}
		if !strings.Contains(err.Error(), wordlistEnvVar) {
			t.Errorf("error should name %s so the operator knows what to fix: %v", wordlistEnvVar, err)
		}
	}
}

// TestNoAutoWordlistForcesEmbedded: the reproducibility escape hatch. It must
// beat both discovery and the environment, and it must say that it ignored the
// environment rather than leaving the operator wondering.
func TestNoAutoWordlistForcesEmbedded(t *testing.T) {
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, "")

	c, err := resolveWordlist("", true)
	if err != nil || c.path != "" || c.origin != wordlistEmbeddedDefault {
		t.Fatalf("got (%#v, %v), want the embedded default", c, err)
	}
	// Discovery never ran, so the line must not blame a missing install: the
	// candidate here exists and would have been picked without the flag.
	if strings.Contains(c.describe(), "no installed wordlist found") {
		t.Errorf("--no-auto-wordlist must not report \"nothing found\"; got %q", c.describe())
	}
	if !strings.Contains(c.describe(), "--no-auto-wordlist") {
		t.Errorf("the line must name the flag that chose the built-in list; got %q", c.describe())
	}
	if c.autoDetected() {
		t.Error("--no-auto-wordlist must not report auto-detection")
	}

	env := writeWordlist(t, filepath.Join(dir, "env.txt"), "env\n")
	t.Setenv(wordlistEnvVar, env)
	c, err = resolveWordlist("", true)
	if err != nil || c.path != "" {
		t.Fatalf("--no-auto-wordlist with %s set: got (%#v, %v), want the embedded default",
			wordlistEnvVar, c, err)
	}
	if !c.envIgnored || !strings.Contains(c.describe(), wordlistEnvVar) {
		t.Errorf("the announcement must say %s was ignored, got %q", wordlistEnvVar, c.describe())
	}
}

// TestWordlistTildeExpansion covers the two "~" candidates against an injected
// home directory.
func TestWordlistTildeExpansion(t *testing.T) {
	home := t.TempDir()
	orig := wordlistUserHomeDir
	wordlistUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { wordlistUserHomeDir = orig })
	t.Setenv(wordlistEnvVar, "")
	useCandidates(t, "~/wordlists/rockyou.txt")

	if c, _ := resolveWordlist("", false); c.path != "" {
		t.Fatalf("nothing in the fake home yet, got %q", c.path)
	}
	want := writeWordlist(t, filepath.Join(home, "wordlists", "rockyou.txt"), "hunter2\n")
	c, err := resolveWordlist("", false)
	if err != nil || c.path != want {
		t.Fatalf("got (%#v, %v), want %q", c, err, want)
	}
}

// TestWordlistSkipsUnusableCandidates: a directory or a zero-byte placeholder
// at a candidate path must not be selected. A truncated
// /usr/share/wordlists/rockyou.txt (an interrupted install) would otherwise be
// chosen and the run would attack nothing while reporting "not found".
func TestWordlistSkipsUnusableCandidates(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(wordlistEnvVar, "")

	asDir := filepath.Join(dir, "a-directory")
	if err := os.MkdirAll(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	empty := writeWordlist(t, filepath.Join(dir, "empty.txt"), "")
	good := writeWordlist(t, filepath.Join(dir, "good.txt"), "hunter2\n")
	useCandidates(t, asDir, empty, good)

	c, err := resolveWordlist("", false)
	if err != nil || c.path != good {
		t.Fatalf("got (%#v, %v), want %q (directories and empty files must be skipped)", c, err, good)
	}
}

// ── gzip ────────────────────────────────────────────────────────────────────

// TestOpenWordlistDetectsGzipByMagicBytes: detection is by content, not by
// name. Both halves matter — a gzip stream named ".txt" must be decompressed,
// and a plain-text file named ".gz" must be read as text. Trusting the suffix
// would feed compressed bytes into the attack as candidate passwords.
func TestOpenWordlistDetectsGzipByMagicBytes(t *testing.T) {
	dir := t.TempDir()

	// gzip content under a name that does NOT say .gz
	misnamedGz := writeGzipWordlist(t, filepath.Join(dir, "list.txt"), "alpha\nbravo\ncharlie\n")
	rc, _, err := openWordlist(misnamedGz)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAllString(rc)
	rc.Close()
	if body != "alpha\nbravo\ncharlie\n" {
		t.Fatalf("gzip content under a .txt name was not decompressed: %q", body)
	}

	// plain content under a name that DOES say .gz
	misnamedPlain := writeWordlist(t, filepath.Join(dir, "list.gz"), "delta\necho\n")
	rc, _, err = openWordlist(misnamedPlain)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = readAllString(rc)
	rc.Close()
	if body != "delta\necho\n" {
		t.Fatalf("plain content under a .gz name was mangled: %q", body)
	}
}

func readAllString(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	return string(b), err
}

// TestCountWordlistLinesOnGzip: the count must be the DECOMPRESSED line count,
// must be repeatable, and must leave a complete stream for the attack that
// follows. Reporting a count derived from the compressed size, or the -1
// "uncountable" sentinel, would both be wrong here: a gzip file is a regular
// file, so re-opening it is free and the honest count is available.
func TestCountWordlistLinesOnGzip(t *testing.T) {
	dir := t.TempDir()
	gz := writeGzipWordlist(t, filepath.Join(dir, "rockyou.txt.gz"), "one\ntwo\n\nthree\n")

	if !wordlistCountable(gz) {
		t.Fatal("a gzip file is a regular file and must be countable")
	}
	for i := 0; i < 2; i++ {
		n, err := countWordlistLines(gz)
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if n != 3 {
			t.Fatalf("pass %d: count = %d, want 3 (blank lines skipped, decompressed)", i, n)
		}
	}
	// The stream the attack needs is still intact after counting.
	rc, _, err := openWordlist(gz)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAllString(rc)
	rc.Close()
	if body != "one\ntwo\n\nthree\n" {
		t.Fatalf("counting consumed the wordlist: %q", body)
	}
}

// TestPrintKeyspaceOnGzipIsExact: --keyspace prints a number scripts divide to
// build --skip/--limit slices. A previous bug in this repo printed -1 for a
// non-seekable wordlist; a gzip list must not reintroduce anything of that
// shape — it must print the real decompressed count.
func TestPrintKeyspaceOnGzipIsExact(t *testing.T) {
	dir := t.TempDir()
	gz := writeGzipWordlist(t, filepath.Join(dir, "words.txt.gz"), "a\nb\nc\nd\n")

	out := captureWordlistStdout(t, func() {
		if err := printKeyspace("dict", gz, "", "", 0, 0, princeDefaultElems, nil); err != nil {
			t.Fatalf("printKeyspace: %v", err)
		}
	})
	if strings.TrimSpace(out) != "4" {
		t.Fatalf("--keyspace on a gzip wordlist printed %q, want \"4\"", strings.TrimSpace(out))
	}
}

// TestDictAttackReadsGzipWordlist: end to end through the real attack path.
func TestDictAttackReadsGzipWordlist(t *testing.T) {
	dir := t.TempDir()
	gz := writeGzipWordlist(t, filepath.Join(dir, "words.txt.gz"), "first\nsecond\nneedle\n")

	var attempts int64
	result, err := dictAttack(context.Background(), gz, 0, 0, 2, &attempts, nil,
		func(candidate string) bool { return candidate == "needle" })
	if err != nil || result.password != "needle" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

// captureWordlistStdout runs fn with os.Stdout redirected and returns what it
// wrote. (stdout_test.go has a captureStdout for func() error; this one takes
// a plain func so a t.Fatalf inside it reports the real failure.)
func captureWordlistStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = orig
	w.Close()
	return <-done
}

// ── announcements and the distributed warning ───────────────────────────────

// TestAnnouncementAlwaysNamesTheSource: every origin produces exactly one line
// that identifies what will be attacked. "Which list did this run actually
// use?" must never be unanswerable from the output.
func TestAnnouncementAlwaysNamesTheSource(t *testing.T) {
	cases := []struct {
		name string
		c    wordlistChoice
		want []string
	}{
		{"flag", wordlistChoice{path: "/tmp/mine.txt", origin: wordlistFromFlag}, []string{"/tmp/mine.txt"}},
		{"flag gzip", wordlistChoice{path: "/tmp/mine.gz", origin: wordlistFromFlag, gzip: true}, []string{"/tmp/mine.gz", "gzip"}},
		{"env", wordlistChoice{path: "/tmp/env.txt", origin: wordlistFromEnv}, []string{"/tmp/env.txt", wordlistEnvVar}},
		{"auto", wordlistChoice{path: "/usr/share/wordlists/rockyou.txt", origin: wordlistAutoDetected},
			[]string{"/usr/share/wordlists/rockyou.txt", "auto-detected"}},
		{"auto gzip", wordlistChoice{path: "/usr/share/wordlists/rockyou.txt.gz", origin: wordlistAutoDetected, gzip: true},
			[]string{"rockyou.txt.gz", "auto-detected", "gzip"}},
		{"embedded", wordlistChoice{origin: wordlistEmbeddedDefault}, []string{defaultWordlistLabel}},
		{"embedded forced", wordlistChoice{origin: wordlistEmbeddedDefault, forced: true},
			[]string{defaultWordlistLabel, "--no-auto-wordlist"}},
		{"embedded forced over env", wordlistChoice{origin: wordlistEmbeddedDefault, forced: true, envIgnored: true},
			[]string{defaultWordlistLabel, "--no-auto-wordlist", wordlistEnvVar}},
	}
	for _, tc := range cases {
		got := tc.c.describe()
		if strings.Count(got, "\n") != 0 {
			t.Errorf("%s: the source line must be one line, got %q", tc.name, got)
		}
		if !strings.HasPrefix(got, "Wordlist: ") {
			t.Errorf("%s: %q should start with \"Wordlist: \"", tc.name, got)
		}
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: %q does not mention %q", tc.name, got, want)
			}
		}
	}
}

// TestDistributedWarningFiresOnlyForAutoDetection: --skip/--limit/--keyspace
// on an auto-detected list must warn (the slices only line up if every machine
// enumerates the same stream), and must NOT warn when the list was pinned with
// -w or the environment — a false warning on every pinned distributed run
// would train operators to ignore it.
func TestDistributedWarningFiresOnlyForAutoDetection(t *testing.T) {
	auto := wordlistChoice{path: "/usr/share/wordlists/rockyou.txt", origin: wordlistAutoDetected}
	pinnedFlag := wordlistChoice{path: "/usr/share/wordlists/rockyou.txt", origin: wordlistFromFlag}
	pinnedEnv := wordlistChoice{path: "/usr/share/wordlists/rockyou.txt", origin: wordlistFromEnv}
	embedded := wordlistChoice{origin: wordlistEmbeddedDefault}

	if w := distributedWordlistWarning(auto, 1000, 0, false); w == "" {
		t.Error("--skip on an auto-detected wordlist must warn")
	} else if !strings.Contains(w, "-w /usr/share/wordlists/rockyou.txt") {
		t.Errorf("the warning must name the -w to pin, got %q", w)
	}
	if distributedWordlistWarning(auto, 0, 500, false) == "" {
		t.Error("--limit on an auto-detected wordlist must warn")
	}
	if distributedWordlistWarning(auto, 0, 0, true) == "" {
		t.Error("--keyspace on an auto-detected wordlist must warn")
	}
	if w := distributedWordlistWarning(auto, 0, 0, false); w != "" {
		t.Errorf("an ordinary single-machine run must not warn, got %q", w)
	}
	for name, c := range map[string]wordlistChoice{"-w": pinnedFlag, "env": pinnedEnv, "embedded": embedded} {
		if w := distributedWordlistWarning(c, 100, 100, true); w != "" {
			t.Errorf("%s is identical on every machine and must not warn, got %q", name, w)
		}
	}
}

// TestModesWithoutAWordlistSkipResolution: -M brute and -M mask never open a
// wordlist, so they must not announce one — and must not fail on a broken
// $HASHSMITH_WORDLIST they were never going to read.
func TestModesWithoutAWordlistSkipResolution(t *testing.T) {
	t.Setenv(wordlistEnvVar, filepath.Join(t.TempDir(), "nonexistent.txt"))
	for _, mode := range []string{"brute", "mask"} {
		if _, err := resolveWordlistForMode(mode, "", false); err != nil {
			t.Errorf("-M %s must not resolve a wordlist it never reads: %v", mode, err)
		}
	}
	for _, mode := range []string{"dict", "hybrid", "combinator", "prince", "markov"} {
		if _, err := resolveWordlistForMode(mode, "", false); err == nil {
			t.Errorf("-M %s reads a wordlist, so a broken %s must fail loudly", mode, wordlistEnvVar)
		}
	}
}

// ── the resolved path really is what runs ───────────────────────────────────

// TestCrackUsesTheResolvedWordlist proves the resolution reaches the attack:
// the password lives ONLY in the discovered file, never in the embedded
// common.txt, so cracking it is only possible if discovery's path was threaded
// all the way through runCrack -> crackTargets -> dictAttack. The same path is
// what the feasibility guard and the progress pre-count measure.
func TestCrackUsesTheResolvedWordlist(t *testing.T) {
	dir := t.TempDir()
	secret := "zq7-discovered-only-passphrase"
	cand := writeWordlist(t, filepath.Join(dir, "found.txt"), "aaa\nbbb\n"+secret+"\n")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, "")

	sum := md5.Sum([]byte(secret))
	target := hex.EncodeToString(sum[:])

	prev := exitCode
	exitCode = 0
	t.Cleanup(func() { exitCode = prev })

	if err := runCrack([]string{"-t", "md5", "--no-pot", target}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d: the auto-detected wordlist never reached the attack "+
			"(the password is not in the embedded common.txt)", exitCode)
	}

	// --no-auto-wordlist must make the very same run fail to find it.
	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "--no-pot", "--no-auto-wordlist", target}); err != nil {
		t.Fatalf("runCrack --no-auto-wordlist: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d: --no-auto-wordlist must fall back to the built-in list, "+
			"which does not contain the password", exitCode)
	}
}

// TestKeyspaceUsesTheResolvedWordlist: --keyspace must report the count of the
// list the run would actually attack, not the embedded default's. A script
// dividing the embedded count while the machines attack rockyou would build
// slices covering a sixtieth of the real keyspace.
func TestKeyspaceUsesTheResolvedWordlist(t *testing.T) {
	dir := t.TempDir()
	useCandidates(t, writeWordlist(t, filepath.Join(dir, "found.txt"), "a\nb\nc\nd\ne\n"))
	t.Setenv(wordlistEnvVar, "")

	out := captureWordlistStdout(t, func() {
		if err := runCrack([]string{"-t", "md5", "--keyspace"}); err != nil {
			t.Fatalf("runCrack --keyspace: %v", err)
		}
	})
	if strings.TrimSpace(out) != "5" {
		t.Fatalf("--keyspace printed %q, want \"5\" (the discovered list's count)", strings.TrimSpace(out))
	}
}

// ── `hashsmith wordlists` ───────────────────────────────────────────────────

func TestWordlistsCommandListsCandidatesInOrder(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.txt")
	present := writeWordlist(t, filepath.Join(dir, "present.txt"), "hunter2\n")
	useCandidates(t, missing, present)
	t.Setenv(wordlistEnvVar, "")

	out := captureWordlistStdout(t, func() {
		if err := runWordlists(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, missing) || !strings.Contains(out, present) {
		t.Fatalf("listing must show every candidate, got:\n%s", out)
	}
	if strings.Index(out, missing) > strings.Index(out, present) {
		t.Error("candidates must be listed in resolution order")
	}
	if !strings.Contains(out, "Selected: "+present) {
		t.Errorf("listing must say which file a run would use, got:\n%s", out)
	}
	if !strings.Contains(out, wordlistEnvVar) {
		t.Error("listing must mention the environment override")
	}
}

func TestWordlistsCommandScanFindsAndSuggests(t *testing.T) {
	root := t.TempDir()
	big := strings.Repeat("password123\n", 200000) // comfortably over 1 MiB
	hit := writeWordlist(t, filepath.Join(root, "lists", "rockyou.txt"), big)
	writeWordlist(t, filepath.Join(root, "lists", "notes.txt"), "too small\n")
	useCandidates(t)
	t.Setenv(wordlistEnvVar, "")

	out := captureWordlistStdout(t, func() {
		if err := runWordlists([]string{"--scan", "--scan-root", root}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, hit) {
		t.Fatalf("--scan did not report %q:\n%s", hit, out)
	}
	if strings.Contains(out, "notes.txt") {
		t.Errorf("--scan must ignore files under the size floor:\n%s", out)
	}
	if !strings.Contains(out, wordlistEnvVar+"="+hit) {
		t.Errorf("--scan must suggest pinning the hit with %s:\n%s", wordlistEnvVar, out)
	}
}

// TestScanStopsWhenTheContextIsDone stands in for Ctrl-C: an already-cancelled
// context must end the walk immediately and report that the results are
// partial, rather than running to completion or discarding what it found.
func TestScanStopsWhenTheContextIsDone(t *testing.T) {
	root := t.TempDir()
	writeWordlist(t, filepath.Join(root, "rockyou.txt"), strings.Repeat("x\n", 600000))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hits, interrupted := scanForWordlists(ctx, []string{root}, wordlistScanMinSize)
	if !interrupted {
		t.Error("a cancelled scan must report itself as interrupted")
	}
	if len(hits) != 0 {
		t.Errorf("a scan cancelled before it started should return nothing, got %v", hits)
	}
}

func TestLooksLikeWordlistFile(t *testing.T) {
	const min = 1 << 20
	yes := []string{"rockyou.txt", "rockyou.txt.gz", "big.lst", "custom.dict", "rockyou", "passwords"}
	// Licence notices and changelogs are the commonest megabyte-scale .txt
	// files on a developer machine; a scan that suggests one of those instead
	// of a wordlist is worse than useless.
	no := []string{"photo.jpg", "libc.so.6", "archive.tar.gz", "readme.md",
		"ThirdPartyNotices.txt", "LICENSE.txt", "CHANGELOG.txt", "third_party_licenses.txt"}
	for _, n := range yes {
		if !looksLikeWordlistFile(n, min, min) {
			t.Errorf("%q should look like a wordlist", n)
		}
	}
	for _, n := range no {
		if looksLikeWordlistFile(n, min, min) {
			t.Errorf("%q should not look like a wordlist", n)
		}
	}
	if looksLikeWordlistFile("rockyou.txt", min-1, min) {
		t.Error("files under the size floor must be ignored")
	}
}

// TestScanRanksWordlistNamesAboveMereSize: a scan of a real machine turns up
// documentation dumps and dictionary files that are simply large. Sorting by
// size alone would suggest one of those over an actual rockyou.txt, so the
// ranking puts the name first and the size second.
func TestScanRanksWordlistNamesAboveMereSize(t *testing.T) {
	root := t.TempDir()
	filler := strings.Repeat("password123\n", 100000) // ~1.2 MiB
	writeWordlist(t, filepath.Join(root, "huge-generic.txt"), strings.Repeat(filler, 4))
	writeWordlist(t, filepath.Join(root, "some-passwords.txt"), strings.Repeat(filler, 2))
	rockyou := writeWordlist(t, filepath.Join(root, "rockyou.txt"), filler)

	hits, _ := scanForWordlists(context.Background(), []string{root}, wordlistScanMinSize)
	if len(hits) != 3 {
		t.Fatalf("want 3 hits, got %v", hits)
	}
	best, ok := suggestScannedWordlist(hits)
	if !ok || best.path != rockyou {
		t.Fatalf("suggested %q; want the (smallest) rockyou.txt %q — the name must "+
			"outrank raw size", best.path, rockyou)
	}
}

// TestScanDoesNotRecommendAnUnrecognisedFile: when nothing found is named like
// a wordlist, --scan must not print a confident `export HASHSMITH_WORDLIST=`
// line for whatever large .txt happened to be biggest. A scan on a machine
// with no wordlist installed turns up log dumps and documentation; pinning one
// of those would make every later run attack nonsense and report "not found".
func TestScanDoesNotRecommendAnUnrecognisedFile(t *testing.T) {
	root := t.TempDir()
	writeWordlist(t, filepath.Join(root, "server-log-dump.txt"), strings.Repeat("noise\n", 400000))
	useCandidates(t)
	t.Setenv(wordlistEnvVar, "")

	out := captureWordlistStdout(t, func() {
		if err := runWordlists([]string{"--scan", "--scan-root", root}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "server-log-dump.txt") {
		t.Fatalf("the hit should still be listed:\n%s", out)
	}
	if strings.Contains(out, wordlistEnvVar+"=/") {
		t.Errorf("must not recommend a file it cannot recognise as a wordlist:\n%s", out)
	}
}

// ── interactive menu (hazard 5) ─────────────────────────────────────────────

// TestInteractiveMenuNamesTheWordlistItWillActuallyUse: the menu used to
// hard-code "built-in common.txt (default)" in both crack flows. With
// auto-detection that label is a lie on any machine with a wordlist installed,
// and the operator picking "default" would unknowingly launch a very different
// run. The default entry must name the discovered file, and choosing it must
// return that file's path — not "", which would send the run to the embedded
// list after all.
func TestInteractiveMenuNamesTheWordlistItWillActuallyUse(t *testing.T) {
	dir := t.TempDir()
	found := writeWordlist(t, filepath.Join(dir, "rockyou.txt"), "hunter2\n")
	useCandidates(t, found)
	t.Setenv(wordlistEnvVar, "")

	menu := captureWordlistStderr(t, func() {
		got, err := promptWordlist(bufio.NewReader(strings.NewReader("1\n")))
		if err != nil {
			t.Fatalf("promptWordlist: %v", err)
		}
		if got != found {
			t.Fatalf("choosing the default returned %q; want the discovered %q", got, found)
		}
	})
	if !strings.Contains(menu, found) {
		t.Errorf("the menu must name the file it will use, got:\n%s", menu)
	}
	if strings.Contains(menu, defaultWordlistLabel) {
		t.Errorf("the menu must not claim the built-in list when a wordlist was discovered:\n%s", menu)
	}

	// With nothing discovered it falls back to naming the built-in list.
	useCandidates(t)
	menu = captureWordlistStderr(t, func() {
		got, err := promptWordlist(bufio.NewReader(strings.NewReader("1\n")))
		if err != nil || got != "" {
			t.Fatalf("promptWordlist: got (%q, %v), want the embedded default", got, err)
		}
	})
	if !strings.Contains(menu, defaultWordlistLabel) {
		t.Errorf("with nothing installed the menu should name the built-in list:\n%s", menu)
	}
}

// TestInteractiveCustomPathIsMatchedByIdentity: the old menu decided "the user
// wants a custom path" by testing whether the chosen option CONTAINED "custom"
// or "enter". Now that the default entry is a real path, a wordlist living in
// e.g. /home/op/custom-lists/ would have made choosing the default look like a
// request to type a path instead.
func TestInteractiveCustomPathIsMatchedByIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "custom-lists")
	found := writeWordlist(t, filepath.Join(dir, "rockyou.txt"), "hunter2\n")
	useCandidates(t, found)
	t.Setenv(wordlistEnvVar, "")

	got, err := promptWordlist(bufio.NewReader(strings.NewReader("1\n")))
	if err != nil {
		t.Fatalf("promptWordlist: %v", err)
	}
	if got != found {
		t.Fatalf("a path containing \"custom\" was mistaken for the custom-path option: got %q", got)
	}

	// Option 2 really is the custom-path prompt.
	other := writeWordlist(t, filepath.Join(dir, "other.txt"), "x\n")
	got, err = promptWordlist(bufio.NewReader(strings.NewReader("2\n" + other + "\n")))
	if err != nil || got != other {
		t.Fatalf("custom path: got (%q, %v), want %q", got, err, other)
	}
}

// captureWordlistStderr runs fn with os.Stderr redirected and returns what it
// wrote. (pipeline_test.go has a captureStderr for func() error.)
func captureWordlistStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	os.Stderr = orig
	w.Close()
	return <-done
}
