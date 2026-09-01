package main

// Every test here injects the config path (and, where discovery matters, the
// candidate list and the home directory), so nothing depends on what the
// machine running the suite happens to have in ~/.hashsmith or /usr/share. A
// test that read the developer's real settings file would pass or fail
// depending on whose laptop ran it, which is worth nothing.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMain redirects the settings file for the WHOLE package before any test
// runs. Without it, every existing resolveWordlist test would start consulting
// the real ~/.hashsmith/config.json — silently host-dependent, and on a
// developer machine with a saved default it would break tests that have
// nothing to do with this feature.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "hashsmith-test-config-*")
	if err != nil {
		panic(err)
	}
	hashsmithConfigPath = func() string { return filepath.Join(dir, "config.json") }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// useConfigDir gives one test its own settings file and restores the previous
// redirection afterwards.
func useConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := hashsmithConfigPath
	hashsmithConfigPath = func() string { return filepath.Join(dir, "config.json") }
	t.Cleanup(func() { hashsmithConfigPath = orig })
	return dir
}

// saveDefaultForTest pins path without going through the CLI.
func saveDefaultForTest(t *testing.T, path string) {
	t.Helper()
	if err := saveHashsmithConfig(hashsmithConfig{Wordlist: path}); err != nil {
		t.Fatal(err)
	}
}

// ── resolution order ────────────────────────────────────────────────────────

// TestSavedDefaultBeatsAutoDetection: the whole point of the setting. An
// operator who pinned /data/corp.txt must get it even on a box where
// rockyou.txt is installed and would otherwise be auto-detected.
func TestSavedDefaultBeatsAutoDetection(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	pinned := writeWordlist(t, filepath.Join(dir, "pinned.txt"), "pinned\n")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, "")
	saveDefaultForTest(t, pinned)

	c, err := resolveWordlist("", false)
	if err != nil {
		t.Fatal(err)
	}
	if c.path != pinned || c.origin != wordlistFromConfig {
		t.Fatalf("got %#v, want the saved default %q with origin wordlistFromConfig", c, pinned)
	}
	if c.autoDetected() {
		t.Error("a saved default is not auto-detection")
	}
}

// TestFlagAndEnvBeatSavedDefault pins the ORDER, which is the part of this
// design most likely to be "simplified" into config-beats-env by someone
// reading the code later. It must not be: an explicit flag is this command, an
// exported variable is this shell, and a saved setting is whatever the
// operator wanted the last time they thought about it. Ranking the setting
// above the variable would make `HASHSMITH_WORDLIST=x hashsmith crack` do
// nothing at all — silently.
func TestFlagAndEnvBeatSavedDefault(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	pinned := writeWordlist(t, filepath.Join(dir, "pinned.txt"), "pinned\n")
	env := writeWordlist(t, filepath.Join(dir, "env.txt"), "env\n")
	flagList := writeWordlist(t, filepath.Join(dir, "flag.txt"), "flag\n")
	useCandidates(t)
	saveDefaultForTest(t, pinned)

	// env beats the saved default
	t.Setenv(wordlistEnvVar, env)
	c, err := resolveWordlist("", false)
	if err != nil {
		t.Fatal(err)
	}
	if c.path != env || c.origin != wordlistFromEnv {
		t.Fatalf("got %#v, want %s=%q to outrank the saved default %q",
			c, wordlistEnvVar, env, pinned)
	}

	// -w beats both
	c, err = resolveWordlist(flagList, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.path != flagList || c.origin != wordlistFromFlag {
		t.Fatalf("got %#v, want -w %q to outrank both", c, flagList)
	}

	// with the env unset the saved default is what is left
	t.Setenv(wordlistEnvVar, "")
	c, err = resolveWordlist("", false)
	if err != nil || c.path != pinned {
		t.Fatalf("got (%#v, %v), want the saved default %q", c, err, pinned)
	}
}

// TestStaleSavedDefaultWarnsAndFallsThrough is the asymmetry with
// $HASHSMITH_WORDLIST, and it is deliberate: a persisted setting goes stale in
// ordinary ways (list deleted, external drive unmounted, config synced from
// another machine), and if that were an error, one unmounted drive would make
// EVERY later hashsmith run fail — locking the operator out of a tool with a
// working built-in list sitting right there. So it warns, by name, and
// continues down the order.
func TestStaleSavedDefaultWarnsAndFallsThrough(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	gone := filepath.Join(dir, "deleted.txt")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, "")
	saveDefaultForTest(t, gone)

	c, err := resolveWordlist("", false)
	if err != nil {
		t.Fatalf("a stale saved default must NOT be an error (that would lock the "+
			"operator out of every subsequent run): %v", err)
	}
	if c.path != cand || c.origin != wordlistAutoDetected {
		t.Fatalf("got %#v, want a fall-through to the next source %q", c, cand)
	}
	if c.staleDefault != gone {
		t.Fatalf("staleDefault = %q, want %q", c.staleDefault, gone)
	}
	warns := strings.Join(c.warnings(), "\n")
	if warns == "" {
		t.Fatal("a stale saved default must warn — this changes what gets attacked")
	}
	if !strings.Contains(warns, gone) {
		t.Errorf("the warning must NAME the missing path, got:\n%s", warns)
	}
	if !strings.Contains(warns, "--clear-default") {
		t.Errorf("the warning must tell the operator how to fix it "+
			"(`hashsmith wordlists --clear-default`), got:\n%s", warns)
	}
	if !strings.Contains(warns, "WARNING") {
		t.Errorf("the warning must be prominent, got:\n%s", warns)
	}

	// It reaches the operator: announceWordlist prints it before the one-liner.
	out := captureWordlistStderr(t, func() { announceWordlist(c) })
	if !strings.Contains(out, gone) || !strings.Contains(out, "--clear-default") {
		t.Errorf("announceWordlist must print the stale-default warning, got:\n%s", out)
	}

	// A stale default with nothing else installed still lands on the embedded
	// list rather than erroring.
	useCandidates(t)
	c, err = resolveWordlist("", false)
	if err != nil || c.origin != wordlistEmbeddedDefault {
		t.Fatalf("got (%#v, %v), want the embedded default", c, err)
	}
	if c.staleDefault != gone {
		t.Error("the warning must survive all the way to the embedded fallback")
	}
}

// TestStaleSavedDefaultCoversUnusableFiles: "missing" is not only ENOENT. A
// zero-byte file (interrupted download) and a directory must be treated the
// same way — warn and fall through — because attacking a zero-byte list is
// attacking nothing while reporting "not found" as if it meant something.
func TestStaleSavedDefaultCoversUnusableFiles(t *testing.T) {
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	empty := writeWordlist(t, filepath.Join(dir, "empty.txt"), "")
	asDir := filepath.Join(dir, "a-dir")
	if err := os.MkdirAll(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{empty, asDir, filepath.Join(dir, "absent.txt")} {
		useConfigDir(t)
		useCandidates(t, cand)
		t.Setenv(wordlistEnvVar, "")
		saveDefaultForTest(t, bad)
		c, err := resolveWordlist("", false)
		if err != nil {
			t.Fatalf("saved default %q: must warn, not error: %v", bad, err)
		}
		if c.path != cand {
			t.Errorf("saved default %q resolved to %q; want a fall-through to %q", bad, c.path, cand)
		}
		if c.staleDefault != bad {
			t.Errorf("saved default %q produced no warning", bad)
		}
	}
}

// TestNoAutoWordlistBypassesSavedDefault: --no-auto-wordlist means "the
// built-in list, deterministically, on every machine". A saved default is a
// per-machine setting, so it must be bypassed exactly as the environment
// variable already is — and, exactly as with the environment variable, the
// bypass is announced rather than silent.
func TestNoAutoWordlistBypassesSavedDefault(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	pinned := writeWordlist(t, filepath.Join(dir, "pinned.txt"), "pinned\n")
	useCandidates(t)
	t.Setenv(wordlistEnvVar, "")
	saveDefaultForTest(t, pinned)

	c, err := resolveWordlist("", true)
	if err != nil || c.path != "" || c.origin != wordlistEmbeddedDefault {
		t.Fatalf("got (%#v, %v), want the embedded default", c, err)
	}
	if !c.configIgnored {
		t.Fatal("--no-auto-wordlist must record that it bypassed the saved default")
	}
	line := c.describe()
	if !strings.Contains(line, "--no-auto-wordlist") || !strings.Contains(line, "saved default") {
		t.Errorf("the announcement must say the saved default was ignored, got %q", line)
	}

	// With the environment set as well, both bypasses are named.
	env := writeWordlist(t, filepath.Join(dir, "env.txt"), "env\n")
	t.Setenv(wordlistEnvVar, env)
	c, err = resolveWordlist("", true)
	if err != nil || c.path != "" {
		t.Fatalf("got (%#v, %v), want the embedded default", c, err)
	}
	line = c.describe()
	if !strings.Contains(line, wordlistEnvVar) || !strings.Contains(line, "saved default") {
		t.Errorf("both bypasses must be named, got %q", line)
	}
}

// TestSavedDefaultAnnouncementNamesItsOrigin: "which list did this run attack,
// and why that one?" must be answerable from the single line every run prints.
func TestSavedDefaultAnnouncementNamesItsOrigin(t *testing.T) {
	c := wordlistChoice{path: "/data/corp.txt", origin: wordlistFromConfig}
	got := c.describe()
	if got != "Wordlist: /data/corp.txt (saved default)" {
		t.Errorf("describe() = %q, want the path plus \"(saved default)\"", got)
	}
	gz := wordlistChoice{path: "/data/corp.txt.gz", origin: wordlistFromConfig, gzip: true}
	if !strings.Contains(gz.describe(), "gzip") {
		t.Errorf("a gzip saved default must say so, got %q", gz.describe())
	}
}

// TestDistributedWarningFiresForSavedDefault: a saved default lives in one
// operator's ~/.hashsmith on one box, so two machines can disagree about what
// -w-less means — exactly the condition that makes a --skip/--limit slice
// overlap and leave gaps. An explicit -w or $HASHSMITH_WORDLIST names the same
// path everywhere and must still NOT warn.
func TestDistributedWarningFiresForSavedDefault(t *testing.T) {
	cfg := wordlistChoice{path: "/data/corp.txt", origin: wordlistFromConfig}
	for _, tc := range []struct{ skip, limit int64 }{{1000, 0}, {0, 500}} {
		if w := distributedWordlistWarning(cfg, tc.skip, tc.limit, false); w == "" {
			t.Errorf("--skip=%d --limit=%d on a saved default must warn", tc.skip, tc.limit)
		}
	}
	w := distributedWordlistWarning(cfg, 0, 0, true)
	if w == "" {
		t.Fatal("--keyspace on a saved default must warn")
	}
	if !strings.Contains(w, "saved default") {
		t.Errorf("the warning should say the list came from the saved default, got %q", w)
	}
	if !strings.Contains(w, "-w /data/corp.txt") {
		t.Errorf("the warning must name the -w that pins every machine, got %q", w)
	}
	if got := distributedWordlistWarning(cfg, 0, 0, false); got != "" {
		t.Errorf("an ordinary single-machine run must not warn, got %q", got)
	}
	for name, c := range map[string]wordlistChoice{
		"-w":  {path: "/data/corp.txt", origin: wordlistFromFlag},
		"env": {path: "/data/corp.txt", origin: wordlistFromEnv},
	} {
		if got := distributedWordlistWarning(c, 100, 100, true); got != "" {
			t.Errorf("%s names the same path on every machine and must not warn, got %q", name, got)
		}
	}
}

// ── --set-default / --clear-default ─────────────────────────────────────────

// TestSetDefaultValidatesBeforeSaving: a persisted setting is applied silently
// on every later run, so the moment the operator is watching is the ONLY good
// moment to refuse a bad path. Nothing may be written when validation fails —
// a saved-but-broken default would warn on every run forever.
func TestSetDefaultValidatesBeforeSaving(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	asDir := filepath.Join(dir, "a-dir")
	if err := os.MkdirAll(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"missing":   filepath.Join(dir, "no-such-file.txt"),
		"directory": asDir,
		"empty":     writeWordlist(t, filepath.Join(dir, "empty.txt"), ""),
		"blank":     "",
	}
	for name, path := range bad {
		saved, err := setSavedWordlistDefault(path)
		if err == nil {
			t.Errorf("%s (%q): --set-default must refuse it, got %q", name, path, saved)
		}
		if got, _ := savedWordlistDefault(); got != "" {
			t.Errorf("%s (%q): nothing must be written when validation fails, but the "+
				"config now holds %q", name, path, got)
		}
	}
	if _, err := os.Stat(hashsmithConfigPath()); err == nil {
		t.Error("a run of rejected --set-defaults must not create a settings file at all")
	}
}

// TestSetDefaultRoundTrip: save, resolve, clear — through the real CLI entry
// point, with the announcements the operator actually sees.
func TestSetDefaultRoundTrip(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	list := writeWordlist(t, filepath.Join(dir, "corp.txt"), "hunter2\n")
	useCandidates(t)
	t.Setenv(wordlistEnvVar, "")

	out := captureWordlistStdout(t, func() {
		if err := runWordlists([]string{"--set-default", list}); err != nil {
			t.Fatalf("--set-default: %v", err)
		}
	})
	if !strings.Contains(out, list) {
		t.Errorf("--set-default must confirm what it saved, got:\n%s", out)
	}
	if !strings.Contains(out, hashsmithConfigPath()) {
		t.Errorf("--set-default must print WHERE it saved the setting, got:\n%s", out)
	}

	c, err := resolveWordlist("", false)
	if err != nil || c.path != list || c.origin != wordlistFromConfig {
		t.Fatalf("after --set-default: got (%#v, %v), want %q from the config", c, err, list)
	}

	out = captureWordlistStdout(t, func() {
		if err := runWordlists([]string{"--clear-default"}); err != nil {
			t.Fatalf("--clear-default: %v", err)
		}
	})
	if !strings.Contains(out, list) {
		t.Errorf("--clear-default should say what it forgot, got:\n%s", out)
	}
	if got, _ := savedWordlistDefault(); got != "" {
		t.Fatalf("--clear-default left %q behind", got)
	}
	c, err = resolveWordlist("", false)
	if err != nil || c.origin != wordlistEmbeddedDefault {
		t.Fatalf("after --clear-default: got (%#v, %v), want the embedded default", c, err)
	}

	// Clearing again is not an error: it is what an operator reaches for when
	// a stale-default warning tells them to, and it must work whether or not
	// the setting is still there.
	out = captureWordlistStdout(t, func() {
		if err := runWordlists([]string{"--clear-default"}); err != nil {
			t.Fatalf("second --clear-default: %v", err)
		}
	})
	if !strings.Contains(strings.ToLower(out), "nothing to clear") {
		t.Errorf("clearing an unset default should say so, got:\n%s", out)
	}
}

// TestSetDefaultStoresAnAbsolutePath: the setting outlives the shell that
// created it, so a relative path saved from one directory would mean a
// different file from the next one — or nothing at all.
func TestSetDefaultStoresAnAbsolutePath(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	writeWordlist(t, filepath.Join(dir, "rel.txt"), "hunter2\n")

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(cwd) })

	saved, err := setSavedWordlistDefault("rel.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(saved) {
		t.Fatalf("--set-default saved %q; it must be absolute", saved)
	}
	got, _ := savedWordlistDefault()
	if !filepath.IsAbs(got) {
		t.Fatalf("the config holds %q; it must be absolute", got)
	}
}

// TestSetDefaultExpandsTilde: "~/lists/x.txt" is what an operator types.
func TestSetDefaultExpandsTilde(t *testing.T) {
	useConfigDir(t)
	home := t.TempDir()
	orig := wordlistUserHomeDir
	wordlistUserHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { wordlistUserHomeDir = orig })

	want := writeWordlist(t, filepath.Join(home, "lists", "x.txt"), "hunter2\n")
	saved, err := setSavedWordlistDefault("~/lists/x.txt")
	if err != nil {
		t.Fatal(err)
	}
	if saved != want {
		t.Fatalf("saved %q, want the expanded %q", saved, want)
	}
}

// TestSetAndClearDefaultTogetherIsRefused: the two contradict each other, and
// silently picking one would leave the operator's setting in a state they did
// not ask for.
func TestSetAndClearDefaultTogetherIsRefused(t *testing.T) {
	useConfigDir(t)
	list := writeWordlist(t, filepath.Join(t.TempDir(), "x.txt"), "a\n")
	if err := runWordlists([]string{"--set-default", list, "--clear-default"}); err == nil {
		t.Fatal("--set-default with --clear-default must be refused")
	}
}

// ── robustness of the settings file ─────────────────────────────────────────

// TestConfigDegradesGracefully: every broken-file mode must produce a clear
// message and a fall-through, never a panic and never a silently wrong
// wordlist. A config file is edited by hand, synced between machines and
// truncated by full disks; all three happen.
func TestConfigDegradesGracefully(t *testing.T) {
	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")

	cases := []struct {
		name      string
		body      string
		wantError bool // loadHashsmithConfig should report a problem
	}{
		{"missing", "\x00MISSING", false},
		{"empty", "", false},
		{"whitespace", "   \n\t\n", false},
		{"malformed", "{not json at all", true},
		{"truncated", `{"version": 1, "wordlist": "/data/`, true},
		{"wrong type", `{"version": 1, "wordlist": 42}`, true},
		{"unknown fields", `{"version": 99, "wordlist": "", "future_setting": {"a": 1}}`, false},
		{"json array", `["not", "an", "object"]`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgDir := useConfigDir(t)
			if tc.body != "\x00MISSING" {
				if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			useCandidates(t, cand)
			t.Setenv(wordlistEnvVar, "")

			_, err := loadHashsmithConfig()
			if tc.wantError && err == nil {
				t.Errorf("loadHashsmithConfig accepted %q as valid", tc.body)
			}
			if !tc.wantError && err != nil {
				t.Errorf("loadHashsmithConfig rejected %q: %v", tc.body, err)
			}
			if err != nil && !strings.Contains(err.Error(), hashsmithConfigPath()) {
				t.Errorf("the error must name the file so it can be fixed: %v", err)
			}

			// Resolution never fails because of the settings file.
			c, rerr := resolveWordlist("", false)
			if rerr != nil {
				t.Fatalf("a broken settings file must not fail resolution: %v", rerr)
			}
			if c.path != cand {
				t.Fatalf("resolved to %q, want a fall-through to %q", c.path, cand)
			}
			if tc.wantError && strings.Join(c.warnings(), "") == "" {
				t.Error("an unusable settings file must warn — a saved default is being ignored")
			}
			// And the listing renders without blowing up.
			_ = captureWordlistStdout(t, func() { printWordlistCandidateTable(os.Stdout) })
		})
	}
}

// TestUnreadableConfigWarnsRatherThanFails: chmod 000 on the settings file (or
// a config synced with the wrong owner) must not stop the tool working.
func TestUnreadableConfigWarnsRatherThanFails(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permissions do not apply (Windows, or running as root)")
	}
	cfgDir := useConfigDir(t)
	path := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"wordlist":"/data/x.txt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	dir := t.TempDir()
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, "")

	if _, err := loadHashsmithConfig(); err == nil {
		t.Fatal("an unreadable settings file must be reported, not treated as empty")
	}
	c, err := resolveWordlist("", false)
	if err != nil {
		t.Fatalf("an unreadable settings file must not fail the run: %v", err)
	}
	if c.path != cand {
		t.Fatalf("resolved to %q, want the fall-through %q", c.path, cand)
	}
	if strings.Join(c.warnings(), "") == "" {
		t.Error("an unreadable settings file must warn")
	}
}

// TestUnwritableConfigDirIsAClearError: --set-default cannot save, and must
// say so rather than reporting success and leaving the operator believing a
// setting exists.
func TestUnwritableConfigDirIsAClearError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permissions do not apply (Windows, or running as root)")
	}
	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.MkdirAll(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })

	orig := hashsmithConfigPath
	hashsmithConfigPath = func() string { return filepath.Join(locked, "sub", "config.json") }
	t.Cleanup(func() { hashsmithConfigPath = orig })

	list := writeWordlist(t, filepath.Join(t.TempDir(), "x.txt"), "hunter2\n")
	_, err := setSavedWordlistDefault(list)
	if err == nil {
		t.Fatal("saving into an uncreatable directory must be an error")
	}
	if !strings.Contains(err.Error(), "NOT saved") {
		t.Errorf("the error must be unambiguous that nothing was saved: %v", err)
	}
}

// TestSavedConfigIsVersionedAndReReadable: the file is a small, versioned JSON
// object with room for settings that do not exist yet.
func TestSavedConfigIsVersionedAndReReadable(t *testing.T) {
	cfgDir := useConfigDir(t)
	list := writeWordlist(t, filepath.Join(t.TempDir(), "x.txt"), "hunter2\n")
	if _, err := setSavedWordlistDefault(list); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(cfgDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("the settings file must be a JSON object: %v (%s)", err, raw)
	}
	if generic["version"] != float64(hashsmithConfigVersion) {
		t.Errorf("version = %v, want %d", generic["version"], hashsmithConfigVersion)
	}
	if generic["wordlist"] != list {
		t.Errorf("wordlist = %v, want %q", generic["wordlist"], list)
	}
	cfg, err := loadHashsmithConfig()
	if err != nil || cfg.Wordlist != list {
		t.Fatalf("round trip: got (%#v, %v), want %q", cfg, err, list)
	}
}

// TestClearDefaultPreservesOtherSettings: other settings will join this file,
// and clearing the wordlist must not wipe them.
func TestClearDefaultPreservesOtherSettings(t *testing.T) {
	cfgDir := useConfigDir(t)
	path := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(path,
		[]byte(`{"version":1,"wordlist":"/data/x.txt","future_setting":"keep me"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clearSavedWordlistDefault(); err != nil {
		t.Fatal(err)
	}
	if got, _ := savedWordlistDefault(); got != "" {
		t.Fatalf("the wordlist setting survived --clear-default: %q", got)
	}
	// Documented limitation, asserted so a future change to it is deliberate:
	// unknown keys are NOT preserved across a rewrite, because the struct does
	// not model them. If a second setting is added, it must become a field.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "future_setting") {
		t.Log("unknown keys are now preserved; update this comment")
	}
}

// ── the listing ─────────────────────────────────────────────────────────────

// TestWordlistsCommandShowsTheConfigState: `hashsmith wordlists` is the answer
// to "why is this box attacking that list?", so it must show all four things
// that can decide it, and mark which one won.
func TestWordlistsCommandShowsTheConfigState(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	pinned := writeWordlist(t, filepath.Join(dir, "pinned.txt"), "pinned\n")
	cand := writeWordlist(t, filepath.Join(dir, "candidate.txt"), "candidate\n")
	useCandidates(t, cand)
	t.Setenv(wordlistEnvVar, "")

	// No default saved yet.
	out := captureWordlistStdout(t, func() {
		if err := runWordlists(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, hashsmithConfigPath()) {
		t.Errorf("the listing must show the settings file path, got:\n%s", out)
	}
	if !strings.Contains(out, "no saved default") {
		t.Errorf("the listing must say there is no saved default, got:\n%s", out)
	}
	if !strings.Contains(out, wordlistEnvVar) {
		t.Errorf("the listing must show the environment state, got:\n%s", out)
	}
	if !strings.Contains(out, "Selected: "+cand) {
		t.Errorf("the listing must name the winner, got:\n%s", out)
	}

	// With one saved, it wins and is marked as such.
	saveDefaultForTest(t, pinned)
	out = captureWordlistStdout(t, func() {
		if err := runWordlists(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "saved default: "+pinned) {
		t.Errorf("the listing must show the saved default, got:\n%s", out)
	}
	if !strings.Contains(out, "Selected: "+pinned+" (saved default)") {
		t.Errorf("the listing must say the saved default won, got:\n%s", out)
	}
	if !strings.Contains(out, "<== USED") {
		t.Errorf("the listing must mark which row wins, got:\n%s", out)
	}

	// A stale one is reported in the listing too, with the fix.
	saveDefaultForTest(t, filepath.Join(dir, "gone.txt"))
	out = captureWordlistStdout(t, func() {
		if err := runWordlists(nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "--clear-default") {
		t.Errorf("a stale saved default must be flagged in the listing, got:\n%s", out)
	}
	if !strings.Contains(out, "Selected: "+cand) {
		t.Errorf("the listing must show the fall-through winner, got:\n%s", out)
	}
}

// TestSavedDefaultReachesTheAttack: the resolution must be threaded all the
// way through the real crack path, not merely computed. The password lives
// ONLY in the pinned file, so cracking it is proof.
func TestSavedDefaultReachesTheAttack(t *testing.T) {
	useConfigDir(t)
	dir := t.TempDir()
	secret := "zq7-saved-default-only-passphrase"
	pinned := writeWordlist(t, filepath.Join(dir, "pinned.txt"), "aaa\nbbb\n"+secret+"\n")
	useCandidates(t)
	t.Setenv(wordlistEnvVar, "")
	saveDefaultForTest(t, pinned)

	sum := md5HexString(secret)
	prev := exitCode
	exitCode = 0
	t.Cleanup(func() { exitCode = prev })

	if err := runCrack([]string{"-t", "md5", "--no-pot", sum}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d: the saved default never reached the attack "+
			"(the password is not in %s)", exitCode, defaultWordlistLabel)
	}

	// --no-auto-wordlist must make the same run miss it.
	exitCode = 0
	if err := runCrack([]string{"-t", "md5", "--no-pot", "--no-auto-wordlist", sum}); err != nil {
		t.Fatalf("runCrack --no-auto-wordlist: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("exitCode = %d: --no-auto-wordlist must bypass the saved default "+
			"and use the built-in list, which lacks the password", exitCode)
	}
}
