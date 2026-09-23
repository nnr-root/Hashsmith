package smith

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Hashsmith shipped no rule files at all, so `--rules best64.rule` — the first
// thing anyone types, because it is what every hashcat tutorial uses — had
// nothing to point at. The engine was complete; there was simply no content.
func TestBundledRulesetsCompile(t *testing.T) {
	names := builtinRuleNames()
	if len(names) < 4 {
		t.Fatalf("only %d bundled rulesets: %v", len(names), names)
	}
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			src, ok := builtinRuleSource(name)
			if !ok {
				t.Fatalf("%q is listed but has no source", name)
			}
			// Every rule must compile: a bundled set that reports parse
			// failures is worse than shipping nothing, because it teaches the
			// user that failures are normal.
			var lines, bad int
			for _, line := range strings.Split(src, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				lines++
				if _, err := compileRuleLine(line); err != nil {
					bad++
					t.Errorf("rule %q does not compile: %v", line, err)
				}
			}
			if lines < 10 {
				t.Errorf("%s has only %d rules", name, lines)
			}
			if bad > 0 {
				t.Errorf("%s: %d of %d rules failed to compile", name, bad, lines)
			}
		})
	}
}

// A bare name resolves to a bundled set; a real file always wins over one.
func TestRuleResolutionPrefersARealFile(t *testing.T) {
	if _, _, err := openRuleSource("best"); err != nil {
		t.Errorf("bare bundled name did not resolve: %v", err)
	}
	if _, _, err := openRuleSource("best.rule"); err != nil {
		t.Errorf("bundled name with extension did not resolve: %v", err)
	}

	// A file called best.rule in the working directory must shadow the
	// bundled one — a user's own rules are never silently replaced.
	dir := t.TempDir()
	own := filepath.Join(dir, "best.rule")
	if err := os.WriteFile(own, []byte("$z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, label, err := openRuleSource(own)
	if err != nil {
		t.Fatalf("own file: %v", err)
	}
	if c, ok := src.(interface{ Close() error }); ok {
		defer c.Close()
	}
	if strings.Contains(label, "bundled") {
		t.Errorf("a real file resolved to the bundled set instead (label %q)", label)
	}
}

// hashcat's own rule names must NOT alias onto ours: those files have specific
// contents, and quietly substituting different rules under the same name would
// make a run unreproducible.
func TestUnknownRuleNameExplainsItself(t *testing.T) {
	_, _, err := openRuleSource("best64.rule")
	if err == nil {
		t.Fatal("best64.rule resolved; it must not alias onto a bundled set")
	}
	msg := err.Error()
	for _, want := range []string{"best64.rule", "bundled", "best", "digits"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q: %s", want, msg)
		}
	}
}

// End to end: the bundled set must actually recover a password the plain
// wordlist cannot.
func TestBundledBestRulesetRecoversAMangledPassword(t *testing.T) {
	engine, bad, err := loadRuleFiles([]string{"best"})
	if err != nil {
		t.Fatalf("loadRuleFiles: %v", err)
	}
	if bad != 0 {
		t.Errorf("%d rules in the bundled set failed to parse", bad)
	}
	var got []string
	for _, m := range engine.expand("password") {
		got = append(got, m.password)
	}
	for _, want := range []string{"Password123", "PASSWORD", "password1", "Password"} {
		if !contains(got, want) {
			t.Errorf("the bundled best ruleset does not produce %q", want)
		}
	}
}
