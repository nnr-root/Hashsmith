package smith

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The existing John test compares against a golden file captured from john
// once. That catches a regression but cannot catch a rule whose semantics were
// misread when the golden file was made: the file records what Hashsmith
// believed john does, checked by hand at one moment.
//
// This runs john. Where the binary is installed, every rule below is executed
// by both engines over the same words and the two candidate streams are
// required to be identical — which is the only statement about compatibility
// that does not depend on somebody having read the documentation correctly.
//
// It is a skip, not a failure, where john is absent, which is the normal case
// in CI.

// johnProbeWords are chosen to exercise the disagreements, not to look
// realistic: mixed case, digits, punctuation, a word short enough for the
// length rejections to bite, and one long enough that they do not.
var johnProbeWords = []string{
	// Multi-word entries, so the find-and-position rules have somewhere to point.
	"one two three four five", "ab cd",
	// Shape coverage.
	"Crack96", "password", "admin", "hi", "Crack", "a", "P@ssw0rd!", "MiXeD",
	// Grammar-command branches, each of which john treats differently and
	// several of which are case-SENSITIVE, so the uppercase twins are not
	// redundant: walked and walking are already past and progressive,
	// walking doubles its g before "ed", free and wife end in a lowercase e,
	// WIFE and BED and DAY and TRY end in an uppercase one, boy takes "ied"
	// after a vowel where pluralisation would not, and leaf, knife, glass,
	// buzz, church and wish each take a different plural.
	"walked", "walking", "walks", "glass", "buzz", "church", "wish",
	"leaf", "knife", "boy", "free", "see", "try", "fly", "day", "sit", "bed",
	"BED", "DAY", "TRY", "WIFE", "wife", "end", "ab", "abc", "abcd",
}

// runJohnRule returns the candidate stream john produces for one rule, or
// skips when john cannot be run.
func runJohnRule(t *testing.T, john, dir, rule string) []string {
	t.Helper()
	conf := filepath.Join(dir, "probe.conf")
	if err := os.WriteFile(conf, []byte("[List.Rules:Probe]\n"+rule+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	words := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(words, []byte(strings.Join(johnProbeWords, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(john, "--config="+conf, "--rules=Probe", "--wordlist="+words, "--stdout")
	cmd.Env = append(os.Environ(), "HOME="+dir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("john failed on rule %q: %v", rule, err)
	}
	var got []string
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			got = append(got, line)
		}
	}
	return got
}

func TestJohnRuleCommandsMatchJohnItself(t *testing.T) {
	john, err := exec.LookPath("john")
	if err != nil {
		t.Skip("john is not installed here, so its answers cannot be compared against")
	}
	dir := t.TempDir()

	// Not every john is a jumbo john, and the commands compared below are
	// jumbo's. A core john refuses them, which would look like a Hashsmith
	// failure rather than a missing feature of the reference, so the
	// reference is checked once before anything is compared to it.
	probe := filepath.Join(dir, "capability.conf")
	if err := os.WriteFile(probe, []byte("[List.Rules:Probe]\nW0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	words := filepath.Join(dir, "capability.txt")
	if err := os.WriteFile(words, []byte("Crack96\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command(john, "--config="+probe, "--rules=Probe", "--wordlist="+words, "--stdout")
	check.Env = append(os.Environ(), "HOME="+dir)
	if out, err := check.CombinedOutput(); err != nil {
		t.Skipf("this john does not accept jumbo rule commands, so it cannot serve as the "+
			"reference (a jumbo build is needed): %v\n%s", err, out)
	}

	// Every command added or corrected because john.conf's own rulesets used
	// it, plus the ones already supported that share a letter with a hashcat
	// command and so could regress silently.
	rules := []string{
		"S", "V", "R", "L",
		"W0", "W1", "W2",
		"=0C", "=1r", "=2a", "=0?d", "=1?a", "=3?l",
		"a0", "a3", "b0", "b3", "b5",
		// A bare "[" cannot appear in a john rule at all — it opens a
		// preprocessor group — so the escaped form is what a real ruleset
		// writes and what is compared here.
		"l", "u", "c", "C", "t", "T0", "r", "d", "f", "{", "}", `\[`, "]",
		"p", "P", "I", "Q", "M",
		"$1", "^x", "D1", "x02", "i1z", "o0y",
		"@?v", "/?d", "!?d", "(?a", ")?d", "%2s",
		// The class form of substitute. Without it `s?d*` read '?' as the
		// character to replace, and a rule whose next character happened to
		// be a valid command would have compiled silently as something else.
		// ?D is the negated-digit class, which makes these also a check that
		// the class table itself is right.
		"s?d*", "s?l#", "s?u-", "s?a.", "s?D*", "s?s_", "sa2",
		"l Q R", "u Q L", "c M S Q", "V Q l",
		"a0 W0", "b3 T0", "=1a l",
		// XNMI, the memory-substring command. Each of these is one of john's
		// own documented examples, and dX0zz is the one that pins WHICH word
		// the memory holds: three copies, not four, because the memory is
		// the word as it was before `d` doubled it.
		"X0z0", "X011", "Xm1z", "dX0zz", "<4X011X113X215",
		"X002", "X1z0", "X0zz", "X099", "l M u X0z0", "M l X0zz",
		// Numeric variables and `p`, the position matched by the last / or %.
		// Dp is the probe that shows WHERE p points: %4[ ] Dp must delete the
		// fourth space and not the first, which is the whole reason
		// john.conf's `%N[ ] … vbpa Tb` capitalises the right word.
		"/[ ] Dp", "%2[ ] Dp", "%3[ ] Dp", "%4[ ] Dp", "/[t] Dp",
		"/[ ] va01 vbpa Tb", "val1 oay", "/[ ] vbp0 Db",
		"%2[ ] va01 vbpa Tb", "va01 vbla Tb", "val1 Da",

		// Preprocessor. These are the reason the corpus figure moved, and
		// every one of them is a shape john.conf itself writes.
		//
		// The duplicate cases are not padding. John's ranges collapse
		// duplicates, so `$[aeioua-c]` is seven rules and not eight, and the
		// \r escape turns only the global pass off while adjacent duplicates
		// collapse either way. That asymmetry is invisible in the
		// documentation and was measured; these lines are what hold it.
		`:$[abc]`, `:$[aeioua-c]`, `:$[aabbcc]`, `:$[abca]`, `:$[aab]`,
		`:$\r[abca]`, `:$\r[a-ca-c]`, `:$\r[aab]`, `:$[1-9A-ZZ]`, `:$\r[1-9A-ZZ]`,
		// Back-references: no bracket of their own, and they emit whatever
		// the range they point at is currently substituting.
		`:$[12]$\0`, `:$[12]$\1`, `:$[ab]$[12]$\1$\2`, `:^[ab]$\1`,
		// Linked ranges, which do not multiply.
		`:$[12]$\p[ab]`, `:$[12]$\p0[ab]`, `:$[abc]$\p\r[abc]`,
		`-[:c] (?a \p1[lc] [{}]`,
		// Escapes that are not group syntax.
		`>9 \[`, `:$\[`, `:$\]`,
	}

	for _, rule := range rules {
		t.Run(rule, func(t *testing.T) {
			// A rule file goes through the preprocessor before the compiler,
			// so the test does too. Compiling the raw line instead would test
			// a path no real run takes — and would have hidden the escape bug
			// this test found, where `\[` resolved only when an unrelated
			// bracket group appeared elsewhere on the line.
			expanded, err := expandJohnRuleLine(rule)
			if err != nil {
				t.Fatalf("Hashsmith cannot expand %q, which john runs: %v", rule, err)
			}
			var got []string
			for _, e := range expanded {
				prog, err := compileRuleLineDialect(e, true)
				if err != nil {
					t.Fatalf("Hashsmith cannot compile %q (from %q), which john runs: %v", e, rule, err)
				}
				for _, w := range johnProbeWords {
					if out, ok := prog.apply(w); ok {
						got = append(got, out)
					}
				}
			}
			want := runJohnRule(t, john, dir, rule)

			// john de-duplicates its own output stream, so compare as
			// multisets after removing repeats from both sides; what is being
			// checked is which candidates each engine can produce, not how
			// many times it says them.
			// john never prints an empty candidate; Hashsmith emits one,
			// which is a real difference and a deliberate one — the empty
			// password exists and costs a single hash to try. It is dropped
			// here so that the comparison is about the rules rather than
			// about that choice.
			gotSet, wantSet := dedupSorted(dropEmpty(got)), dedupSorted(want)
			if strings.Join(gotSet, "\n") != strings.Join(wantSet, "\n") {
				t.Errorf("rule %q disagrees with john\n  hashsmith: %v\n  john:      %v",
					rule, gotSet, wantSet)
			}
		})
	}
}

func dropEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func dedupSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// TestJohnCorpusCoverageDoesNotRegress is a ratchet on how much of john's own
// configuration Hashsmith can read.
//
// The number is a floor, not a target: raise it when coverage improves, never
// lower it to make a change pass. It was 66.9% before the keyboard, case and
// length commands landed, 82.5% after them, 84.1% once the preprocessor learned
// back-references and range de-duplication, 84.9% with the character classes
// read out of john, 87.3% with XNMI, 94.8% with numeric variables and `p`, and
// 98.4% once word-pair rules were recognised as not applying rather than
// reported as broken.
//
// The remaining four lines are not a gap that can close. They expand to
// 2,030,625 and 857,375,000 rules; john generates its expansions lazily and

// johnConfRuleLines returns the lines of a john.conf that are actually rules:
// the contents of its [List.Rules:...] sections, minus the file's own
// structure.
//
// John's config format has TWO comment markers, not one. Its doc/CONFIG says
// so in as many words:
//
//	Comment lines start with a hash character ("#") or a semicolon (";")
//	and are ignored.
//
// Only "#" used to be stripped here, so every commented-out rule beginning
// with ";" was counted as a rule and then failed to compile, for the excellent
// reason that ";-c T1 Q M T0 Q" is not a rule. That measured a coverage
// number about the file's comment style rather than about this project.
//
// Two things hid it. The CI step meant to run the corpus test named a package
// containing no tests, so `go test -run` matched nothing and exited 0. And
// Homebrew's john.conf keeps its ";"-commented rules outside the
// [List.Rules:...] sections this walks, while Debian's keeps them inside — so
// the bug was invisible on a Mac and, on Ubuntu, dropped the measured coverage
// to 90.5% against a 98% floor.
func johnConfRuleLines(data string) []string {
	var out []string
	inRules := false
	for _, ln := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "[") {
			inRules = strings.HasPrefix(strings.ToLower(trimmed), "[list.rules:")
			continue
		}
		// A blank line, either comment marker, a !! pragma and a .include are
		// all part of the file's structure rather than rules.
		if !inRules || trimmed == "" ||
			strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") ||
			strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, ".include") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// TestJohnConfRuleLinesSkipsBothCommentMarkers pins the classification against
// a file shaped like Debian's, which is the layout that exposed the bug and
// the one no Mac has to hand.
func TestJohnConfRuleLinesSkipsBothCommentMarkers(t *testing.T) {
	const conf = `
[Options]
Wordlist = $JOHN/password.lst

[List.Rules:Wordlist]
# a hash comment
: 
-c l
;# Toggle case everywhere (up to length 8), assuming that certain case
;# combinations were already tried.
;-c T1 Q M T0 Q
;-c T2 Q M T[z0] T[z1] Q
!! this is a pragma
.include <another.conf>
u

[List.Rules:NT]
;l Az"[1-90][0-9][0-9]" <+
c
`
	got := johnConfRuleLines(conf)
	want := []string{":", "-c l", "u", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %d rule lines %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if strings.TrimSpace(got[i]) != want[i] {
			t.Errorf("line %d = %q, want %q", i, strings.TrimSpace(got[i]), want[i])
		}
	}
	for _, line := range got {
		if strings.HasPrefix(strings.TrimSpace(line), ";") {
			t.Errorf("a semicolon-commented line survived: %q — John's doc/CONFIG "+
				"names both \"#\" and \";\" as comment markers", line)
		}
	}
}

// never holds them all, while Hashsmith materialises them so a program can be
// compiled once and reused. Those four are refused with their actual size.
func TestJohnCorpusCoverageDoesNotRegress(t *testing.T) {
	const floor = 0.98 // 98.4% measured; the floor lags so a small corpus change cannot fail it

	confPaths := []string{
		"/opt/homebrew/share/john/john.conf",
		"/usr/share/john/john.conf",
		"/etc/john/john.conf",
	}
	var data []byte
	var used string
	for _, p := range confPaths {
		if b, err := os.ReadFile(p); err == nil {
			data, used = b, p
			break
		}
	}
	if data == nil {
		t.Skip("john.conf is not installed here, so corpus coverage cannot be measured")
	}

	total, ok := 0, 0
	var failed []string
	for _, ln := range johnConfRuleLines(string(data)) {
		total++
		expanded, err := expandJohnRuleLine(ln)
		if err != nil {
			expanded = []string{ln}
		}
		good := true
		for _, e := range expanded {
			if _, err := compileRuleLineDialect(e, true); err != nil {
				// A rule that asks for single-crack word pairs is READ
				// correctly and correctly found not to apply to a wordlist
				// run — which is what john does with it too, silently. It
				// counts as handled, not as a gap.
				if errors.Is(err, errRuleNotApplicable) {
					continue
				}
				good = false
				if len(failed) < 15 {
					failed = append(failed, fmt.Sprintf("%s  (%v)", ln, err))
				}
				break
			}
		}
		if good {
			ok++
		}
	}
	if total == 0 {
		t.Skipf("%s contains no rule lines", used)
	}
	got := float64(ok) / float64(total)
	t.Logf("%s: %d of %d rule lines compile (%.1f%%)", used, ok, total, 100*got)
	if got < floor {
		t.Errorf("john.conf coverage fell to %.1f%%, below the %.1f%% floor; still failing:\n  %s",
			100*got, 100*floor, strings.Join(failed, "\n  "))
	}
}

// TestJohnCharacterClassesMatchJohnItself compares the MEMBERSHIP of every
// character class against john, one byte at a time, rather than spot-checking
// a rule that happens to use one.
//
// Spot checks are what let ?s stay wrong. It was implemented as "printable,
// not a letter, not a digit", which is a reasonable reading of the word
// "symbols" and is not what john does: john's ?s is an explicit 23-character
// set, and the nine characters of ?p are punctuation and deliberately outside
// it. `s?s_` on "P@ssw0rd!" gave "P_ssw0rd_" here against john's
// "P_ssw0rd!" — one character, in a class used by rules that rewrite
// punctuation.
//
// Substituting a marker for every member over a word containing every
// printable byte turns the whole table into one comparison, so a class cannot
// be subtly wrong in a corner no rule in the test list happens to reach.
func TestJohnCharacterClassesMatchJohnItself(t *testing.T) {
	john, err := exec.LookPath("john")
	if err != nil {
		t.Skip("john is not installed here, so its classes cannot be compared against")
	}
	dir := t.TempDir()

	// Every printable byte, in order. The marker is a byte NOT in the word so
	// that "this position changed" is unambiguous — an in-word marker makes a
	// character that is already the marker look like a match.
	var word []byte
	for c := 33; c < 127; c++ {
		word = append(word, byte(c))
	}
	const marker = "\\x01"

	for _, class := range []byte{'v', 'c', 'w', 'p', 's', 'l', 'u', 'd', 'a', 'x', 'z', 'o', 'y', 'b', '?'} {
		t.Run(string(class), func(t *testing.T) {
			rule := "s?" + string(class) + marker

			conf := filepath.Join(dir, "cls.conf")
			if err := os.WriteFile(conf, []byte("[List.Rules:Probe]\n"+rule+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			words := filepath.Join(dir, "cls.txt")
			if err := os.WriteFile(words, append(word, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(john, "--config="+conf, "--rules=Probe", "--wordlist="+words, "--stdout")
			cmd.Env = append(os.Environ(), "HOME="+dir)
			raw, err := cmd.Output()
			if err != nil {
				t.Skipf("this john did not run the class probe for ?%c: %v", class, err)
			}
			out := strings.TrimRight(string(raw), "\n")
			if len(out) != len(word) {
				t.Skipf("john returned %d bytes for a %d-byte word; the probe cannot be read",
					len(out), len(word))
			}
			var johnSet []byte
			for i := range word {
				if out[i] != word[i] {
					johnSet = append(johnSet, word[i])
				}
			}

			match, ok := johnClassMatch(class)
			if !ok {
				t.Fatalf("Hashsmith has no class ?%c, but john matched %q", class, johnSet)
			}
			var ourSet []byte
			for _, b := range word {
				if match(b) {
					ourSet = append(ourSet, b)
				}
			}
			if string(ourSet) != string(johnSet) {
				t.Errorf("class ?%c differs over printable bytes\n  hashsmith: %q\n  john:      %q",
					class, ourSet, johnSet)
			}
		})
	}
}
