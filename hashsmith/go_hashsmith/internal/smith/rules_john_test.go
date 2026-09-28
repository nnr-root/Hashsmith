package smith

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// John's rule dialect. Before this, 1 of the 26 lines in john.conf's own
// [List.Rules:Wordlist] compiled — the engine was Hashcat-complete and could
// read essentially no John ruleset at all.

func TestJohnPreprocessorExpansion(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"$[12]", []string{"$1", "$2"}},
		{"^[ab]$[12]", []string{"^a$1", "^a$2", "^b$1", "^b$2"}},
		{"$[0-2]", []string{"$0", "$1", "$2"}},
		{"c $1", []string{"c $1"}},
		// A \pN group is LINKED, not multiplied: it takes the index the N-th
		// group took. Two groups of two here means four rules, not eight, and
		// 'l' pairs with ':' while 'c' pairs with 'c'.
		{`-[:c] \p1[lc] [PI]`, []string{
			"-: l P", "-: l I", "-c c P", "-c c I",
		}},
	} {
		got, err := expandJohnRuleLine(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q expanded to %q; want %q", c.in, got, c.want)
		}
	}
	if _, err := expandJohnRuleLine("$[12"); err == nil {
		t.Error("an unterminated bracket group was accepted")
	}
}

// The dialect is chosen by compiling both ways and keeping the better fit,
// because marker syntax cannot tell them apart: hashcat's positions include 8,
// C and P, so `-8` is both a valid hashcat rule and a valid John reject flag,
// and `@?d` is "purge '?', duplicate" in hashcat but "purge digits" in John.
// Two marker heuristics were tried and each read a real hashcat file as John.
func TestDialectSelectionNeverFlipsAValidHashcatFile(t *testing.T) {
	for name, lines := range map[string][]string{
		"specific.rule's -8":   {"-8", "l", "u"},
		"d3ad0ne's @? literal": {`*75 @? '7`, "l"},
		"positions":            {"-C", "-P", "c", "$1"},
	} {
		progs, bad := compileRuleLinesAs(lines, false)
		if bad != 0 {
			t.Errorf("%s: %d line(s) fail to compile as hashcat", name, bad)
		}
		got, gotBad, err := compileRuleLines(lines)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if gotBad != 0 || len(got) != len(progs) {
			t.Errorf("%s: dialect selection changed the result (%d rules, %d bad; hashcat alone gives %d, 0)",
				name, len(got), gotBad, len(progs))
		}
	}
}

// Candidate-for-candidate parity with john on its own Wordlist ruleset, against
// output captured from john 1.9.0-jumbo-1 so CI needs no john installed.
func TestJohnWordlistRulesetMatchesJohnExactly(t *testing.T) {
	ruleFile := filepath.Join("testdata", "john_wordlist.rule")
	rules, bad, err := loadRuleFiles([]string{ruleFile})
	if err != nil {
		t.Fatalf("loadRuleFiles: %v", err)
	}
	if bad != 0 {
		t.Errorf("%d line(s) of john.conf's own Wordlist ruleset failed to compile", bad)
	}

	words := readLinesForTest(t, filepath.Join("testdata", "john_wordlist_words.txt"))
	// expand() deliberately excludes the base word — it seeds its dedup set
	// with it, and the attack loop emits the unmangled word itself. The
	// candidate STREAM a user sees is therefore the word plus its expansions,
	// which is what john's --stdout prints, so that is what is compared.
	var got []string
	for _, w := range words {
		got = append(got, w)
		for _, m := range rules.expand(w) {
			got = append(got, m.password)
		}
	}
	sort.Strings(got)

	want := readLinesForTest(t, filepath.Join("testdata", "john_wordlist_expected.txt"))
	sort.Strings(want)

	if len(got) != len(want) {
		t.Errorf("produced %d candidates; john produces %d", len(got), len(want))
	}
	inWant := map[string]int{}
	for _, w := range want {
		inWant[w]++
	}
	var extra []string
	for _, g := range got {
		if inWant[g] > 0 {
			inWant[g]--
		} else {
			extra = append(extra, g)
		}
	}
	var missing []string
	for w, n := range inWant {
		for ; n > 0; n-- {
			missing = append(missing, w)
		}
	}
	if len(extra) > 0 || len(missing) > 0 {
		sort.Strings(extra)
		sort.Strings(missing)
		t.Errorf("candidate streams differ.\n  only hashsmith (%d): %v\n  only john (%d): %v",
			len(extra), firstN(extra, 10), len(missing), firstN(missing, 10))
	}
}

// Each command whose semantics were taken from john itself rather than assumed.
func TestJohnCommandSemantics(t *testing.T) {
	for _, c := range []struct{ rule, in, want string }{
		{"p", "password", "passwords"},
		{"p", "try", "tries"},
		{"p", "box", "boxes"},
		{"p", "wife", "wives"},
		{"P", "password", "passworded"},
		{"P", "try", "tried"},
		{"P", "wife", "wifed"},
		{"I", "password", "passwording"},
		{"I", "wife", "wifing"},
		{"@?v", "password", "psswrd"},
		{`A0"XY"`, "admin", "XYadmin"},
		{`A2"-"`, "admin", "ad-min"},
		// `l` is the ORIGINAL word's length, resolved at run time, so `d`
		// doubles the word and `'l` truncates it straight back.
		{"l d 'l", "admin", "admin"},
		{"l d 'm", "admin", "admi"},
	} {
		prog, err := compileRuleLineDialect(c.rule, true)
		if err != nil {
			t.Errorf("%q: %v", c.rule, err)
			continue
		}
		got, ok := prog.apply(c.in)
		if !ok {
			t.Errorf("%q rejected %q", c.rule, c.in)
			continue
		}
		if got != c.want {
			t.Errorf("%q on %q = %q; want %q (john's own answer)", c.rule, c.in, got, c.want)
		}
	}

	// Reject commands.
	for _, c := range []struct {
		rule, in string
		accept   bool
	}{
		{"%2s", "password", true},
		{"%2s", "AdMiN", false},
		{"%1a", "password", true},
		{"%1a", "AdMiN", false},
		{"!?d", "password", true},
		{"!?d", "box123", false},
		{"/?d", "box123", true},
		{"/?d", "password", false},
		{"(?a", "password", true},
		{"(?d", "password", false},
	} {
		prog, err := compileRuleLineDialect(c.rule, true)
		if err != nil {
			t.Errorf("%q: %v", c.rule, err)
			continue
		}
		if _, ok := prog.apply(c.in); ok != c.accept {
			t.Errorf("%q on %q accepted=%v; want %v", c.rule, c.in, ok, c.accept)
		}
	}

	// M/Q: reject unless the word changed since it was memorised. They cannot
	// be closures — a program is compiled once and run concurrently — so the
	// state lives in apply.
	prog, err := compileRuleLineDialect("M l Q", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prog.apply("admin"); ok {
		t.Error("M l Q accepted a word lowercasing does not change")
	}
	if got, ok := prog.apply("ADMIN"); !ok || got != "admin" {
		t.Errorf("M l Q on ADMIN = %q, %v; want admin, true", got, ok)
	}
}

func readLinesForTest(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
