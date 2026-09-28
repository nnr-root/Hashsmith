package smith

import "testing"

func TestRuleOps(t *testing.T) {
	cases := []struct{ rule, in, want string }{
		{":", "hello", "hello"},
		{"l", "P@ssW0rd", "p@ssw0rd"},
		{"u", "P@ssW0rd", "P@SSW0RD"},
		{"c", "hELLO", "Hello"},
		{"C", "hello", "hELLO"},
		{"t", "Password", "pASSWORD"},
		{"r", "hello", "olleh"},
		{"d", "hi", "hihi"},
		{"p2", "hi", "hihihi"},
		{"f", "hi", "hiih"},
		{"q", "hi", "hhii"},
		{"{", "hello", "elloh"},
		{"}", "hello", "ohell"},
		{"[", "hello", "ello"},
		{"]", "hello", "hell"},
		{"k", "hello", "ehllo"},
		{"K", "hello", "helol"},
		{"$1", "abc", "abc1"},
		{"^1", "abc", "1abc"},
		{"$ ", "ab", "ab "},
		{"@a", "banana", "bnn"},
		{"sao", "banana", "bonono"},
		{"T0", "hello", "Hello"},
		{"T4", "hello", "hellO"},
		{"D0", "hello", "ello"},
		{"D4", "hello", "hell"},
		{"z2", "hi", "hhhi"},
		{"Z2", "hi", "hiii"},
		{"y2", "hello", "hehello"},
		{"Y2", "hello", "hellolo"},
		{"'3", "hello", "hel"},
		{"o1z", "hello", "hzllo"},
		{"i1z", "hello", "hzello"},
		{"x02", "hello", "he"},
		{"x14", "hello", "ello"},
		{"*04", "hello", "oellh"},
		// multi-command lines
		{"c $1 $2 $3", "pass", "Pass123"},
		{"so0 c $!", "root", "R00t!"},
		{"l r $9", "AB", "ba9"},
	}
	for _, c := range cases {
		p, err := compileRuleLine(c.rule)
		if err != nil {
			t.Errorf("%q: compile error %v", c.rule, err)
			continue
		}
		got, ok := p.apply(c.in)
		if !ok {
			t.Errorf("%q on %q: unexpectedly rejected", c.rule, c.in)
			continue
		}
		if got != c.want {
			t.Errorf("%q on %q: got %q want %q", c.rule, c.in, got, c.want)
		}
	}
}

func TestRuleRejects(t *testing.T) {
	rejects := []struct{ rule, in string }{
		{">6", "short"},    // len 5, not > 6 → reject
		{"<3", "hello"},    // len 5, not < 3 → reject
		{"_4", "hello"},    // len 5 != 4 → reject
		{"!s", "password"}, // contains 's' → reject
		{"/z", "password"}, // lacks 'z' → reject
	}
	// NOTE: an out-of-range POSITION is deliberately not in this list. Rules
	// like T9/D9/*19 on a short word used to be rejected here; hashcat leaves
	// the word unchanged instead, and rejecting shrank the searched keyspace
	// for any rule file using them. The reject list is now only the explicit
	// gates (<N >N _N !X /X). See TestRuleOutOfRangePositionsPassThrough and
	// the oracle vectors in rules_hashcat_compat_test.go.
	for _, c := range rejects {
		p, err := compileRuleLine(c.rule)
		if err != nil {
			t.Errorf("%q: compile error %v", c.rule, err)
			continue
		}
		if _, ok := p.apply(c.in); ok {
			t.Errorf("%q on %q: expected rejection, got accepted", c.rule, c.in)
		}
	}
	// Passing conditions
	keep := []struct{ rule, in string }{
		{">3", "hello"}, {"<9", "hello"}, {"_5", "hello"}, {"!z", "hello"}, {"/e", "hello"},
	}
	for _, c := range keep {
		p, _ := compileRuleLine(c.rule)
		if _, ok := p.apply(c.in); !ok {
			t.Errorf("%q on %q: expected accept, got rejected", c.rule, c.in)
		}
	}
}

func TestRuleCompileErrors(t *testing.T) {
	for _, bad := range []string{"$", "^", "sX", "Q", "T", "TZZ"[:1]} {
		if _, err := compileRuleLine(bad); err == nil {
			t.Errorf("%q: expected compile error", bad)
		}
	}
}

func TestRuleEngineDedup(t *testing.T) {
	e := &ruleEngine{}
	for _, line := range []string{":", "l", "u", "c"} {
		p, err := compileRuleLine(line)
		if err != nil {
			t.Fatal(err)
		}
		e.programs = append(e.programs, p)
	}
	// base word "abc": ":"→abc(==identity, skipped), l→abc(==identity, skipped),
	// u→ABC, c→Abc  → 2 unique candidates.
	got := e.expand("abc")
	if len(got) != 2 {
		t.Fatalf("want 2 unique candidates, got %d: %+v", len(got), got)
	}
}

// TestRuleOutOfRangePositionsPassThrough pins the direction of the fix: a
// position operand past the end of the word leaves the word unchanged rather
// than dropping the candidate. Rejecting is the dangerous direction — it
// silently removes candidates from the search and reports "not found".
func TestRuleOutOfRangePositionsPassThrough(t *testing.T) {
	for _, rule := range []string{"T9", "D9", "*19", "o9z", "i9z", "x29", "y9", "Y9", "O99", "+9", "-9", "L9", "R9", ".9", ",9"} {
		p, err := compileRuleLine(rule)
		if err != nil {
			t.Errorf("%q: compile error %v", rule, err)
			continue
		}
		got, ok := p.apply("hello")
		if !ok {
			t.Errorf("%q on %q: rejected; hashcat passes the word through", rule, "hello")
			continue
		}
		if got != "hello" {
			t.Errorf("%q on %q: got %q, want the word unchanged", rule, "hello", got)
		}
	}
}
