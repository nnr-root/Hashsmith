package main

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
		{"T9", "hello"},    // position 9 out of range → reject
		{"D9", "hello"},
		{"*19", "hello"},
	}
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
