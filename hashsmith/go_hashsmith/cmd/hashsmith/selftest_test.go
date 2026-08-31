package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// fastVectorBudget is the per-vector ceiling for the default suite. It exists
// to catch a self-test vector that is secretly a high-iteration or
// memory-hard KDF hiding in the fast suite: those take *seconds* (the
// VeraCrypt vector that originally caused a 600s suite timeout ran ~85s on
// its own), so the guard's discriminating power lives three orders of
// magnitude above any legitimate fast vector.
//
// Measured on an otherwise-busy dev machine (8 cores, ambient load average
// ~14-21 from unrelated processes) by timing every fast-classified vector
// across ~20 repeated runs: the slowest legitimate vectors (sha1crypt,
// sm3crypt, symfony-legacy, snmpv3, cisco8/9, sap-issha*) sat at roughly
// 15-30ms with the machine otherwise idle, but ambient contention alone
// (no deliberate load) pushed isolated samples as high as ~180ms - in line
// with two independent reviewers reproducing 64-67ms runs at load average
// ~19 against the old 50ms budget. 500ms is ~10-30x the idle-case slowest
// vector and still comfortably clears the contended samples we observed,
// while remaining ~170x below a real slow KDF, so it stays a strict guard
// against misclassification without flaking under CI/CPU contention.
const fastVectorBudget = 500 * time.Millisecond

// A fast-classified vector that takes longer than the budget has been
// misclassified; failing here keeps the default suite from creeping back
// toward the 600s timeout one vector at a time.
func TestFastVectorsStayWithinBudget(t *testing.T) {
	var over []string
	for _, v := range universalHashRegistry.vectors {
		if universalHashRegistry.isSlow(v.typ) {
			continue
		}
		start := time.Now()
		verifyCandidate(v.password, v.target, v.typ, v.salt, "prefix")
		if d := time.Since(start); d > fastVectorBudget {
			over = append(over, fmt.Sprintf("%s took %v", v.typ, d.Round(time.Millisecond)))
		}
	}
	if len(over) > 0 {
		t.Errorf("%d fast-classified vector(s) exceeded %v; add each type to "+
			"slowSelfTestTypeSeed() in selftest.go:\n  %s",
			len(over), fastVectorBudget, strings.Join(over, "\n  "))
	}
}

// checkSelfTestVector asserts one vector matches its known answer and rejects
// a wrong password. Shared by the fast and slow suites.
func checkSelfTestVector(t *testing.T, v selfTestVector) {
	t.Helper()
	ok, err := verifyCandidate(v.password, v.target, v.typ, v.salt, "prefix")
	if err != nil {
		t.Errorf("%s: %v", v.typ, err)
		return
	}
	if !ok {
		t.Errorf("%s: vector did not match its known answer", v.typ)
		return
	}
	if bad, _ := verifyCandidate(wrongPassword(v.password), v.target, v.typ, v.salt, "prefix"); bad {
		t.Errorf("%s: accepted a wrong password", v.typ)
	}
}

// The fast vectors must pass on every run. Slow KDFs are covered by
// TestSelfTestVectorsSlow behind the slowtest build tag.
func TestSelfTestVectorsAllPass(t *testing.T) {
	if len(universalHashRegistry.vectors) == 0 {
		t.Fatal("no self-test vectors are compiled in")
	}
	ran := 0
	for _, v := range universalHashRegistry.vectors {
		if universalHashRegistry.isSlow(v.typ) {
			continue
		}
		checkSelfTestVector(t, v)
		ran++
	}
	if ran == 0 {
		t.Fatal("every vector was classified slow; the fast suite tested nothing")
	}
	t.Logf("fast vectors run: %d", ran)
}

// The split must actually exclude something, or the classification has
// silently stopped being applied and the suite will creep back to 600s.
func TestSlowVectorsAreExcludedFromFastSuite(t *testing.T) {
	slow := 0
	for _, v := range universalHashRegistry.vectors {
		if universalHashRegistry.isSlow(v.typ) {
			slow++
		}
	}
	if slow == 0 {
		t.Fatal("no vectors are classified slow — expected ~146 high-iteration KDFs")
	}
	t.Logf("slow vectors excluded from the fast suite: %d", slow)
}

// Every vector must name a type the engine implements and the catalogue lists.
func TestSelfTestVectorsNameRealTypes(t *testing.T) {
	documented := map[string]bool{}
	for _, group := range universalHashRegistry.groups {
		for _, item := range group.items {
			documented[canonicalHashType(strings.Fields(item[0])[0])] = true
		}
	}
	for _, v := range universalHashRegistry.vectors {
		canonical := canonicalHashType(v.typ)
		if canonical != v.typ {
			t.Errorf("vector type %q should be spelled canonically as %q", v.typ, canonical)
		}
		if !documented[canonical] {
			t.Errorf("vector type %q is not listed by `hashsmith types`", v.typ)
		}
	}
}

// wrongPassword has to survive formats that truncate the password, which is
// exactly where a naive "append junk" mutation silently stops testing anything.
func TestWrongPasswordMutatesTheFirstByte(t *testing.T) {
	cases := map[string]string{
		"password":  "aassword",
		"abc":       "bbc",
		"":          "x",
		"a":         "b",
		"hashsmith": "aashsmith",
	}
	for in, want := range cases {
		if got := wrongPassword(in); got != want {
			t.Errorf("wrongPassword(%q) = %q, want %q", in, got, want)
		}
		if got := wrongPassword(in); got == in {
			t.Errorf("wrongPassword(%q) returned the same string", in)
		}
	}
	// The mutation must land inside the first 8 bytes, which is the shortest
	// truncation limit among supported formats (DES crypt).
	long := "passwordpasswordpassword"
	if wrongPassword(long)[:8] == long[:8] {
		t.Error("mutation fell outside the DES-crypt truncation window")
	}
}

// Coverage accounting must not double-count or invent types.
func TestSelfTestCoverageAccounting(t *testing.T) {
	covered, uncovered := selfTestCoverage()
	if len(covered) == 0 {
		t.Fatal("coverage reported no types with vectors")
	}
	seen := map[string]bool{}
	for _, name := range append(append([]string{}, covered...), uncovered...) {
		if seen[name] {
			t.Errorf("%q appears twice in the coverage split", name)
		}
		seen[name] = true
	}
	haveVector := map[string]bool{}
	for _, v := range universalHashRegistry.vectors {
		haveVector[canonicalHashType(v.typ)] = true
	}
	for _, name := range uncovered {
		if haveVector[canonicalHashType(name)] {
			t.Errorf("%q has a vector but was reported as uncovered", name)
		}
	}
}
