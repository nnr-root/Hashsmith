package main

import (
	"strings"
	"testing"
)

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
		t.Fatal("no vectors are classified slow — expected ~120 high-iteration KDFs")
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
