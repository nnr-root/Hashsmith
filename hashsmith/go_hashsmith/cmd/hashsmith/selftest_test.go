package main

import (
	"strings"
	"testing"
)

// The vectors shipped in the binary must actually pass — otherwise `hashsmith
// selftest` would report a broken build as healthy.
func TestSelfTestVectorsAllPass(t *testing.T) {
	if len(selfTestVectors) == 0 {
		t.Fatal("no self-test vectors are compiled in")
	}
	for _, v := range selfTestVectors {
		ok, err := verifyCandidate(v.password, v.target, v.typ, v.salt, "prefix")
		if err != nil {
			t.Errorf("%s: %v", v.typ, err)
			continue
		}
		if !ok {
			t.Errorf("%s: vector did not match its known answer", v.typ)
			continue
		}
		if bad, _ := verifyCandidate(wrongPassword(v.password), v.target, v.typ, v.salt, "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", v.typ)
		}
	}
}

// Every vector must name a type the engine implements and the catalogue lists.
func TestSelfTestVectorsNameRealTypes(t *testing.T) {
	documented := map[string]bool{}
	for _, group := range hashTypeCatalogue {
		for _, item := range group.items {
			documented[canonicalHashType(strings.Fields(item[0])[0])] = true
		}
	}
	for _, v := range selfTestVectors {
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
	for _, v := range selfTestVectors {
		haveVector[canonicalHashType(v.typ)] = true
	}
	for _, name := range uncovered {
		if haveVector[canonicalHashType(name)] {
			t.Errorf("%q has a vector but was reported as uncovered", name)
		}
	}
}
