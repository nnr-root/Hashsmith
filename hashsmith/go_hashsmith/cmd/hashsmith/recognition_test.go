package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
)

// recognitionFloor is a ratchet, not a target. Raise it as coverage improves;
// never lower it to make a change pass.
//
// Measured 2026-09-05 on top of base commit 62e2617 (Task 15's own fixes to
// mssql2012, cisco4 and ripemd320 detection applied on top of that base,
// not present at it): 272/502 = 54.18326...%.
// Set to that rate minus 0.01, computed rather than hand-rounded so the
// margin is exact. See docs/superpowers/notes/2026-09-05-recognition-baseline.md.
const recognitionFloor = 272.0/502.0 - 0.01

func TestRecognitionAccuracy(t *testing.T) {
	var total, recognized int
	missed := map[string]string{}

	for _, v := range universalHashRegistry.vectors {
		if v.target == "" {
			continue
		}
		total++
		ok := false
		for _, c := range identifyCandidates(v.target) {
			if c.Suppressed || c.Type != v.typ {
				continue
			}
			if c.Confidence == hashid.Certain || c.Confidence == hashid.Likely {
				ok = true
			}
			break
		}
		if ok {
			recognized++
		} else if _, dup := missed[v.typ]; !dup {
			missed[v.typ] = v.target
		}
	}

	rate := float64(recognized) / float64(total)
	names := make([]string, 0, len(missed))
	for k := range missed {
		names = append(names, k)
	}
	sort.Strings(names)
	t.Logf("recognition: %d/%d = %.1f%%", recognized, total, rate*100)
	t.Logf("formats not recognized at certain/likely (%d): %s",
		len(names), strings.Join(names, " "))

	if rate < recognitionFloor {
		t.Fatalf("recognition rate %.3f fell below the ratchet %.3f", rate, recognitionFloor)
	}
}

// detectableFloor is a ratchet, not a target: the maximum number of self-test
// vectors whose own type is allowed to be missing from detectHashTypes'
// candidates. It does NOT mean the other vectors ARE detectable — only that
// no more than this many are known NOT to be. Raise the bar by lowering this
// number as detection improves; never raise it to make a change pass.
//
// Re-measured 2026-09-05 immediately after C1's fix (detectTypesFromTable
// filtering non-hash types out of crack's vocabulary): 194, unchanged from
// before that fix, because C1 only removes non-hash candidates (base32,
// morse, nato, ...) that were never a self-test vector's own type to begin
// with.
const detectableFloor = 194

// Every vector must at least be CRACKABLE by auto-detection, which is a weaker
// and more important property than being confidently named. This test only
// guarantees that the count of vectors failing that property has not grown
// past detectableFloor — it does not guarantee any specific vector passes.
func TestEveryVectorIsDetectableForCracking(t *testing.T) {
	var missing []string
	for _, v := range universalHashRegistry.vectors {
		if v.target == "" {
			continue
		}
		found := false
		for _, typ := range detectHashTypes(v.target) {
			if typ == v.typ {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, fmt.Sprintf("%s (%.40s)", v.typ, v.target))
		}
	}
	sort.Strings(missing)
	t.Logf("%d vectors whose own type is not among detectHashTypes' candidates:", len(missing))
	for _, m := range missing {
		t.Log("  " + m)
	}
	if len(missing) > detectableFloor {
		t.Fatalf("%d vectors are not detectable for cracking, exceeding the ratchet of %d",
			len(missing), detectableFloor)
	}
}

// TestNonHashTypesExcludedFromCracking is the regression test for C1: the
// prototype table carries non-hash recognitions (Base32, Morse, NATO, ...)
// so identify can name them, but detectHashTypes/detectTypesFromTable feed
// crack's auto-detection, and crack has no attack routine for any of them.
// Before this test existed, "hashsmith crack -t auto admin" confidently
// misidentified "admin" as base32 and then failed with "unsupported hash
// algorithm: base32" instead of the honest "could not auto-detect" guidance
// — see detectTypesFromTable's crackable() filter in prototypes.go.
//
// The golden corpus (testdata/detect_golden.txt) is 502 hash-shaped vectors
// and contains no ordinary English word, which is exactly why nineteen
// per-task reviews missed this hole; these vectors are deliberately
// non-hash-shaped so they cannot land in that corpus.
func TestNonHashTypesExcludedFromCracking(t *testing.T) {
	nonHashInputs := []string{
		"admin",               // plain word: base32-shaped under a loose Match
		"1 2 3 4 5",           // decimal byte sequence
		"... --- ...",         // Morse code
		"Alpha Bravo Charlie", // NATO phonetic alphabet
	}
	for _, in := range nonHashInputs {
		if got := detectHashTypes(in); len(got) != 0 {
			t.Errorf("detectHashTypes(%q) = %v, want none (crack must never auto-select a non-hash type)", in, got)
		}
		cs := identifyCandidates(in)
		named := false
		for _, c := range cs {
			if !c.Suppressed {
				named = true
				break
			}
		}
		if !named {
			t.Errorf("identifyCandidates(%q) named nothing; identify must keep recognizing non-hash encodings", in)
		}
	}
}

// TestCandidatePrevalenceMatchesTheProtoThatFired is the regression test for
// I4: prevalenceOf (deleted) looked a type up by NAME across the whole
// table and returned the FIRST prototype containing it, not the one that
// actually produced the candidate. krb5tgs is one of nine types that appear
// in more than one prototype with different curated prevalences — the
// etype-23 (Kerberoastable) shape at 30, any other etype at 8 — and the
// etype-23 entry precedes the general one in table order, so the old lookup
// always returned 30 even for a general-etype record. Candidate.Prevalence
// is now copied directly from the firing prototype in the Identify loop, so
// this can no longer happen by construction; this test pins the observable
// behaviour so a future reintroduction of a table-wide lookup is caught.
func TestCandidatePrevalenceMatchesTheProtoThatFired(t *testing.T) {
	general := "$krb5tgs$18$user$realm$abcdef1234567890"
	cs := identifyCandidates(general)
	c := (*hashid.Candidate)(nil)
	for i := range cs {
		if cs[i].Type == "krb5tgs" {
			c = &cs[i]
			break
		}
	}
	if c == nil {
		t.Fatalf("no krb5tgs candidate for %q: %+v", general, cs)
	}
	if c.Prevalence != 8 {
		t.Errorf("krb5tgs (general etype) prevalence = %d, want 8 (the general prototype's own curated value, not the etype-23 prototype's 30)", c.Prevalence)
	}
}

func TestFalsePositives(t *testing.T) {
	notHashes := []string{
		"the quick brown fox jumps over the lazy dog",
		"hello world",
		"550e8400-e29b-41d4-a716-446655440000",
		"/usr/local/bin/hashsmith",
		"1234",
		"{}",
	}
	for _, in := range notHashes {
		for _, c := range identifyCandidates(in) {
			if !c.Suppressed && c.Confidence == hashid.Certain {
				t.Errorf("%q was identified as %s with certainty", in, c.Display)
			}
		}
	}
}
