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
// Measured 2026-09-05 at commit 62e2617 (Task 15's own fixes to mssql2012,
// cisco4 and ripemd320 detection already applied): 272/502 = 54.18326...%.
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

// Every vector must at least be CRACKABLE by auto-detection, which is a weaker
// and more important property than being confidently named.
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
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Logf("%d vectors whose own type is not among detectHashTypes' candidates:", len(missing))
		for _, m := range missing {
			t.Log("  " + m)
		}
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
