package main

import (
	"sort"
	"strings"
	"testing"
)

// The embedded fallback wordlist is what a run uses when the machine has no
// rockyou.txt, which is most machines that are not Kali. Its VALUE is not its
// length — it is that the candidates most likely to hit come first, because a
// run that is interrupted, or that is attacking a slow KDF, only ever reaches
// the beginning of it.
//
// That property was absent and nothing noticed. Of the 3,545 entries in John
// the Ripper's default password.lst, the 230,930-line list contained 1,839
// anywhere at all and 91 within its first 5,000 lines: 111 curated passwords
// followed by an alphabetical English dictionary. Length is easy to check and
// was fine; ordering is the thing that mattered and was checked by nothing.
//
// These tests check the ordering.

// headSize is how far into the list the frequency-ordered section must reach.
// It is deliberately smaller than the real head, so adding or removing a few
// entries does not fail the test — only losing the section does.
const headSize = 3000

func embeddedWords(t *testing.T) []string {
	t.Helper()
	words := strings.Split(strings.TrimRight(embeddedCommonWordlist, "\n"), "\n")
	if len(words) < headSize {
		t.Fatalf("the embedded wordlist has %d entries, fewer than the %d-entry head", len(words), headSize)
	}
	return words
}

// TestEmbeddedWordlistHeadIsNotADictionary is the regression test for the
// defect itself. An alphabetically sorted run is the signature of a dictionary
// pasted in where passwords belong: real password frequency order has no
// relationship to spelling, so a frequency-ordered list is sorted only by
// accident and only in short stretches.
func TestEmbeddedWordlistHeadIsNotADictionary(t *testing.T) {
	head := embeddedWords(t)[:headSize]

	if sort.StringsAreSorted(head) {
		t.Fatalf("the first %d entries are in alphabetical order, which means a dictionary has "+
			"been put where the frequency-ordered passwords belong", headSize)
	}

	// A frequency-ordered list still has sorted stretches. The bar is where it
	// is because of two measurements, not taste: the defect ran 145,455 sorted
	// entries out of 230,930, about 63% of the file, while John's own
	// password.lst contains a deliberate 782-entry sorted block of additional
	// common passwords at index 1,135, about 22% of its length. A canonical,
	// hand-curated password list therefore FAILS a strict bar. Half the head
	// sits above what a real list does and well below what a dictionary does.
	longest, run := 1, 1
	for i := 1; i < len(head); i++ {
		if head[i-1] <= head[i] {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 1
		}
	}
	if longest > headSize/2 {
		t.Errorf("the head's longest alphabetically sorted run is %d of %d entries, so most of it "+
			"is a dictionary rather than a frequency-ordered password list", longest, headSize)
	}
}

// TestEmbeddedWordlistLeadsWithCommonPasswords pins the other half: the head
// must actually be common passwords, not merely unsorted text. Every entry
// below appears at the top of every published breach analysis, so a list that
// buries them is not ordered by frequency whatever else it is.
func TestEmbeddedWordlistLeadsWithCommonPasswords(t *testing.T) {
	words := embeddedWords(t)
	rank := make(map[string]int, len(words))
	for i, w := range words {
		if _, seen := rank[w]; !seen {
			rank[w] = i
		}
	}

	for _, want := range []string{
		"123456", "password", "12345678", "qwerty", "abc123",
		"letmein", "monkey", "dragon", "iloveyou", "trustno1",
		"111111", "sunshine", "princess", "admin", "welcome",
	} {
		at, ok := rank[want]
		if !ok {
			t.Errorf("%q is not in the embedded wordlist at all", want)
			continue
		}
		if at >= headSize {
			t.Errorf("%q is at position %d, past the %d-entry head — a short run would never reach it",
				want, at, headSize)
		}
	}
}

// TestEmbeddedWordlistIsWellFormed catches a bad regeneration. Every one of
// these costs a wasted candidate at best; a blank line is a hash attempt
// against the empty password, and a trailing space turns a correct password
// into a wrong one.
func TestEmbeddedWordlistIsWellFormed(t *testing.T) {
	words := embeddedWords(t)
	seen := make(map[string]int, len(words))
	dupes, blanks, padded, carriage := 0, 0, 0, 0
	firstDupe := ""
	for i, w := range words {
		switch {
		case strings.TrimSpace(w) == "":
			blanks++
		case w != strings.TrimSpace(w):
			padded++
		case strings.Contains(w, "\r"):
			carriage++
		}
		if _, ok := seen[w]; ok {
			if dupes == 0 {
				firstDupe = w
			}
			dupes++
		} else {
			seen[w] = i
		}
	}
	if blanks > 0 {
		t.Errorf("%d blank entries: each one attacks the empty password", blanks)
	}
	if padded > 0 {
		t.Errorf("%d entries carry leading or trailing whitespace, which makes a correct password wrong", padded)
	}
	if carriage > 0 {
		t.Errorf("%d entries contain a carriage return, so the file was saved with CRLF line endings", carriage)
	}
	if dupes > 0 {
		t.Errorf("%d duplicate entries, first %q: every one is a candidate tried twice", dupes, firstDupe)
	}
}
