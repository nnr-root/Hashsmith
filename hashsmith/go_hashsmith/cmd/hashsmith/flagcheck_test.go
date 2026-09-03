package main

import "testing"

// A salt mode the tool cannot honour used to be accepted and then answered
// "not found": every consumer tests `saltMode == "suffix"`, so "sufix",
// "postfix" and every other spelling silently meant prefix. A suffix-salted
// dump attacked with a mistyped -S hashed the salt on the wrong end and
// reported every target as uncracked, which reads exactly like an exhaustive
// miss.
func TestCheckSaltModeRejectsAnythingItCannotHonour(t *testing.T) {
	for _, ok := range validSaltModes {
		if err := checkSaltMode(ok); err != nil {
			t.Errorf("checkSaltMode(%q) = %v, want nil", ok, err)
		}
	}
	// "" is included deliberately: the flag defaults to "prefix", so an empty
	// mode can only arrive from a caller that cleared it, and treating it as
	// prefix is the same silent guess.
	for _, bad := range []string{"sufix", "postfix", "append", "Prefix", "SUFFIX", "", "pre"} {
		if err := checkSaltMode(bad); err == nil {
			t.Errorf("checkSaltMode(%q) = nil, want an error — a mode the tool "+
				"cannot honour must not be silently read as prefix", bad)
		}
	}
}

// An empty brute charset has an empty keyspace: the run swept zero candidates
// and still printed "Not found". The usual cause is -C "$VAR" with VAR unset.
func TestCheckBruteCharsetRejectsEmptyOnlyInBruteMode(t *testing.T) {
	if err := checkBruteCharset("brute", ""); err == nil {
		t.Error("an empty -C in brute mode must be refused, not swept as zero candidates")
	}
	if err := checkBruteCharset("brute", "abc"); err != nil {
		t.Errorf("a non-empty charset must pass: %v", err)
	}
	// Every other mode supplies its candidates from somewhere else — a mask,
	// a wordlist, an element list — so an empty -C there is simply unused and
	// must not be turned into an error.
	for _, m := range []string{"mask", "dict", "hybrid", "markov", "combinator", "prince"} {
		if err := checkBruteCharset(m, ""); err != nil {
			t.Errorf("-M %s does not use -C, so an empty one must pass: %v", m, err)
		}
	}
}
