package main

import "fmt"

// Validation for two flags whose bad values used to be accepted silently and
// then answered "not found".
//
// Both are the same failure this codebase keeps removing: an input the tool
// cannot honour, producing a plausible answer to a question nobody asked. A
// typo does not look like a typo — it looks like the password was not in the
// keyspace.

// validSaltModes is the complete set. Everywhere the salt mode is consumed the
// test is `saltMode == "suffix"` (keyspace.go, stdfast.go, hash.go), so every
// other spelling — "sufix", "postfix", "append" — silently meant prefix. A
// suffix-salted dump attacked with a mistyped -S would report every target as
// not found while hashing the salt on the wrong end.
var validSaltModes = []string{"prefix", "suffix"}

// checkSaltMode rejects a salt mode the tool would otherwise misinterpret.
func checkSaltMode(mode string) error {
	for _, v := range validSaltModes {
		if mode == v {
			return nil
		}
	}
	return fmt.Errorf("unknown salt mode %q: expected one of prefix, suffix "+
		"(an unrecognised mode used to be treated as prefix, which hashes the "+
		"salt on the wrong end and reports every target as not found)", mode)
}

// checkBruteCharset rejects an empty brute-force charset. An empty charset has
// an empty keyspace, so the run swept zero candidates and still printed "Not
// found" — indistinguishable from a real exhaustive miss. The likely cause is
// a shell variable that did not expand: -C "$CHARSET" with CHARSET unset.
func checkBruteCharset(mode, charset string) error {
	if mode != "brute" || charset != "" {
		return nil
	}
	return fmt.Errorf("-C is empty, so there are no candidates to try " +
		"(an unset shell variable in -C \"$VAR\" is the usual cause); " +
		"pass a charset, or use -M mask for per-position charsets")
}
