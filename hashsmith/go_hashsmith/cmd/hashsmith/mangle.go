package main

import (
	"strings"
	"unicode"
)

// mangledWord pairs a candidate password with a human-readable rule label.
type mangledWord struct {
	password  string
	ruleLabel string
}

// manglingRule is a named transformation applied to a base dictionary word.
type manglingRule struct {
	label string
	fn    func(string) string
}

// ── Primitive transforms ──────────────────────────────────────────────────────

// leetMap maps common characters to their leet-speak equivalents.
var leetMap = map[rune]rune{
	'a': '4', 'A': '4',
	'e': '3', 'E': '3',
	'i': '1', 'I': '1',
	'o': '0', 'O': '0',
	's': '5', 'S': '5',
	't': '7', 'T': '7',
	'l': '1', 'L': '1',
	'g': '9', 'G': '9',
	'b': '8', 'B': '8',
}

func mangleCapitalize(w string) string {
	if w == "" {
		return w
	}
	r := []rune(w)
	r[0] = unicode.ToUpper(r[0])
	for i := 1; i < len(r); i++ {
		r[i] = unicode.ToLower(r[i])
	}
	return string(r)
}

func mangleLeet(w string) string {
	r := []rune(w)
	for i, ch := range r {
		if rep, ok := leetMap[ch]; ok {
			r[i] = rep
		}
	}
	return string(r)
}

func mangleReverse(w string) string {
	r := []rune(w)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func mangleToggle(w string) string {
	r := []rune(w)
	for i, ch := range r {
		if unicode.IsUpper(ch) {
			r[i] = unicode.ToLower(ch)
		} else {
			r[i] = unicode.ToUpper(ch)
		}
	}
	return string(r)
}

// ── Rule set construction ─────────────────────────────────────────────────────

func buildManglingRules() []manglingRule {
	up := strings.ToUpper
	lo := strings.ToLower
	cap_ := mangleCapitalize
	leet := mangleLeet
	rev := mangleReverse

	// appendRule creates a rule that appends suffix s to a word.
	appendRule := func(label, s string) manglingRule {
		return manglingRule{label: label, fn: func(w string) string { return w + s }}
	}
	// prependRule creates a rule that prepends prefix p to a word.
	prependRule := func(label, p string) manglingRule {
		return manglingRule{label: label, fn: func(w string) string { return p + w }}
	}
	// compoundRule creates a rule that applies transform t then appends s.
	compoundRule := func(label, s string, t func(string) string) manglingRule {
		return manglingRule{label: label, fn: func(w string) string { return t(w) + s }}
	}

	rules := []manglingRule{
		// ── Case transforms ───────────────────────────────────────────────────
		{label: "Lowercase", fn: lo},
		{label: "Uppercase", fn: up},
		{label: "Capitalize", fn: cap_},
		{label: "Toggle case", fn: mangleToggle},

		// ── Leet speak ────────────────────────────────────────────────────────
		{label: "Leet", fn: leet},
		{label: "Capitalize + Leet", fn: func(w string) string { return leet(cap_(w)) }},
		{label: "Leet + Capitalize", fn: func(w string) string { return cap_(leet(w)) }},

		// ── Reverse ───────────────────────────────────────────────────────────
		{label: "Reverse", fn: rev},
		{label: "Reverse + Capitalize", fn: func(w string) string { return cap_(rev(w)) }},

		// ── Double word ───────────────────────────────────────────────────────
		{label: "Double", fn: func(w string) string { return w + w }},
	}

	// ── Digit suffix appends: 0-9 ────────────────────────────────────────────
	for _, d := range "0123456789" {
		rules = append(rules, appendRule("Append '"+string(d)+"'", string(d)))
	}

	// ── Common number-string suffixes ────────────────────────────────────────
	for _, s := range []string{"12", "123", "1234", "12345", "01", "11", "00", "99"} {
		rules = append(rules, appendRule("Append '"+s+"'", s))
	}

	// ── Special-character suffixes ───────────────────────────────────────────
	for _, s := range []string{"!", "@", "#", "!!", "1!", "123!", "!123", "?", "*"} {
		rules = append(rules, appendRule("Append '"+s+"'", s))
	}

	// ── Year suffixes ────────────────────────────────────────────────────────
	for _, s := range []string{"2019", "2020", "2021", "2022", "2023", "2024", "2025"} {
		rules = append(rules, appendRule("Append '"+s+"'", s))
	}

	// ── Capitalize + digit suffix ────────────────────────────────────────────
	for _, d := range "0123456789" {
		rules = append(rules, compoundRule("Capitalize + Append '"+string(d)+"'", string(d), cap_))
	}

	// ── Capitalize + common suffixes ─────────────────────────────────────────
	for _, s := range []string{"1", "123", "!", "1234", "2023", "2024", "123!", "!!"} {
		rules = append(rules, compoundRule("Capitalize + Append '"+s+"'", s, cap_))
	}

	// ── Uppercase + digit suffix ─────────────────────────────────────────────
	for _, d := range "123456789" {
		rules = append(rules, compoundRule("Uppercase + Append '"+string(d)+"'", string(d), up))
	}

	// ── Uppercase + common suffixes ───────────────────────────────────────────
	for _, s := range []string{"1", "123", "!", "2024"} {
		rules = append(rules, compoundRule("Uppercase + Append '"+s+"'", s, up))
	}

	// ── Leet + Capitalize + common suffixes ───────────────────────────────────
	leetCap := func(w string) string { return cap_(leet(w)) }
	for _, s := range []string{"1", "123", "!", "2024"} {
		rules = append(rules, compoundRule("Leet + Capitalize + Append '"+s+"'", s, leetCap))
	}

	// ── Digit prefixes ───────────────────────────────────────────────────────
	for _, d := range "123456789" {
		rules = append(rules, prependRule("Prepend '"+string(d)+"'", string(d)))
	}

	// ── Common string prefixes ───────────────────────────────────────────────
	for _, s := range []string{"0", "!", "123", "the"} {
		rules = append(rules, prependRule("Prepend '"+s+"'", s))
	}

	return rules
}

// allManglingRules is the global ordered rule set, built once at startup.
var allManglingRules = buildManglingRules()

// NumManglingRules is the total number of rules (used for progress estimation).
var NumManglingRules = len(allManglingRules)

// expandRules applies all mangling rules to word and returns unique candidate/
// label pairs.  The original word is NOT included — the caller already tests it
// before calling expandRules.
func expandRules(word string) []mangledWord {
	seen := make(map[string]struct{}, NumManglingRules+1)
	seen[word] = struct{}{} // skip identity (already tested by caller)

	out := make([]mangledWord, 0, NumManglingRules)
	for _, rule := range allManglingRules {
		candidate := rule.fn(word)
		if _, dup := seen[candidate]; dup {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, mangledWord{password: candidate, ruleLabel: rule.label})
	}
	return out
}
