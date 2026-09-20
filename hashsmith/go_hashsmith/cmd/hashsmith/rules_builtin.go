package main

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// ── Bundled rulesets ──────────────────────────────────────────────────────────
//
// Hashsmith shipped no rule files at all, so `--rules best64.rule` — the first
// thing anyone types, because it is what every hashcat tutorial uses — had
// nothing to point at. The rule ENGINE was complete and hashcat-compatible;
// there was simply no content for it to run.
//
// These are authored here rather than copied from another project, and are
// deliberately small. Every rule multiplies the wordlist, so a first pass wants
// the transformations with the highest yield per unit of work, not every
// transformation that exists.
//
// They are embedded so they work from a single downloaded binary with nothing
// installed alongside it, which is the distribution promise this project makes.
// A bare name resolves to one of these; anything that names an existing file
// still reads that file, so a user's own rules always win.

//go:embed rules/*.rule
var builtinRuleFS embed.FS

// builtinRuleNames lists the bundled rulesets, sorted.
func builtinRuleNames() []string {
	entries, err := fs.ReadDir(builtinRuleFS, "rules")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".rule"))
	}
	sort.Strings(out)
	return out
}

// builtinRuleSource returns the text of a bundled ruleset.
//
// Both "best" and "best.rule" resolve, so it does not matter whether the user
// types the name or the filename. A name Hashsmith does not bundle — hashcat's
// "best64.rule", say — deliberately does NOT alias onto one of these: that file
// has specific contents, and quietly substituting different rules under its
// name would make a run unreproducible. It errors instead, listing what IS
// available.
func builtinRuleSource(name string) (string, bool) {
	base := strings.TrimSuffix(path.Base(name), ".rule")
	if base == "" || strings.ContainsAny(base, `/\`) {
		return "", false
	}
	b, err := builtinRuleFS.ReadFile("rules/" + base + ".rule")
	if err != nil {
		return "", false
	}
	return string(b), true
}

// unknownRuleFileError explains a --rules value that is neither a readable file
// nor a bundled name, and lists what IS available — a plain "no such file" for
// `--rules best64.rule` tells the user nothing about what they could have typed.
func unknownRuleFileError(name string) error {
	return fmt.Errorf("no rule file %q, and no bundled ruleset by that name.\n"+
		"  bundled: %s\n"+
		"  or pass a path to your own rule file",
		name, strings.Join(builtinRuleNames(), ", "))
}

// openRuleSource resolves a --rules value to a reader: a readable file first,
// then a bundled ruleset by bare name. label names the source for messages.
func openRuleSource(name string) (io.Reader, string, error) {
	f, err := os.Open(name)
	if err == nil {
		return f, strconv.Quote(name), nil
	}
	if text, ok := builtinRuleSource(name); ok {
		return strings.NewReader(text), "bundled ruleset " + strconv.Quote(strings.TrimSuffix(path.Base(name), ".rule")), nil
	}
	if os.IsNotExist(err) {
		return nil, "", unknownRuleFileError(name)
	}
	return nil, "", err
}
