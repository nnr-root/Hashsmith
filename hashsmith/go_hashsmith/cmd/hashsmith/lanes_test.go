package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestDictAttackLanesFindsAtEveryPosition is the test that matters: the lane
// buffer must be flushed at end-of-batch and end-of-wordlist, or trailing
// candidates go untested and a crackable password is silently reported as not
// found - the worst possible failure for a cracker.
func TestDictAttackLanesFindsAtEveryPosition(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("needle"), 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 2, 3, 5, 7, 8, 9, 17} {
		for _, pos := range []int{0, n / 2, n - 1} {
			words := make([]string, n)
			for i := range words {
				words[i] = "chaff"
			}
			words[pos] = "needle"

			dir := t.TempDir()
			path := filepath.Join(dir, "wl.txt")
			var buf []byte
			for _, w := range words {
				buf = append(buf, w...)
				buf = append(buf, '\n')
			}
			if err := os.WriteFile(path, buf, 0o600); err != nil {
				t.Fatal(err)
			}

			var attempts int64
			verify := func(c string) bool {
				return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
			}
			res, err := dictAttack(context.Background(), path, 0, 0, 2, &attempts, nil,
				verify, string(crypt), "bcrypt", "", "prefix")
			if err != nil {
				t.Fatalf("n=%d pos=%d: %v", n, pos, err)
			}
			if res.password != "needle" {
				t.Errorf("n=%d pos=%d: got %q, want \"needle\"", n, pos, res.password)
			}
			if atomic.LoadInt64(&attempts) < int64(pos+1) {
				t.Errorf("n=%d pos=%d: only %d attempts counted", n, pos, attempts)
			}
		}
	}
}

// TestDictAttackLanesRuleLabels pins hit attribution: a match found in lane 3
// must report lane 3's rule label, not a neighbour's.
func TestDictAttackLanesRuleLabels(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("needle1"), 4)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(path, []byte("aaa\nbbb\nneedle\nccc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Ruling F-8: the brief calls a nonexistent newRuleEngineFromRules
	// constructor. Build the engine directly, matching this repo's own
	// tests (see rules_test.go:106-114 / TestRuleEngineDedup).
	e := &ruleEngine{}
	p, err := compileRuleLine("$1")
	if err != nil {
		t.Fatal(err)
	}
	e.programs = append(e.programs, p)
	rules := e
	var attempts int64
	verify := func(c string) bool {
		return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
	}
	res, err := dictAttack(context.Background(), path, 0, 0, 2, &attempts, rules,
		verify, string(crypt), "bcrypt", "", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	if res.password != "needle1" {
		t.Fatalf("got %q, want \"needle1\"", res.password)
	}
	if res.ruleLabel != "$1" {
		t.Errorf("rule label %q, want \"$1\"", res.ruleLabel)
	}
}
