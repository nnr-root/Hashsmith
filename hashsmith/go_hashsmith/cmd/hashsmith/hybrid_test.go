package main

import "testing"

func TestHybridLayout(t *testing.T) {
	words := []string{"password", "summer"}
	sets, err := parseMask(&maskConfig{mask: "?d?d"})
	if err != nil {
		t.Fatal(err)
	}
	// append (word+mask): 2 words × 100 = 200
	l := hybridLayout(words, sets, false)
	if l.total != 200 {
		t.Fatalf("total: want 200 got %d", l.total)
	}
	if c := l.candidate(0); c != "password00" {
		t.Errorf("candidate(0): want password00 got %q", c)
	}
	if c := l.candidate(99); c != "password99" {
		t.Errorf("candidate(99): want password99 got %q", c)
	}
	if c := l.candidate(100); c != "summer00" {
		t.Errorf("candidate(100): want summer00 got %q", c)
	}
	// prepend (mask+word)
	lp := hybridLayout(words, sets, true)
	if c := lp.candidate(100); c != "00summer" {
		t.Errorf("prepend candidate(100): want 00summer got %q", c)
	}
	// full coverage is unique
	seen := map[string]bool{}
	for i := int64(0); i < l.total; i++ {
		seen[l.candidate(i)] = true
	}
	if len(seen) != 200 {
		t.Errorf("coverage: want 200 unique, got %d", len(seen))
	}
}
