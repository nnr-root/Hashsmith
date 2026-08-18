package main

import "testing"

func TestCombinatorLayout(t *testing.T) {
	left := []string{"super", "iron", "spider"}
	right := []string{"man", "woman", "men"}
	l := combinatorLayout(left, right)
	if l.total != 9 {
		t.Fatalf("total: want 9 got %d", l.total)
	}
	cases := map[int64]string{
		0: "superman", 1: "superwoman", 2: "supermen",
		3: "ironman", 8: "spidermen",
	}
	for i, want := range cases {
		if c := l.candidate(i); c != want {
			t.Errorf("candidate(%d): want %q got %q", i, want, c)
		}
	}
}
