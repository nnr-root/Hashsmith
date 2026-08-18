package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCombinatorAttack(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "l.txt")
	right := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(left, []byte("super\niron\nspider\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, []byte("man\nwoman\nmen\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var n int64
	got, _ := combinatorAttack(context.Background(), left, right, 4,
		func(c string) bool { return c == "spiderman" }, &n)
	if got != "spiderman" {
		t.Errorf("got %q want spiderman", got)
	}

	// exhaustive enumeration when nothing matches: 3 × 3 = 9 attempts
	n = 0
	got, _ = combinatorAttack(context.Background(), left, right, 4,
		func(c string) bool { return false }, &n)
	if got != "" {
		t.Errorf("expected no match, got %q", got)
	}
	if n != 9 {
		t.Errorf("expected 9 attempts (3×3), got %d", n)
	}
}
