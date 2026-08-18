package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHybridAttackDirections(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte("password\nsummer\ndragon\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sets, err := parseMask(&maskConfig{mask: "?d?d"})
	if err != nil {
		t.Fatal(err)
	}

	// append (word+mask): "summer" + "24"
	var n int64
	got, _ := hybridAttack(context.Background(), wl, sets, false, 4,
		func(c string) bool { return c == "summer24" }, &n)
	if got != "summer24" {
		t.Errorf("append: got %q want summer24", got)
	}

	// prepend (mask+word): "24" + "dragon"
	got, _ = hybridAttack(context.Background(), wl, sets, true, 4,
		func(c string) bool { return c == "24dragon" }, &n)
	if got != "24dragon" {
		t.Errorf("prepend: got %q want 24dragon", got)
	}

	// no match → empty, and the full keyspace was enumerated (3 words × 100)
	n = 0
	got, _ = hybridAttack(context.Background(), wl, sets, false, 4,
		func(c string) bool { return false }, &n)
	if got != "" {
		t.Errorf("expected no match, got %q", got)
	}
	if n != 300 {
		t.Errorf("expected 300 attempts (3 words × 100), got %d", n)
	}
}
