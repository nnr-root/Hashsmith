package main

import (
	"path/filepath"
	"testing"
)

func TestPotfileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pot")
	p, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.lookup("deadbeef"); ok {
		t.Fatal("empty potfile should have no entries")
	}
	// A hash containing ':' (NetNTLM-style) and a plaintext containing ':' must
	// round-trip intact thanks to the TAB separator.
	hash := "user::DOMAIN:1122:aabb:ccdd"
	plain := "p:a:s:s"
	p.add(hash, plain)
	p.add(hash, "ignored-duplicate")

	reloaded, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.lookup(hash)
	if !ok || got != plain {
		t.Fatalf("round-trip failed: got %q ok=%v", got, ok)
	}
}
