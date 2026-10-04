package smith

import (
	"os"
	"testing"
)

func TestCoordinatorKeyspaceMask(t *testing.T) {
	// ?l?l is 26*26 = 676.
	got, err := coordinatorKeyspace("mask", "?l?l", "", "", "", "", "", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != 676 {
		t.Fatalf("got %d, want 676", got)
	}
}

func TestCoordinatorKeyspaceBrute(t *testing.T) {
	// charset "ab", minLen 1, maxLen 2: "a","b" (2) + "aa".."bb" (4) = 6.
	got, err := coordinatorKeyspace("brute", "", "", "", "", "", "ab", 1, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != 6 {
		t.Fatalf("got %d, want 6", got)
	}
}

func TestCoordinatorKeyspaceDict(t *testing.T) {
	path := t.TempDir() + "/words.txt"
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := coordinatorKeyspace("dict", "", "", "", "", "", "", 0, 0, path)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Fatalf("got %d, want 3", got)
	}
}

func TestCoordinatorKeyspaceUnknownMode(t *testing.T) {
	if _, err := coordinatorKeyspace("nonsense", "", "", "", "", "", "", 0, 0, ""); err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
}
