package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWordlistCountable(t *testing.T) {
	dir := t.TempDir()

	// regular file → countable
	reg := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(reg, []byte("a\nb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !wordlistCountable(reg) {
		t.Error("regular file should be countable")
	}
	if n, _ := countWordlistLines(reg); n != 2 {
		t.Errorf("regular file count: want 2 got %d", n)
	}

	// empty path (embedded default) → countable
	if !wordlistCountable("") {
		t.Error("embedded default should be countable")
	}

	// directory → not a regular file → not countable
	if wordlistCountable(dir) {
		t.Error("directory should not be countable")
	}

	// FIFO / pipe → one-shot stream → not countable, and count returns -1
	// WITHOUT reading it (so the attack can still consume the data).
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	if wordlistCountable(fifo) {
		t.Error("FIFO should not be countable")
	}
	if n, err := countWordlistLines(fifo); n != -1 || err != nil {
		t.Errorf("FIFO count: want (-1,nil) got (%d,%v)", n, err)
	}
}
