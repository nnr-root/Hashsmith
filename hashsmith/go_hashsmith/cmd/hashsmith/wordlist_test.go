//go:build !windows

// This test exercises FIFO handling via syscall.Mkfifo, which does not exist
// on windows/amd64 (go vet fails to compile the file there without this
// constraint). The FIFO behavior it checks is Unix-specific to begin with,
// so excluding the whole file on windows is not a loss of coverage.
package main

import (
	"bytes"
	"io"
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

// --keyspace must refuse (stderr error, nonzero exit at the CLI layer) rather
// than print countWordlistLines' -1 "not countable" sentinel as if it were a
// real word count. A script doing K=$(hashsmith ... --keyspace) and dividing
// K would otherwise get a nonsensical negative slice size — the same failure
// mode as the already-handled over-int64 case, just from a different cause.
func TestPrintKeyspaceRefusesUncountableWordlist(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	kErr := printKeyspace("dict", fifo, "", "", 0, 0, nil)
	os.Stdout = origStdout
	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if kErr == nil {
		t.Fatal("want an error for a non-seekable (FIFO) wordlist, got nil")
	}
	if buf.Len() != 0 {
		t.Errorf("stdout must stay empty on refusal, got %q", buf.String())
	}
}

// hybrid and combinator modes count wordlists through the same
// exactWordlistCount guard as dict; a FIFO on the combinator's right-hand
// list must refuse exactly like the left-hand one.
func TestPrintKeyspaceRefusesUncountableCombinatorWordlist(t *testing.T) {
	dir := t.TempDir()
	left := filepath.Join(dir, "left.txt")
	if err := os.WriteFile(left, []byte("a\nb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe2")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	if err := printKeyspace("combinator", left, fifo, "", 0, 0, nil); err == nil {
		t.Fatal("want an error when the right-hand wordlist is not seekable, got nil")
	}
}
