package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn while capturing everything written to os.Stdout.
func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() {
		var sb strings.Builder
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			sb.WriteString(sc.Text())
			sb.WriteByte('\n')
		}
		done <- sb.String()
	}()
	err := fn()
	w.Close()
	os.Stdout = old
	out := <-done
	if err != nil {
		t.Fatalf("streamCandidates error: %v", err)
	}
	return out
}

func TestStreamCandidates(t *testing.T) {
	// mask: ?l?d begins a,0 and has 260 candidates in order
	out := captureStdout(t, func() error {
		return streamCandidates("mask", "", "", "", 0, 0, &maskConfig{mask: "?l?d"}, nil, 0, 0)
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 260 {
		t.Errorf("mask: want 260 candidates, got %d", len(lines))
	}
	if lines[0] != "a0" || lines[1] != "a1" {
		t.Errorf("mask order wrong: %q %q", lines[0], lines[1])
	}

	// brute ab n1..2 → a b aa ab ba bb
	out = captureStdout(t, func() error {
		return streamCandidates("brute", "", "", "ab", 1, 2, nil, nil, 0, 0)
	})
	if got := strings.Fields(out); strings.Join(got, ",") != "a,b,aa,ab,ba,bb" {
		t.Errorf("brute order: %v", got)
	}
}
