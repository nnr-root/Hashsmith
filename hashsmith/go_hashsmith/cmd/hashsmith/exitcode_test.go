package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExitCodeAggregation(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	os.WriteFile(wl, []byte("password\nadmin\n"), 0644)
	cc, _ := newCrackCtx("", true, "", false, "", false) // no potfile

	// all cracked → exitCode 0
	exitCode = 0
	crackTargets([]string{md5hex("password")}, "md5", "dict", wl, "",
		1, 4, 2, "", "prefix", "", false, nil, nil, cc)
	if exitCode != 0 {
		t.Errorf("cracked: exitCode=%d want 0", exitCode)
	}

	// not found → exitCode 1
	exitCode = 0
	crackTargets([]string{md5hex("nowhere-in-list")}, "md5", "dict", wl, "",
		1, 4, 2, "", "prefix", "", false, nil, nil, cc)
	if exitCode != 1 {
		t.Errorf("not found: exitCode=%d want 1", exitCode)
	}
	exitCode = 0 // reset for other tests
}

func TestProbeRejectsUnknownType(t *testing.T) {
	if _, err := verifyCandidate("x", md5hex("y"), "bogustype", "", "prefix"); err == nil {
		t.Error("unknown type should produce a verify error (drives exit 2)")
	}
	if _, err := verifyCandidate("x", md5hex("y"), "md5", "", "prefix"); err != nil {
		t.Errorf("valid type should not error: %v", err)
	}
}
