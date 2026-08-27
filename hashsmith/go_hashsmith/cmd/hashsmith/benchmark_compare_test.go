package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComparisonCases(t *testing.T) {
	want := map[string][2]string{
		"md5": {"raw-md5", "0"}, "md4": {"raw-md4", "900"}, "ntlm": {"nt", "1000"},
		"sha1": {"raw-sha1", "100"}, "sha256": {"raw-sha256", "1400"},
	}
	for _, c := range comparisonCases {
		if got, ok := want[c.typ]; !ok || got != [2]string{c.johnFormat, c.hashcatMode} {
			t.Errorf("unexpected comparison mapping: %#v", c)
		}
	}
	if _, err := selectComparisonCases("hashcat:0"); err != nil {
		t.Fatalf("Hashcat alias should select MD5: %v", err)
	}
	if _, err := selectComparisonCases("bcrypt"); err == nil {
		t.Fatal("unsupported comparison type was accepted")
	}
}

func TestComparisonWordlistAndMedian(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := writeComparisonWordlist(path, 4); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 4 || lines[3] != comparisonPassword || lines[0] != "hsb000000000" {
		t.Fatalf("unexpected comparison wordlist: %q", lines)
	}
	if got := medianSeconds([]float64{9, 1, 3}); got != 3 {
		t.Fatalf("odd median = %v", got)
	}
	if got := medianSeconds([]float64{4, 2}); got != 3 {
		t.Fatalf("even median = %v", got)
	}
}

func TestComparisonProof(t *testing.T) {
	if !comparisonProof("hashsmith", comparisonPassword, "Found: "+comparisonPassword+"\n") {
		t.Fatal("Hashsmith proof was not recognized")
	}
	proof := filepath.Join(t.TempDir(), "result.txt")
	if err := os.WriteFile(proof, []byte("hash:"+comparisonPassword+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !comparisonProof("john", proof, "") || !comparisonProof("hashcat", proof, "") {
		t.Fatal("file proof was not recognized")
	}
}

func TestComparisonCommandEnablesHashsmithGPUOnly(t *testing.T) {
	c := comparisonCases[0]
	hashsmithArgs, _ := comparisonCommand("hashsmith", c, "target", "target.txt", "words.txt", t.TempDir(), 0, true)
	if !containsString(hashsmithArgs, "--gpu") {
		t.Fatalf("Hashsmith args do not enable GPU: %q", hashsmithArgs)
	}
	johnArgs, _ := comparisonCommand("john", c, "target", "target.txt", "words.txt", t.TempDir(), 0, true)
	if containsString(johnArgs, "--gpu") {
		t.Fatalf("Hashsmith GPU flag leaked into John args: %q", johnArgs)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestComparisonMissingToolsAreSkipped(t *testing.T) {
	jsonPath := filepath.Join(t.TempDir(), "report.json")
	err := runComparisonBenchmark(comparisonConfig{
		typ: "md5", candidates: 2, repeats: 1, jsonPath: jsonPath,
		hashsmithPath: "hashsmith-does-not-exist", johnPath: "john-does-not-exist", hashcatPath: "hashcat-does-not-exist",
		timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var report comparisonReport
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != 1 || report.Cases[0].Tools["hashsmith"].Status != "skipped" || report.Candidates != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
}
