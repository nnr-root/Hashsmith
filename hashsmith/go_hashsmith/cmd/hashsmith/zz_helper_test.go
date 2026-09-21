package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// hashcatExampleFor returns the published example record for a Hashcat mode.
func hashcatExampleFor(t *testing.T, mode string) string {
	t.Helper()
	f, err := os.Open("testdata/hashcat_example_hashes.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<22), 1<<22)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) == 4 && p[0] == mode {
			return p[3]
		}
	}
	t.Fatalf("no example record for mode %s", mode)
	return ""
}
