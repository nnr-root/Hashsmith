package main

import (
	"strings"
	"testing"
)

// TestDumpSelfTestVectorsIsTabSeparated pins the shape the John-label verifier
// in scripts/john-labels-verify.sh parses: one TSV record per vector, carrying
// the canonical type, the plaintext, the salt and the ciphertext. Targets can
// contain spaces and '$', so the separator must be a tab and the record must
// not be reordered.
func TestDumpSelfTestVectorsIsTabSeparated(t *testing.T) {
	vectors := []selfTestVector{
		{typ: "md5", password: "password", salt: "", target: "5f4dcc3b5aa765d61d8327deb882cf99"},
		{typ: "md5crypt", password: "pw", salt: "abcd", target: "$1$abcd$xyz"},
	}
	out := dumpSelfTestVectors(vectors)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), out)
	}
	first := strings.Split(lines[0], "\t")
	if len(first) != 4 {
		t.Fatalf("got %d fields, want 4: %q", len(first), lines[0])
	}
	if first[0] != "md5" || first[1] != "password" || first[2] != "" || first[3] != "5f4dcc3b5aa765d61d8327deb882cf99" {
		t.Errorf("fields out of order or wrong: %q", first)
	}
	second := strings.Split(lines[1], "\t")
	if second[2] != "abcd" || second[3] != "$1$abcd$xyz" {
		t.Errorf("salt/target not preserved: %q", second)
	}
}

// TestDumpSelfTestVectorsSkipsUndumpableRecords keeps the TSV parseable: a
// vector whose own fields contain a tab or newline would silently corrupt the
// record boundaries downstream, so it is omitted rather than emitted broken.
func TestDumpSelfTestVectorsSkipsUndumpableRecords(t *testing.T) {
	vectors := []selfTestVector{
		{typ: "ok", password: "p", target: "t"},
		{typ: "bad", password: "has\ttab", target: "t"},
		{typ: "bad2", password: "p", target: "has\nnewline"},
	}
	out := dumpSelfTestVectors(vectors)
	if strings.Contains(out, "bad") {
		t.Errorf("records with embedded separators must be skipped, got: %q", out)
	}
	if !strings.Contains(out, "ok") {
		t.Errorf("clean record was dropped: %q", out)
	}
}
