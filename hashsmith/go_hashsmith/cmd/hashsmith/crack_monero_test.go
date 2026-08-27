package main

import "testing"

func TestMoneroPublishedVector(t *testing.T) {
	ok, err := verifyCandidate("test", moneroPublishedRecord, "john:monero", "", "prefix")
	if err != nil || !ok {
		t.Fatalf("published Monero vector: ok=%v err=%v", ok, err)
	}
	if bad, err := verifyCandidate("wrong-password", moneroPublishedRecord, "monero", "", "prefix"); err != nil || bad {
		t.Fatalf("wrong Monero password: ok=%v err=%v", bad, err)
	}
	if got := detectHashTypes(moneroPublishedRecord); len(got) != 1 || got[0] != "monero" {
		t.Fatalf("detectHashTypes = %v, want [monero]", got)
	}
}
