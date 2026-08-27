package main

import "testing"

func TestVNCPublishedVector(t *testing.T) {
	record := "$vnc$*7963F9BB7BA6A42A085763808156F570*475B10D05648E4110D77F03916106F98"
	ok, err := verifyCandidate("123", record, "john:vnc", "", "prefix")
	if err != nil || !ok {
		t.Fatalf("published VNC vector: ok=%v err=%v", ok, err)
	}
	if bad, err := verifyCandidate("wrong", record, "vnc", "", "prefix"); err != nil || bad {
		t.Fatalf("wrong VNC password: ok=%v err=%v", bad, err)
	}
	if got := detectHashTypes(record); len(got) != 1 || got[0] != "vnc" {
		t.Fatalf("detectHashTypes = %v, want [vnc]", got)
	}
}
