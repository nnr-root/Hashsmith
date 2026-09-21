package main

import "testing"

// TestLUKS2HashcatVector pins mode 34100 against hashcat's published record.
// The record is ~500 KB, so it is read from the example table rather than
// inlined; the Argon2 call costs about a second and a gibibyte, which is the
// format's real price and the reason for the worker cap below.
func TestLUKS2HashcatVector(t *testing.T) {
	if testing.Short() {
		t.Skip("LUKS2 needs 1 GiB and ~1s per candidate")
	}
	rec := hashcatExampleFor(t, "34100")
	ok, err := verifyLUKS2(rec, "hashcat")
	if err != nil || !ok {
		t.Fatalf("LUKS2 verify failed for the correct passphrase: ok=%v err=%v", ok, err)
	}
	bad, err := verifyLUKS2(rec, "hashcat1")
	if err != nil || bad {
		t.Fatalf("LUKS2 accepted a wrong passphrase: ok=%v err=%v", bad, err)
	}
}

// TestLUKS2MemoryCap checks that the default worker count is reduced to fit
// the memory the header asks for, and that the record alone is enough to know
// that — an operator who does not pass -t still gets the cap.
func TestLUKS2MemoryCap(t *testing.T) {
	rec := hashcatExampleFor(t, "34100")
	per := candidateMemoryBytes("", rec)
	if per != 1<<30 {
		t.Fatalf("expected the header's 1 GiB to be reported, got %d", per)
	}
	// Asking for far more workers than could fit must be reduced.
	got, note := workerCapForMemory(4096, "luks2", rec)
	if got >= 4096 || note == "" {
		t.Fatalf("expected a cap well below 4096, got %d note=%q", got, note)
	}
	// A format with no declared memory cost must not be capped.
	if n, note := workerCapForMemory(8, "md5", "d41d8cd98f00b204e9800998ecf8427e"); n != 8 || note != "" {
		t.Fatalf("cheap format was capped: %d %q", n, note)
	}
}
