package main

import "testing"

// Bitwarden vector (passphrase "hashsmith", email "user@example.com"), Python-generated.
func TestBitwardenVector(t *testing.T) {
	h := "$bitwarden$2*100000*dXNlckBleGFtcGxlLmNvbQ==*1T7YrDYENfccHpf9+YnmLc1iQlw0SOoKPU7xefd1bRM="
	if ok, err := verifyBitwarden(h, "hashsmith"); err != nil || !ok {
		t.Errorf("Bitwarden verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyBitwarden(h, "wrong"); ok {
		t.Error("Bitwarden should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "bitwarden" {
		t.Errorf("detectHashTypes(bitwarden) = %v", got)
	}
}
