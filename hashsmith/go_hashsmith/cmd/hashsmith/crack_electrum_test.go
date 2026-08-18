package main

import "testing"

// Authoritative Electrum salt-type 1 vector (hashcat mode 16600 example),
// passphrase "hashcat".
func TestElectrumVector(t *testing.T) {
	line := "$electrum$1*44358283104603165383613672586868*c43a6632d9f59364f74c395a03d8c2ea"

	if ok, err := verifyElectrum(line, "hashcat"); err != nil || !ok {
		t.Fatalf("Electrum verify failed for the correct passphrase: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyElectrum(line, "wrongpass"); ok {
		t.Error("Electrum should reject the wrong passphrase")
	}
	if got := detectHashTypes(line); len(got) != 1 || got[0] != "electrum" {
		t.Errorf("detectHashTypes = %v, want [electrum]", got)
	}
}
