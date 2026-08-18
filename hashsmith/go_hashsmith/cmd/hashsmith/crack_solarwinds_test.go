package main

import "testing"

// SolarWinds Orion vector (salt "admin", passphrase "hashsmith"), Python-generated.
func TestSolarWindsVector(t *testing.T) {
	h := "$solarwinds$0$admin$gWiHE/NPgE/YtGzyLmH3kpG51robFZFQ4re8mH6veZYq4AaYoebzopWtF3aEvsig5dQc7Q6IUMfZEdPF+Hu9Ng=="
	if ok, err := verifySolarWinds(h, "hashsmith"); err != nil || !ok {
		t.Errorf("SolarWinds verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifySolarWinds(h, "wrong"); ok {
		t.Error("SolarWinds should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "solarwinds" {
		t.Errorf("detectHashTypes(solarwinds) = %v", got)
	}
}
