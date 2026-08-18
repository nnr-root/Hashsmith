package main

import "testing"

// Oracle 11g/12c vector (passphrase "hashsmith"), Python-generated.
func TestOracle11gVector(t *testing.T) {
	h := "f49ad07d1f71398cf0e475ffa0d1b56575e407fd0011223344556677889a"
	if ok, err := verifyOracle11g(h, "hashsmith"); err != nil || !ok {
		t.Errorf("Oracle 11g verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyOracle11g(h, "wrong"); ok {
		t.Error("Oracle 11g should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "oracle11g" {
		t.Errorf("detectHashTypes(oracle11g) = %v", got)
	}
}
