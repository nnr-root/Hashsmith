package main

import "testing"

// SAP CODVN F/G (hashcat mode 7800 example), password "hashcat", user "USER".
func TestSAPCodvnFG(t *testing.T) {
	h := "USER$ABCAD719B17E7F794DF7E686E563E9E2D24DE1D0"
	if ok, err := verifySAPCodvnFG(h, "hashcat"); err != nil || !ok {
		t.Errorf("SAP CODVN F/G verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifySAPCodvnFG(h, "wrong"); ok {
		t.Error("SAP CODVN F/G should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "sap-fg" {
		t.Errorf("detectHashTypes(sap-fg) = %v", got)
	}
}
