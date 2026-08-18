package main

import "testing"

// SAP CODVN B / BCODE (hashcat mode 7700 example), password "hashcat", user "USER".
func TestSAPCodvnB(t *testing.T) {
	h := "USER$C8B48F26B87B7EA7"
	if ok, err := verifySAPCodvnB(h, "hashcat"); err != nil || !ok {
		t.Errorf("SAP CODVN B verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifySAPCodvnB(h, "wrong"); ok {
		t.Error("SAP CODVN B should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "sap-b" {
		t.Errorf("detectHashTypes(sap-b) = %v", got)
	}
}
