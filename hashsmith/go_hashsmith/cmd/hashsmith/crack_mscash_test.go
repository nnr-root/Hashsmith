package main

import "testing"

// Domain Cached Credentials vectors (hashcat modes 1100/2100), passphrase "hashcat".
func TestMSCashVectors(t *testing.T) {
	// DCC (mscash): username "3060147285011".
	dcc := "4dd8965d1d476fa0d026722989a6b772:3060147285011"
	if ok, err := verifyDCC(dcc, "hashcat"); err != nil || !ok {
		t.Errorf("DCC verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyDCC(dcc, "wrong"); ok {
		t.Error("DCC should reject the wrong passphrase")
	}
	if got := detectHashTypes(dcc); len(got) != 2 || got[0] != "vbulletin" || got[1] != "dcc" {
		t.Errorf("detectHashTypes(dcc) = %v, want [vbulletin dcc]", got)
	}

	// DCC2 (mscash2): username "tom", 10240 iterations.
	dcc2 := "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f"
	if ok, err := verifyDCC2(dcc2, "hashcat"); err != nil || !ok {
		t.Errorf("DCC2 verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyDCC2(dcc2, "wrong"); ok {
		t.Error("DCC2 should reject the wrong passphrase")
	}
	if got := detectHashTypes(dcc2); len(got) != 1 || got[0] != "dcc2" {
		t.Errorf("detectHashTypes(dcc2) = %v, want [dcc2]", got)
	}
}
