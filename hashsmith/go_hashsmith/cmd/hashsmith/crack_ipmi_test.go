package main

import "testing"

func TestIPMIHalfMD5Vectors(t *testing.T) {
	// IPMI2 RAKP (hashcat example), password "hashcat".
	ipmi := "b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174:472bdabe2d5d4bffd6add7b3ba79a291d104a9ef"
	if ok, err := verifyIPMI(ipmi, "hashcat"); err != nil || !ok {
		t.Errorf("IPMI verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyIPMI(ipmi, "wrong"); ok {
		t.Error("IPMI should reject the wrong passphrase")
	}
	if got := detectHashTypes(ipmi); len(got) != 1 || got[0] != "ipmi" {
		t.Errorf("detectHashTypes(ipmi) = %v", got)
	}

	// Half-MD5 (passphrase "hashsmith"): first 16 hex of md5.
	hm := "ed1a4cb602d45090"
	if ok, err := verifyHalfMD5(hm, "hashsmith"); err != nil || !ok {
		t.Errorf("Half-MD5 verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyHalfMD5(hm, "wrong"); ok {
		t.Error("Half-MD5 should reject the wrong passphrase")
	}
}
