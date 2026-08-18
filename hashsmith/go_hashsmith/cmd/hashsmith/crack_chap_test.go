package main

import "testing"

// iSCSI CHAP vector (passphrase "hashsmith"), Python-generated.
func TestChapVector(t *testing.T) {
	h := "81474a4f7a3dbf22e071a02c10e54b47:abcdef0123456789:1b"
	if ok, err := verifyChap(h, "hashsmith"); err != nil || !ok {
		t.Errorf("CHAP verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyChap(h, "wrong"); ok {
		t.Error("CHAP should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "chap" {
		t.Errorf("detectHashTypes(chap) = %v", got)
	}
}
