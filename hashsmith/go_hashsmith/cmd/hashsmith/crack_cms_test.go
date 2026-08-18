package main

import "testing"

// MediaWiki / vBulletin / Redmine vectors (passphrase "hashsmith"), Python-generated.
func TestCMSVectors(t *testing.T) {
	mw := "$B$a1b2c3d4$c98b583edcb1cdccf2a4b855442a6cc6"
	if ok, err := verifyMediaWiki(mw, "hashsmith"); err != nil || !ok {
		t.Errorf("MediaWiki verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyMediaWiki(mw, "wrong"); ok {
		t.Error("MediaWiki should reject the wrong passphrase")
	}
	if got := detectHashTypes(mw); len(got) != 1 || got[0] != "mediawiki" {
		t.Errorf("detectHashTypes(mediawiki) = %v", got)
	}

	vb := "209a1ebf02b22c103e1b3896b895ecd2:Zx9"
	if ok, err := verifyVBulletin(vb, "hashsmith"); err != nil || !ok {
		t.Errorf("vBulletin verify failed: ok=%v err=%v", ok, err)
	}
	if got := detectHashTypes(vb); len(got) == 0 || got[0] != "vbulletin" {
		t.Errorf("detectHashTypes(vbulletin) = %v, want vbulletin first", got)
	}

	rm := "e68c45f4f20e4e1958daa2c1a7ff80ea39f1dd97:3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5d"
	if ok, err := verifyRedmine(rm, "hashsmith"); err != nil || !ok {
		t.Errorf("Redmine verify failed: ok=%v err=%v", ok, err)
	}
	if got := detectHashTypes(rm); len(got) != 1 || got[0] != "redmine" {
		t.Errorf("detectHashTypes(redmine) = %v", got)
	}
}
