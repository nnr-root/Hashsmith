package main

import "testing"

func TestGRUB2Vector(t *testing.T) {
	const vector = "grub.pbkdf2.sha512.1000.73616C74792D67727562.CD16B324E198DBDC0B8332A77D72A034D68EDE011F6DBF59DDB80F15E1C1C39342F25AC32DB910201112C836D9FAA0D5C141C21C39CB9BD010B848E445385213"
	if ok, err := verifyGRUB2(vector, "hashsmith"); err != nil || !ok {
		t.Fatalf("GRUB2 vector failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyGRUB2(vector, "wrong"); ok {
		t.Error("GRUB2 accepted the wrong password")
	}
	if got := detectHashTypes(vector); len(got) != 1 || got[0] != "grub2" {
		t.Errorf("detectHashTypes(GRUB2) = %v", got)
	}
	if !isGRUB2("$" + vector) {
		t.Error("GRUB2 parser should accept the optional leading $")
	}
}
