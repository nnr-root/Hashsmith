package main

import "testing"

// iTunes backup (hashcat mode 14700 example, iOS < 10.2), password "hashcat".
func TestITunesBackupVector(t *testing.T) {
	h := "$itunes_backup$*9*b8e3f3a970239b22ac199b622293fe4237b9d16e74bad2c3c3568cd1bd3c471615a6c4f867265642*10000*4542263740587424862267232255853830404566**"
	if ok, err := verifyITunesBackup(h, "hashcat"); err != nil || !ok {
		t.Errorf("iTunes backup verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyITunesBackup(h, "wrong"); ok {
		t.Error("iTunes backup should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "itunes" {
		t.Errorf("detectHashTypes(itunes) = %v", got)
	}
}
