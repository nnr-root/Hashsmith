package main

import "testing"

func TestAxCryptSHA1(t *testing.T) {
	h := "$axcrypt_sha1$b89eaac7e61417341b710b727768294d0e6a277b"
	if ok, err := verifyAxCryptSHA1(h, "hashcat"); err != nil || !ok {
		t.Errorf("axcrypt-sha1 failed ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyAxCryptSHA1(h, "wrong"); ok {
		t.Error("should reject")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "axcrypt-sha1" {
		t.Errorf("detect=%v", got)
	}
}
