package main

import "testing"

// Apache apr1 vector (openssl passwd -apr1), passphrase "hashsmith".
func TestAPR1Vector(t *testing.T) {
	h := "$apr1$abcdefgh$U1gIt51iVe84gztna6VnP0"
	if ok, err := verifyAPR1(h, "hashsmith"); err != nil || !ok {
		t.Errorf("apr1 verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyAPR1(h, "wrong"); ok {
		t.Error("apr1 should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "apr1" {
		t.Errorf("detectHashTypes(apr1) = %v", got)
	}
}
