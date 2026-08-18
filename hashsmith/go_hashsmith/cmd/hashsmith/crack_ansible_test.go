package main

import "testing"

// Ansible Vault vector (passphrase "hashsmith"), Python-generated.
func TestAnsibleVector(t *testing.T) {
	h := "$ansible$0*0*00112233445566778899aabbccddeeff*f7c3cc30dd11c057fc913c1a39c062fbda11319016b329897480ea4be6fc03ab*aabbccddeeff00112233445566778899"
	if ok, err := verifyAnsible(h, "hashsmith"); err != nil || !ok {
		t.Errorf("Ansible verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyAnsible(h, "wrong"); ok {
		t.Error("Ansible should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "ansible" {
		t.Errorf("detectHashTypes(ansible) = %v", got)
	}
}
