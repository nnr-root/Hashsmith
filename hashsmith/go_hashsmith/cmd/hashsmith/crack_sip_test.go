package main

import "testing"

// SIP digest (hashcat mode 11400 example), password "hashcat".
func TestSIPVector(t *testing.T) {
	h := "$sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*192.168.100.121**2b01df0b****MD5*ad0520061ca07c120d7e8ce696a6df2d"
	if ok, err := verifySIP(h, "hashcat"); err != nil || !ok {
		t.Errorf("SIP verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifySIP(h, "wrong"); ok {
		t.Error("SIP should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "sip" {
		t.Errorf("detectHashTypes(sip) = %v", got)
	}
}
