package main

import (
	"encoding/hex"
	"testing"
)

// WPA vectors built on the authoritative 802.11i PBKDF2 test vector
// (passphrase "password", ESSID "IEEE"), cross-checked with Python.
func TestWPAVectors(t *testing.T) {
	// PBKDF2 PMK anchor.
	pmk := hex.EncodeToString(wpaPMK("password", []byte("IEEE")))
	const knownPMK = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
	if pmk != knownPMK {
		t.Fatalf("PMK vector mismatch:\n  got  %s\n  want %s", pmk, knownPMK)
	}

	// PMKID: AP=001122334455, STA=8899aabbccdd, ESSID="IEEE" (hex 49454545).
	pmkidLine := "WPA*01*6d3c40446a165cfeb121c82f18bf97d8*001122334455*8899aabbccdd*49454545"
	if ok, err := verifyWPA(pmkidLine, "password"); err != nil || !ok {
		t.Errorf("PMKID verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyWPA(pmkidLine, "wrongpass"); ok {
		t.Error("PMKID should not verify with the wrong passphrase")
	}
	// Legacy 16800 form of the same PMKID.
	legacy := "6d3c40446a165cfeb121c82f18bf97d8*001122334455*8899aabbccdd*49454545"
	if !isLegacyPMKID(legacy) {
		t.Error("legacy PMKID not recognised")
	}
	if ok, err := verifyWPA(legacy, "password"); err != nil || !ok {
		t.Errorf("legacy PMKID verify failed: ok=%v err=%v", ok, err)
	}

	// EAPOL (key-descriptor v2, HMAC-SHA1): ANONCE=aa*32, SNONCE=bb*32 (embedded).
	eapol := "02030075fe008a00000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	eapolLine := "WPA*02*31a3e55864c82260c49cffd6a890e99e*001122334455*8899aabbccdd*49454545*" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*" + eapol + "*02"
	if ok, err := verifyWPA(eapolLine, "password"); err != nil || !ok {
		t.Errorf("EAPOL verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyWPA(eapolLine, "nope"); ok {
		t.Error("EAPOL should not verify with the wrong passphrase")
	}

	// Detection routes both to the wpa cracker.
	for _, line := range []string{pmkidLine, eapolLine, legacy} {
		got := detectHashTypes(line)
		if len(got) != 1 || got[0] != "wpa" {
			t.Errorf("detectHashTypes(%.20s…) = %v, want [wpa]", line, got)
		}
	}
}

// TestAESCMAC checks the RFC 4493 AES-CMAC vectors used by EAPOL key-version 3.
func TestAESCMAC(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	cases := []struct{ msg, want string }{
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
	}
	for _, c := range cases {
		msg, _ := hex.DecodeString(c.msg)
		got, err := aesCMAC(key, msg)
		if err != nil {
			t.Fatalf("aesCMAC: %v", err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("AES-CMAC(%s):\n  got  %s\n  want %s", c.msg, hex.EncodeToString(got), c.want)
		}
	}
}
