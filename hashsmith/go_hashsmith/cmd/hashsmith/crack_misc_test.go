package main

import "testing"

// Network-device / service vectors. Citrix/PIX/ASA/CRAM-MD5 use the hashcat
// examples (password "hashcat"); SCRAM is Python-generated ("hashsmith").
func TestMiscVectors(t *testing.T) {
	// Citrix NetScaler.
	cx := "1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea"
	if ok, err := verifyCitrix(cx, "hashcat"); err != nil || !ok {
		t.Errorf("Citrix verify failed: ok=%v err=%v", ok, err)
	}
	if got := detectHashTypes(cx); len(got) != 1 || got[0] != "citrix" {
		t.Errorf("detectHashTypes(citrix) = %v", got)
	}

	// Cisco-PIX and Cisco-ASA.
	if ok, err := verifyCiscoPIX("dRRVnUmUHXOTt9nk", "hashcat"); err != nil || !ok {
		t.Errorf("Cisco-PIX verify failed: ok=%v err=%v", ok, err)
	}
	if ok, err := verifyCiscoASA("02dMBMYkTdC5Ziyp:36", "hashcat"); err != nil || !ok {
		t.Errorf("Cisco-ASA verify failed: ok=%v err=%v", ok, err)
	}
	if got := detectHashTypes("02dMBMYkTdC5Ziyp:36"); len(got) != 1 || got[0] != "cisco-asa" {
		t.Errorf("detectHashTypes(cisco-asa) = %v", got)
	}

	// CRAM-MD5 (Python-generated: challenge "<1234.5678@server>", user "smith").
	cram := "$cram_md5$PDEyMzQuNTY3OEBzZXJ2ZXI+$c21pdGggNGVkNDY0NGI2ZmY0OWViYmU1OGE5MjY2MWQzMmE4MTg="
	if ok, err := verifyCRAMMD5(cram, "hashsmith"); err != nil || !ok {
		t.Errorf("CRAM-MD5 verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyCRAMMD5(cram, "wrong"); ok {
		t.Error("CRAM-MD5 should reject the wrong passphrase")
	}

	// PostgreSQL SCRAM-SHA-256.
	scram := "SCRAM-SHA-256$4096:ABEiM0RVZnc=$tXvV/5d2dbq937pl1Urt3L2m8LXy7/llbOPTaIXXgsI=:s5u1rzVInmgZSrQkhL722KLzdU3PzDktG2BMsuT009c="
	if ok, err := verifySCRAM(scram, "hashsmith"); err != nil || !ok {
		t.Errorf("SCRAM verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifySCRAM(scram, "wrong"); ok {
		t.Error("SCRAM should reject the wrong passphrase")
	}
	if got := detectHashTypes(scram); len(got) != 1 || got[0] != "scram" {
		t.Errorf("detectHashTypes(scram) = %v", got)
	}
}
