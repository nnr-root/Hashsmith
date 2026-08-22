package main

import "testing"

// Published Hashcat self-test/example records. The password is "hashcat".
func TestHashcatWrappedBcryptVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"25600", "$2a$05$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12yDN7/6I8ZV0q/1lEohLru"},
		{"25800", "$2a$05$Uo385Fa0g86uUXHwZxB90.qMMdRFExaXePGka4WGFv.86I45AEjmO"},
		{"30600", "$2b$10$FxDtpTNaL303lLcWtd6LFO2U6Gc63VJ07qycHcfqbQQ71GhO/qSzu"},
	}
	for _, tc := range cases {
		ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); bad {
			t.Errorf("mode %s accepted a wrong password", tc.mode)
		}
	}
}

func TestHashcatShiro1Vector(t *testing.T) {
	const target = "$shiro1$SHA-512$1024$WobJGSjbUhsMdaILomMOdw==$9uptGJ24vzZCqZI55F77N7xjUxGlVrK5aCmAwIrV1vwDmFM4akE6Hmd23Aj8ANLSUdIEkHLZ6SnoitZbOsoQNQ=="
	if ok, err := verifyCandidate("hashcat", target, "12150", "", "prefix"); err != nil || !ok {
		t.Fatalf("mode 12150: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyCandidate("wrong", target, "shiro1-sha512", "", "prefix"); bad {
		t.Fatal("Shiro 1 accepted a wrong password")
	}
	if got := detectHashTypes(target); len(got) != 1 || got[0] != "shiro1-sha512" {
		t.Fatalf("Shiro 1 detection = %v", got)
	}
	if _, err := verifyCandidate("x", "$shiro1$SHA-512$100000001$c2FsdA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", "12150", "", "prefix"); err == nil {
		t.Fatal("Shiro 1 accepted an excessive iteration count")
	}
}

func TestHashcatExistingParserBridgeVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"124", "sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013"},
		{"5700", "2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI"},
		{"6400", "{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2"},
		{"6500", "{ssha512}06$bJbkFGJAB30L2e23$bXiXjyH5YGIyoWWmEVwq67nCU5t7GLy9HkCzrodRCQCx3r9VvG98o7O3V0r9cVrX3LPPGuHqT5LLn0oGCuI1.."},
		{"32060", "$pbkdf2-sha256$100000$MDUzMTE4NjQyNDc5NTQxMjAwMjg1OTYxNjAxNDgzNzc$bwYpAyQ2g5PqdnMj8mJ46mkwQbyztw8gEQqnhDHj48c"},
	}
	for _, tc := range cases {
		ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
	}

	// These records are generated independently elsewhere in the suite; this
	// assertion pins their Hashcat mode-number routing as well.
	for mode, canonical := range map[string]string{"7100": "macos", "7200": "grub2"} {
		if got := canonicalHashType(mode); got != canonical {
			t.Errorf("mode %s = %q, want %q", mode, got, canonical)
		}
	}
}
