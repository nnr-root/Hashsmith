package main

import "testing"

func TestHashcatCryptHeaderPublishedVectors(t *testing.T) {
	tests := []struct {
		mode, typ, password, target string
	}{
		{"29311", "truecrypt-ripemd160", "hashcat", cryptHeaderHashcat29311Vector},
		{"29321", "truecrypt-sha512", "hashcat", cryptHeaderHashcat29321Vector},
		{"29331", "truecrypt-whirlpool", "hashcat", cryptHeaderHashcat29331Vector},
		{"29411", "veracrypt-ripemd160", "hashcat", cryptHeaderHashcat29411Vector},
		{"29421", "veracrypt-sha512", "hashcat", cryptHeaderHashcat29421Vector},
		{"29431", "veracrypt-whirlpool", "hashcat", cryptHeaderHashcat29431Vector},
		{"29451", "veracrypt-sha256", "hashcat", cryptHeaderHashcat29451Vector},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestHashcatCryptHeaderWrongPasswords(t *testing.T) {
	for typ, target := range map[string]string{
		"truecrypt-ripemd160": "29311",
		"veracrypt-sha512":    "29421",
	} {
		vectors := map[string]string{"29311": cryptHeaderHashcat29311Vector, "29421": cryptHeaderHashcat29421Vector}
		if ok, err := verifyCandidate("definitely-wrong", vectors[target], typ, "", "prefix"); err != nil || ok {
			t.Errorf("%s wrong password: ok=%v err=%v", typ, ok, err)
		}
	}
}

func TestHashcatCryptHeaderDetection(t *testing.T) {
	for target, want := range map[string]string{
		cryptHeaderHashcat29311Vector: "truecrypt",
		cryptHeaderHashcat29421Vector: "veracrypt",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
}

func TestHashcatCryptHeaderRejectsMalformed(t *testing.T) {
	for typ, target := range map[string]string{
		"truecrypt-ripemd160": "$truecrypt$00$11",
		"veracrypt-sha512":    "$veracrypt$00$11",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s accepted malformed header", typ)
		}
	}
}
