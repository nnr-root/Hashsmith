package main

import "testing"

// hashcatCryptHeaderPublishedCases is shared by the fast alias assertion
// below and by TestHashcatCryptHeaderPublishedVectors in
// crack_hashcat_crypt_headers_slow_test.go (slowtest tag), so the vector
// table exists exactly once for both halves of the split.
var hashcatCryptHeaderPublishedCases = []struct {
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

// The fast half of the TestHashcatCryptHeaderPublishedVectors split: the
// mode-to-type alias resolution. See crack_hashcat_crypt_headers_slow_test.go
// (slowtest tag) for the slow verifyCandidate half.
func TestHashcatCryptHeaderAliases(t *testing.T) {
	for _, tc := range hashcatCryptHeaderPublishedCases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
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
