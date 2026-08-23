package main

import (
	"encoding/hex"
	"testing"
)

const krb5paMD5HashcatVector = "$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835"

func TestSkip32Primitive(t *testing.T) {
	plaintext, _ := hex.DecodeString("44630464")
	got := skip32Encrypt([]byte("hashcat!!!"), plaintext)
	if hex.EncodeToString(got[:]) != "c9350366" {
		t.Fatalf("Skip32 = %x, want c9350366", got)
	}
}

func TestHashcatLegacyCipherVectors(t *testing.T) {
	cases := []struct {
		mode, typ, password, wrong, target string
	}{
		{"3100", "oracle-h", "hashcat", "wrong", "792FCB0AE31D8489:7284616727"},
		{"7350", "ipmi-md5", "admin", "wrong", "08b017f3628b9835c748521e412429c9:f3450000df540000cdd981b0b3441be8774a61e69321291891a29a0c5fdac3f06194bd2c29fa5246000000000000000000000000000000001400"},
		{"7500", "krb5pa", "hashcat", "wrong", krb5paMD5HashcatVector},
		{"8300", "dnssec-nsec3", "hashcat", "wrong", "pi6a89u8tca930h8mvolklmesefc5gmn:.fnmlbsik.net:35537886:1"},
		{"14900", "skip32", "hashcat!!!", "wrong!!!!!", "c9350366:44630464"},
		{"26401", "aes128-ecb-nokdf", "hashcat", "wrong", "e7a32f3210455cc044f26117c4612aab:86046627772965328523223752173724"},
		{"26402", "aes192-ecb-nokdf", "hashcat", "wrong", "2995e91b798ef51232a91579edb1d176:49869364034411376791729962721320"},
		{"26403", "aes256-ecb-nokdf", "hashcat", "wrong", "264a4248c9522cb74d33fe26cb596895:61270210011294880287232432636227"},
		{"24", "md5-salt-pass", "hashcat", "wrong", "e983672a03adcc9767b24584338eb378:00"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			if ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix"); err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate(tc.wrong, tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestLegacyCipherJohnFormats(t *testing.T) {
	cases := []struct {
		typ, password, target string
	}{
		{"john:oracle", "THALES", "O$SYSTEM#9EEDFA0AD26C6D52"},
		{"john:nsec3", "ns1", "$NSEC3$0$$879ffda85c7cb08df1f93fb040b90a6869b205f1$example.com."},
		{"john:krb5pa-md5", "John", "$krb5pa$23$user$realm$salt$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7daeb03b6fbcfe91f8346f3c0ae7e8abfe5"},
	}
	for _, tc := range cases {
		if ok, err := verifyCandidate(tc.password, tc.target, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v", tc.typ, ok, err)
		}
	}
}

func TestLegacyCipherDetection(t *testing.T) {
	cases := []struct{ target, want string }{
		{"792FCB0AE31D8489:7284616727", "oracle-h"},
		{"O$SYSTEM#9EEDFA0AD26C6D52", "oracle-h"},
		{"08b017f3628b9835c748521e412429c9:f3450000df540000cdd981b0b3441be8774a61e69321291891a29a0c5fdac3f06194bd2c29fa5246000000000000000000000000000000001400", "ipmi-md5"},
		{"pi6a89u8tca930h8mvolklmesefc5gmn:.fnmlbsik.net:35537886:1", "dnssec-nsec3"},
		{"$NSEC3$0$$879ffda85c7cb08df1f93fb040b90a6869b205f1$example.com.", "dnssec-nsec3"},
		{"c9350366:44630464", "skip32"},
		{"e7a32f3210455cc044f26117c4612aab:86046627772965328523223752173724", "aes128-ecb-nokdf"},
	}
	for _, tc := range cases {
		got := detectHashTypes(tc.target)
		found := false
		for _, candidate := range got {
			if candidate == tc.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("detection = %v, missing %s", got, tc.want)
		}
	}
}

func TestLegacyCipherMalformedInputs(t *testing.T) {
	for typ, target := range map[string]string{
		"oracle-h":         "bad:user",
		"ipmi-md5":         "bad:packet",
		"dnssec-nsec3":     "bad:domain:salt:rounds",
		"skip32":           "bad:plain",
		"aes128-ecb-nokdf": "bad:plain",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
