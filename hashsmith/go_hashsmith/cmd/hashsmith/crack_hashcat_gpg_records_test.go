package main

import "testing"

func TestHashcatGPGSecretKeyPublishedVectors(t *testing.T) {
	tests := []struct {
		mode, password, target string
	}{
		{"17010", "hashcat", gpgHashcat17010Vector},
		{"17020", "hashcat", gpgHashcat17020Vector},
		{"17030", "8CdhZ2J8umrHg0tMjB0NDRDpKKFeL7i", gpgHashcat17030Vector},
		{"17040", "Hashcat1!", gpgHashcat17040Vector},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != "gpg" {
				t.Fatalf("mode alias = %q, want gpg", got)
			}
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("definitely-wrong", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestGPGSecretKeyJohnCompatibility(t *testing.T) {
	if got := canonicalHashType("john:gpg"); got != "gpg" {
		t.Fatalf("john:gpg = %q, want gpg", got)
	}
	ok, err := verifyCandidate("hashcat", gpgHashcat17010Vector, "john:gpg", "", "prefix")
	if err != nil || !ok {
		t.Fatalf("John gpg record: ok=%v err=%v", ok, err)
	}
	got := detectHashTypes(gpgHashcat17010Vector)
	if len(got) != 1 || got[0] != "gpg" {
		t.Fatalf("detection = %v, want [gpg]", got)
	}
}

func TestGPGSecretKeyRejectsMalformedRecords(t *testing.T) {
	bad := []string{
		"$gpg$*1*128*1024*00*3*254*2*7*16*00000000000000000000000000000000*65536*0000000000000000",
		"$gpg$*1*128*1024*zz*3*254*2*7*16*00000000000000000000000000000000*65536*0000000000000000",
		"$gpg$*1*128*1024*00*3*254*2*7*16*00*65536*0000000000000000",
	}
	for _, target := range bad {
		if _, err := verifyCandidate("hashcat", target, "gpg", "", "prefix"); err == nil {
			t.Errorf("accepted malformed GPG record")
		}
	}
}
