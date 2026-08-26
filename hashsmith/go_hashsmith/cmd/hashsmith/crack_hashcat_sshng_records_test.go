package main

import "testing"

func TestHashcatSSHNGPublishedVectors(t *testing.T) {
	tests := []struct {
		mode, password, target string
	}{
		{"22911", "hashcat", sshHashcat22911Vector},
		{"22921", "hashcat", sshHashcat22921Vector},
		{"22931", "hashcat", sshHashcat22931Vector},
		{"22941", "hashcat", sshHashcat22941Vector},
		{"22951", "hashcat", sshHashcat22951Vector},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != "ssh" {
				t.Fatalf("mode alias = %q, want ssh", got)
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

func TestSSHNGJohnCompatibilityAndDetection(t *testing.T) {
	if got := canonicalHashType("john:ssh"); got != "ssh" {
		t.Fatalf("john:ssh = %q, want ssh", got)
	}
	ok, err := verifyCandidate("hashcat", sshHashcat22911Vector, "john:ssh", "", "prefix")
	if err != nil || !ok {
		t.Fatalf("John ssh record: ok=%v err=%v", ok, err)
	}
	got := detectHashTypes(sshHashcat22911Vector)
	if len(got) != 1 || got[0] != "ssh" {
		t.Fatalf("detection = %v, want [ssh]", got)
	}
}

func TestSSHNGRejectsMalformedRecords(t *testing.T) {
	bad := []string{
		"$sshng$7$8$0000000000000000$32$0000000000000000000000000000000000000000000000000000000000000000",
		"$sshng$0$8$00$32$0000000000000000000000000000000000000000000000000000000000000000",
		"$sshng$0$8$0000000000000000$31$0000000000000000000000000000000000000000000000000000000000000000",
	}
	for _, target := range bad {
		if _, err := verifyCandidate("hashcat", target, "ssh", "", "prefix"); err == nil {
			t.Errorf("accepted malformed sshng record")
		}
	}
}
