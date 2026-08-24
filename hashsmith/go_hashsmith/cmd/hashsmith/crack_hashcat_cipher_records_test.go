package main

import "testing"

func TestHashcatCipherAndStatePublishedVectors(t *testing.T) {
	tests := []struct {
		mode, password, target string
	}{
		{"14000", "hashcat1", "53b325182924b356:1412781058343178"},
		{"14100", "hashcat1hashcat1hashcat1", "4c29eea59d8db1e7:7428288455525516"},
		{"15400", "hashcat_hashcat_hashcat_hashcat_", "$chacha20$*0400000000000003*16*0200000000000001*5152535455565758*6b05fe554b0bc3b3"},
		{"16000", "hashcat", "pfaRCwDe0U"},
		{"16501", "hashcat", "mojolicious=abc--85d455b37bc3d8672908fde9e802cc3294d7db7ad0d63768305d105a948fb823"},
		{"18800", "hashcat", "YnM6WYERjJfhxwepT7zV6odWoEUz1X4esYQb4bQ3KZ7bbZAyOTc1MDM3OTc1NjMyODA0ECcAAD3vFoc="},
		{"31500", "b4b9b02e6f09a9bd760f388b67351e2b", "c896b3c6963e03c86ade3a38370bbb09:54161084332"},
		{"31600", "b4b9b02e6f09a9bd760f388b67351e2b", "$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626"},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got == tc.mode {
				t.Fatalf("Hashcat mode %s is not routed", tc.mode)
			}
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate(wrongPassword(tc.password), tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatCipherAndStateRejectMalformedRecords(t *testing.T) {
	tests := map[string]string{
		"14000": "abcd:1234",
		"14100": "abcd:1234",
		"15400": "$chacha20$*bad",
		"16000": "not-a-tripcode",
		"16501": "mojolicious=abc--bad",
		"18800": "not-base64",
		"31500": "abcd:user",
		"31600": "$DCC2$bad#user#abcd",
	}
	for mode, target := range tests {
		if _, err := verifyCandidate("hashcat", target, mode, "", "prefix"); err == nil {
			t.Errorf("mode %s accepted malformed record %q", mode, target)
		}
	}
}

func TestHashcatCipherAndStateAutoDetection(t *testing.T) {
	tests := map[string]string{
		"$chacha20$*0400000000000003*16*0200000000000001*5152535455565758*6b05fe554b0bc3b3": "chacha20",
		"mojolicious=abc--85d455b37bc3d8672908fde9e802cc3294d7db7ad0d63768305d105a948fb823": "mojolicious",
		"YnM6WYERjJfhxwepT7zV6odWoEUz1X4esYQb4bQ3KZ7bbZAyOTc1MDM3OTc1NjMyODA0ECcAAD3vFoc=":  "blockchain-second",
	}
	for target, want := range tests {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detectHashTypes(%q) = %v, want [%s]", target, got, want)
		}
	}
}
