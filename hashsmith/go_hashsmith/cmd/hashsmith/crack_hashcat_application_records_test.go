package main

import "testing"

const saltedUsernameSHA1Vector = "339b5eaa53f28516008e9ca710857d3a4785b6fc:8ca064ff42fcab5a8f0692544b8dd3d3054bd73fe9afaa08c6b6b310538cc9a7:757365726e616d65"

func TestHashcatApplicationRecordVectors(t *testing.T) {
	cases := []struct {
		mode, typ, target string
	}{
		{"24900", "dahua-auth-md5", "GRuHbyVp"},
		{"24901", "besder-auth-md5", "GRmHbqVh"},
		{"22800", "md5-salt-pass-md5pass", "86d173f13213d1e48bce9647bdc306d5:8e86a279d6e182b3c811c559e6b15484"},
		{"20712", "netwitness-sha256", "6F48F44C46F5ADC534597687B086278F0AAF7D262ADDB3978562A7D55BBDF467:MDAwMzY1NzYwODI4MQ=="},
		{"29000", "sha1-salt-user-password", saltedUsernameSHA1Vector},
		{"29200", "radmin3", radmin3PublishedVector},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			if ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix"); err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong-password", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatApplicationRecordDetection(t *testing.T) {
	cases := []struct {
		target, want string
	}{
		{"GRuHbyVp", "dahua-auth-md5"},
		{"GRmHbqVh", "besder-auth-md5"},
		{"86d173f13213d1e48bce9647bdc306d5:8e86a279d6e182b3c811c559e6b15484", "md5-salt-pass-md5pass"},
		{"6F48F44C46F5ADC534597687B086278F0AAF7D262ADDB3978562A7D55BBDF467:MDAwMzY1NzYwODI4MQ==", "netwitness-sha256"},
		{saltedUsernameSHA1Vector, "sha1-salt-user-password"},
		{radmin3PublishedVector, "radmin3"},
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

func TestHashcatApplicationRecordMalformedInputs(t *testing.T) {
	for typ, target := range map[string]string{
		"dahua-auth-md5":          "too-short",
		"besder-auth-md5":         "########",
		"md5-salt-pass-md5pass":   "bad",
		"netwitness-sha256":       "bad:not-base64!",
		"sha1-salt-user-password": "bad:salt:user",
		"radmin3":                 "$radmin3$bad",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
