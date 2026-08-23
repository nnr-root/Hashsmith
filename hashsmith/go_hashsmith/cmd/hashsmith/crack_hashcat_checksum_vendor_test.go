package main

import "testing"

func TestHashcatChecksumVendorVectors(t *testing.T) {
	cases := []struct {
		mode, typ, target string
	}{
		{"27800", "murmur3-seeded", "23e93f65:00000000"},
		{"27900", "crc32c-hashcat", "5e23d60f:00000000"},
		{"28000", "crc64-jones", "65c1f848fe38cce6:4260950400318054"},
		{"22200", "citrix-sha512", "2f9282ade42ce148175dc3b4d8b5916dae5211eee49886c3f7cc768f6b9f2eb982a5ac2f2672a0223999bfd15349093278adf12f6276e8b61dacf5572b3f93d0b4fa886ce"},
		{"26300", "fortigate256", "SH2lpcpFXM5QRlWYwY5vL9+5svfYyb+c79qENpxEoB3NtZpVxKwHjuq/9TH88U="},
		{"24800", "umbraco-hmac-sha1", "8uigXlGMNI7BzwLCJlDbcKR2FP4="},
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

func TestHashcatChecksumVendorDetection(t *testing.T) {
	cases := []struct {
		target, want string
	}{
		{"23e93f65:00000000", "murmur3-seeded"},
		{"5e23d60f:00000000", "crc32c-hashcat"},
		{"65c1f848fe38cce6:4260950400318054", "crc64-jones"},
		{"2f9282ade42ce148175dc3b4d8b5916dae5211eee49886c3f7cc768f6b9f2eb982a5ac2f2672a0223999bfd15349093278adf12f6276e8b61dacf5572b3f93d0b4fa886ce", "citrix-sha512"},
		{"SH2lpcpFXM5QRlWYwY5vL9+5svfYyb+c79qENpxEoB3NtZpVxKwHjuq/9TH88U=", "fortigate256"},
		{"8uigXlGMNI7BzwLCJlDbcKR2FP4=", "umbraco-hmac-sha1"},
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

func TestHashcatChecksumVendorMalformedInputs(t *testing.T) {
	for typ, target := range map[string]string{
		"murmur3-seeded":    "bad:seed",
		"crc32c-hashcat":    "bad:seed",
		"crc64-jones":       "bad:seed",
		"citrix-sha512":     "2bad",
		"fortigate256":      "SH2bad",
		"umbraco-hmac-sha1": "bad",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
