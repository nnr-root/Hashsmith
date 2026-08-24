package main

import "testing"

func TestHashcatLegacyAuthenticationPublishedVectors(t *testing.T) {
	tests := []struct {
		mode, candidate, target string
	}{
		{"2500", "hashcat!", hccapxHashcatSelfTest},
		{"2501", "7f620a599c445155935a35634638fa67b4aafecb92e0bd8625388757a63c2dda", hccapxHashcatSelfTest},
		{"22001", "88f43854ae7b1624fc2ab7724859e795130f4843c7535729e819cf92f39535dc", "WPA*01*5ce7ebe97a1bbfeb2822ae627b726d5b*27462da350ac*accd10fb464e*686173686361742d6573736964***"},
		{"27000", "b4b9b02e6f09a9bd760f388b67351e2b", "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920"},
		{"28800", "hashcat", "$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e"},
	}
	wantTypes := map[string]string{
		"2500": "wpa-hccapx", "2501": "wpa-hccapx-pmk", "22001": "wpa-pmk",
		"27000": "netntlmv1-nt", "28800": "krb5db",
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != wantTypes[tc.mode] {
				t.Fatalf("mode alias = %q, want %q", got, wantTypes[tc.mode])
			}
			ok, err := verifyCandidate(tc.candidate, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			wrong := "wrong-password"
			if tc.mode == "2501" || tc.mode == "22001" || tc.mode == "27000" {
				wrong = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			if bad, err := verifyCandidate(wrong, tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong candidate: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatLegacyAuthenticationDetection(t *testing.T) {
	for target, want := range map[string]string{
		hccapxHashcatSelfTest: "wpa-hccapx",
		"$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e": "krb5db",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detectHashTypes() = %v, want [%s]", got, want)
		}
	}
}

func TestHashcatLegacyAuthenticationRejectsMalformed(t *testing.T) {
	for mode, target := range map[string]string{
		"2500":  "48435058",
		"2501":  hccapxHashcatSelfTest[:84] + "00" + hccapxHashcatSelfTest[86:],
		"22001": "WPA*03*bad",
		"27000": "::bad",
		"28800": "$krb5db$17$user$REALM$00",
	} {
		candidate := "hashcat"
		if mode == "27000" {
			candidate = "b4b9b02e6f09a9bd760f388b67351e2b"
		}
		if _, err := verifyCandidate(candidate, target, mode, "", "prefix"); err == nil {
			t.Errorf("mode %s accepted malformed record", mode)
		}
	}
}
