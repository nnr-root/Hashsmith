package main

import "testing"

func TestHashcatSecureRecordVectors(t *testing.T) {
	cases := []struct {
		mode, typ, password, target string
	}{
		{"31200", "veeam-vbk", "hashcat", "$vbk$*54731702769149752741495960625996207399688284541933702394775960978730695504382155223405444342855920150089170058956647576461877712*10000*78cf7df8f1ed8bb50bda1129ec8e6810"},
		{"33700", "ms-online-account", "hashcat", "$MSONLINEACCOUNT$0$10000$91869d1d5d3a1df25dd3f0e57bbc226a43641bc03086dcb5b6672941fcabce01"},
		{"31400", "securecrt-v2", "hashcat", "S:\"Config Passphrase\"=02:ded7137400e0a1004a12f1708453968ccc270908ba02ab0345c83690d1de3d9937587be66ad2a7fe8cc6cb16ecff02e61ac05e09d4f49f284efd24f6b16d6ae3"},
		{"25900", "knx-ip-secure", "hashcat", "$knx-ip-secure-device-authentication-code$*3033*fa7c0d787a9467c209f0a6e7cf16069ed704f3959dce19e45d7935c0a91bce41*f927640d9bbe9a4b0b74dd3289ad41ec"},
		{"27100", "netntlmv2-nt", "b4b9b02e6f09a9bd760f388b67351e2b", "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"},
		{"28300", "teamspeak3", "hashcat", "$teamspeak$3$E0aV0IQ29EDyxRfkFoQflUGJ6zo=$mRgDUkNpd0IwUEcTJQBmE0NHYwdDEhFzQ0VgMRcFJUIRYnaHBwNXRZJwk2ZUaURzdXkVYiUROERmI0hYYGFYCDiIJCeIU3N5EhRVcZFnSIRCJlkUFkY4YFMDcheYeTl4RYZEdpKGJYhxAIQJEYGYEA=="},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("correct candidate: ok=%v err=%v", ok, err)
			}
			badCandidate := wrongPassword(tc.password)
			if bad, err := verifyCandidate(badCandidate, tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong candidate: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatSecureRecordDetection(t *testing.T) {
	for target, want := range map[string]string{
		"$vbk$*54731702769149752741495960625996207399688284541933702394775960978730695504382155223405444342855920150089170058956647576461877712*10000*78cf7df8f1ed8bb50bda1129ec8e6810":                      "veeam-vbk",
		"$MSONLINEACCOUNT$0$10000$91869d1d5d3a1df25dd3f0e57bbc226a43641bc03086dcb5b6672941fcabce01":                                                                                                          "ms-online-account",
		"S:\"Config Passphrase\"=02:ded7137400e0a1004a12f1708453968ccc270908ba02ab0345c83690d1de3d9937587be66ad2a7fe8cc6cb16ecff02e61ac05e09d4f49f284efd24f6b16d6ae3":                                        "securecrt-v2",
		"$knx-ip-secure-device-authentication-code$*3033*fa7c0d787a9467c209f0a6e7cf16069ed704f3959dce19e45d7935c0a91bce41*f927640d9bbe9a4b0b74dd3289ad41ec":                                                  "knx-ip-secure",
		"$teamspeak$3$E0aV0IQ29EDyxRfkFoQflUGJ6zo=$mRgDUkNpd0IwUEcTJQBmE0NHYwdDEhFzQ0VgMRcFJUIRYnaHBwNXRZJwk2ZUaURzdXkVYiUROERmI0hYYGFYCDiIJCeIU3N5EhRVcZFnSIRCJlkUFkY4YFMDcheYeTl4RYZEdpKGJYhxAIQJEYGYEA==": "teamspeak3",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
}

func TestHashcatSecureRecordMalformedInputs(t *testing.T) {
	for typ, target := range map[string]string{
		"veeam-vbk":         "$vbk$*bad*0*bad",
		"ms-online-account": "$MSONLINEACCOUNT$0$0$bad",
		"securecrt-v2":      "S:\"Config Passphrase\"=02:bad",
		"knx-ip-secure":     "$knx-ip-secure-device-authentication-code$*bad",
		"netntlmv2-nt":      "user::domain:bad",
		"teamspeak3":        "$teamspeak$3$bad$bad",
	} {
		if _, err := verifyCandidate("not-a-valid-candidate", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}

func TestHashcatMode33100Alias(t *testing.T) {
	if got := canonicalHashType("33100"); got != "md5-salt-md5pass-salt" {
		t.Fatalf("mode alias = %q", got)
	}
	if ok, err := verifyCandidate("hashcat", "866244ca1d318292a6f40b60e03fd29c:72219426709", "33100", "", "prefix"); err != nil || !ok {
		t.Fatalf("Hashcat 33100 vector: ok=%v err=%v", ok, err)
	}
}
