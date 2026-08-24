package main

import "testing"

func TestHashcatExpansionPublishedVectors(t *testing.T) {
	tests := []struct {
		mode, target string
	}{
		{"125", "5387280701327dc2162bdeb451d5a465af6d13eff9276efeba"},
		{"11750", "0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337"},
		{"11760", "d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337"},
		{"11850", "be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337"},
		{"11860", "bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337"},
		{"14400", "fd9149fb3ae37085dc6ed1314449f449fbf77aba:87740665218240877702"},
		{"16400", "{CRAM-MD5}5389b33b9725e5657cb631dc50017ff1535ce4e2a1c414009126506fc4327d0d"},
		{"17700", "e1dfad9bafeae6ef15f5bbb16cf4c26f09f5f1e7870581962fc84636"},
		{"17900", "5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701"},
		{"18500", "888a2ffcb3854fba0321110c5d0d434ad1aa2880"},
		{"19210", "@S@vm2nBGHes6QkXra0f74XmouSiRzjYD3r/0py+txv0Kr8A4hCPMGFHoZqr41JFiYcJPPOeIheqFseMyLyw/15Pw==@NDY2MDEwNjk3YjBjYzM2MzliMzc3Mzc0ZTNiMTAzNzE="},
		{"20200", "$pbkdf2-sha512$25000$LyWE0HrP2RsjZCxlDGFMKQ$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH.SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw"},
		{"20300", "$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A"},
		{"20400", "$pbkdf2$131000$r5WythYixPgfQ2jt3buXcg$8Kdr.QQEOaZIXNOrrru36I/.6Po"},
		{"21501", "$solarwinds$1$3pHkk55NTYpAeV3EJjcAww==$N4Ii2PxXX/bTZZwslQLIKrp0wvfZ5aN9hpyiR896ozJMJTPO1Q7BK1Eht8Vhl4kXq/42Vn2zp3qYeAkRuqsuEw=="},
		{"35100", "$sm3$KTTUB40dW4mRyRFd$ul2xLiIY3FJtbo8sv1R93sAYCkxQCH/6rmS1kD5vJYA"},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatExpansionAutoDetection(t *testing.T) {
	tests := map[string]string{
		"$sm3$KTTUB40dW4mRyRFd$ul2xLiIY3FJtbo8sv1R93sAYCkxQCH/6rmS1kD5vJYA":          "sm3crypt",
		"{CRAM-MD5}5389b33b9725e5657cb631dc50017ff1535ce4e2a1c414009126506fc4327d0d": "dovecot-cram-md5",
		"fd9149fb3ae37085dc6ed1314449f449fbf77aba:87740665218240877702":              "sha1-cx",
		"5387280701327dc2162bdeb451d5a465af6d13eff9276efeba":                         "arubaos",
	}
	for target, want := range tests {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detectHashTypes(%q) = %v, want [%s]", target, got, want)
		}
	}
}

func TestHashcatExpansionBlockchainAlias(t *testing.T) {
	if got := canonicalHashType("15200"); got != "blockchain" {
		t.Fatalf("canonicalHashType(15200) = %q, want blockchain", got)
	}
}

func TestHashcatExpansionRejectsMalformedRecords(t *testing.T) {
	tests := map[string]string{
		"125":   "5387280700-not-hex",
		"14400": "abcd:short",
		"16400": "{CRAM-MD5}abcd",
		"19210": "@S@bad@bad",
		"21501": "$solarwinds$1$bad$bad",
		"35100": "$sm3$bad",
	}
	for mode, target := range tests {
		if _, err := verifyCandidate("hashcat", target, mode, "", "prefix"); err == nil {
			t.Errorf("mode %s accepted malformed record %q", mode, target)
		}
	}
}
