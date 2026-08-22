package main

import "testing"

// Published Hashcat example records. Unless Hashcat documents otherwise, the
// password for these vectors is "hashcat".
func TestHashcatIteratedRecordVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"32000", "$sspr$0$100000$NONE$2c8586ef492e3c3dd3795395507dc14f"},
		{"32010", "$sspr$1$100000$NONE$b3485214dfa55b038a606a183a560dab7db4ecf1"},
		{"32020", "$sspr$2$100000$CxCpGqosk9PkCBcoRFp6DLjjRhVEJKK8$a33283d71c2ecaf4f3017b0a89feca2fc879221c"},
		{"32030", "$sspr$3$100000$ODk2NDA5Mjc2NDIwMjMwMjQyMTQ1NzMz$7195873d47c7e3627510862e37fe7cab9bc83b91feecb9864841bf80cff92419"},
		{"32031", "$sspr$3$1000$f9bbf1381f481427$a1b45fd7eb190cc7f0bf831698cb777207eebbb4b7ea2abd6fff84be539aae62"},
		{"32040", "$sspr$4$100000$NzYwNjMyNDc2MTQ2OTE4NTUzODAyODE3$0ce2e8b8efa4280e6e003d77cb45d45300dff3960c5c073f68303565fe62fe4ff3ada8cee7d3b87d0457335ab0df73c5c64ee1f71ccf6b8bd43a316ecb42ecd4"},
		{"32041", "$sspr$4$1000$9ad596c50a5c9acd$d4cdc3c7d227e3cc57a9c9014b1eff1684808ef40191482cd8ae6e9d7b66211a5f04e4b34f494b0513a5f67b9614c5ff16e95e624a60f41b16b90533f305146e"},
		{"32050", "$pbkdf2-hmac-sha1$100000$7134180503252384106490944216249411431665011151428170747164626720$990e0c5f62b1384d48cbe3660329b9741c4a8473"},
		{"32070", "$pbkdf2-hmac-sha512$100000.0211258841559010919749469547425215185689838310218571790549787198.1659e40e64daf84d635a5f1ed2f5708f6735233bed471994bdc0307b3c5f77597f79bdcdd088d1e79357b383809ddfd84379006b49e14f4ff45c449071478777"},
	}
	for _, tc := range cases {
		ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); bad {
			t.Errorf("mode %s accepted a wrong password", tc.mode)
		}
	}
}

func TestHashcatApplicationDigestVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"122", "1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683"},
		{"1722", "648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d"},
		{"2612", "$PHPS$34323438373734$5b07e065b9d78d69603e71201c6cf29f"},
		{"4522", "4a2b722cc65ecf0f7797cdaea4bce81f66716eef:653074362104"},
		{"4711", "53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1"},
		{"5800", "0223b799d526b596fe4ba5628b9e65068227e68e:f6d45822728ddb2c"},
		{"6300", "{smd5}a5/yTL/u$VfvgyHx1xUlXZYBocQpQY0"},
		{"6700", "{ssha1}06$bJbkFGJAB30L2e23$dCESGOsP7jaIIAJ1QAcmaGeG.kr"},
		{"7401", "$mysql$A$005*F9CC98CE08892924F50A213B6BC571A2C11778C5*625479393559393965414D45316477456B484F41316E64484742577A2E3162785353526B7554584647562F"},
		{"20711", "$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824"},
		{"30420", "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df"},
		{"35200", "$as400$ssha1$*QTEST1*7ED7D3694D0A2E40A720D41031B456C09124966E"},
	}
	for _, tc := range cases {
		password := "hashcat"
		if tc.mode == "35200" {
			password = "IOIO13" // Hashcat's module self-test password.
		}
		ok, err := verifyCandidate(password, tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); bad {
			t.Errorf("mode %s accepted a wrong password", tc.mode)
		}
	}
}

func TestHashcatWhirlpoolAndCompositeVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"30500", "e13bb4b8e5a98db7277df344aa3363cf:28945624531"},
		{"32600", "a2c0342a2617026fbaeed01130c826cc3f58242799894b3ecc1abfa811ede03fd712efd14a886af6fa74045502f22c9feb1c45a291cf2d7bbe9bb94c388b6403:deadbeef"},
	}
	for _, tc := range cases {
		ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
	}
}

func TestHashcatRecordDetection(t *testing.T) {
	for target, want := range map[string]string{
		"$sspr$0$1$NONE$7fc56270e7a70fa81a5935b72eacbe29":                                        "sspr",
		"$as400$ssha1$*USER*0000000000000000000000000000000000000000":                            "as400-ssha1",
		"$PHPS$31$00000000000000000000000000000000":                                              "phps",
		"$SHA$1234567890123456$0000000000000000000000000000000000000000000000000000000000000000": "authme-sha256",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detectHashTypes(%q) = %v, want [%s]", target, got, want)
		}
	}
}
