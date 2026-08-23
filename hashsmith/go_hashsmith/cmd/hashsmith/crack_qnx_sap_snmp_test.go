package main

import "testing"

func TestQNXAndExpandedSNMPHashcatVectors(t *testing.T) {
	cases := []struct {
		mode, typ, password, target string
	}{
		{"19000", "qnx-md5", "hashcat", "@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050"},
		{"19100", "qnx-sha256", "hashcat", "@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604"},
		{"19200", "qnx-sha512", "hashcat", "@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159"},
		{"10300", "sap-issha1", "hashcat", "{x-issha, 1024}BnjXMqcNTwa3BzdnUOf1iAu6dw02NzU4MzE2MTA="},
		{"25200", "snmpv3", "hashcat1", snmpV3Mode2Vector},
		{"26700", "snmpv3", "hashcat1", snmpV3Mode3Vector},
		{"26800", "snmpv3", "hashcat1", snmpV3Mode4Vector},
		{"26900", "snmpv3", "hashcat1", snmpV3Mode5Vector},
		{"27300", "snmpv3", "hashcat1", snmpV3Mode6Vector},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong-password", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestSAPJohnPublishedVectors(t *testing.T) {
	for target, password := range map[string]string{
		"{x-issha, 1024}hmiyJ2a/Z+HRpjQ37Osz+rYax9UxMjM0NTY3ODkwYWI=":                                    "OpenWall",
		"{x-isSHA256, 3000}UqMnsr5BYN+uornWC7yhGa/Wj0u5tshX19mDUQSlgih6OTFoZjRpMQ==":                     "booboo",
		"{x-isSHA384, 5000}3O/F4YGKNmIYHDu7ZQ7Q+ioCOQi4HRY4yrggKptAU9DtmHigCuGqBiAPVbKbEAfGTzh4YlZLWUM=": "booboo",
	} {
		ok, err := verifyCandidate(password, target, "john:saph", "", "prefix")
		if err != nil || !ok {
			t.Errorf("John saph correct password: ok=%v err=%v", ok, err)
		}
	}
}

func TestQNXJohnAliasDispatch(t *testing.T) {
	for target := range map[string]bool{
		"@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050":                                                                                                 true,
		"@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604":                                                                 true,
		"@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159": true,
	} {
		ok, err := verifyCandidate("hashcat", target, "john:qnx", "", "prefix")
		if err != nil || !ok {
			t.Errorf("John qnx correct password: ok=%v err=%v", ok, err)
		}
	}
}

func TestQNXAndSAPDetection(t *testing.T) {
	for target, want := range map[string]string{
		"@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050":                                                                                                 "qnx-md5",
		"@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604":                                                                 "qnx-sha256",
		"@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159": "qnx-sha512",
		"{x-issha, 1024}BnjXMqcNTwa3BzdnUOf1iAu6dw02NzU4MzE2MTA=":                                                                                              "sap-issha1",
		"{x-isSHA256, 3000}UqMnsr5BYN+uornWC7yhGa/Wj0u5tshX19mDUQSlgih6OTFoZjRpMQ==":                                                                           "sap-issha256",
		"{x-isSHA384, 5000}3O/F4YGKNmIYHDu7ZQ7Q+ioCOQi4HRY4yrggKptAU9DtmHigCuGqBiAPVbKbEAfGTzh4YlZLWUM=":                                                       "sap-issha384",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
}

func TestQNXAndSAPMalformedRecords(t *testing.T) {
	for typ, target := range map[string]string{
		"qnx-md5":      "@m@bad@salt",
		"qnx-sha256":   "@s,0@bad@1234567890123456",
		"qnx-sha512":   "@S@bad@1234567890123456",
		"sap-issha1":   "{x-issha, 0}bad",
		"sap-issha256": "{x-isSHA256, 0}bad",
		"sap-issha384": "{x-isSHA384, 0}bad",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
