package main

import "testing"

// Official Hashcat module self-tests; every module uses "hashcat" here.
func TestHashcatMoreRecordVectors(t *testing.T) {
	cases := []struct {
		mode, typ, target string
	}{
		{"3730", "md5-salt1-upper-md5-salt2-pass", "0e1484eb061b8e9cfd81868bba1dc4a0:229381927:182719643"},
		{"31700", "md5-triple-dual-salt", "c7a971e405313d0ecc22e37e8b2424a1:2316355934:478467"},
		{"32300", "empirecms", "5962d4ada95d6493379cd9c05ce7a376:726620866134417802643053384570:6056291339665060317728572165496183"},
		{"5720", "cisco-ise", "465865d4226c4d9696e601f2c99b25ae2c194ec01806bafc93933331acfc1a60e8bdcca8be9fa245a5fa16029bb52480915746f47d1c539d01da7ec6f37468d1"},
		{"7000", "fortigate", "AK1FCIhM0IUIQVFJgcDFwLCMi7GppdwtRzMyDpFOFxdpH8="},
		{"6800", "lastpass", "02eb97e869e0ddc7dc760fc633b4b54d:100100:pmix@trash-mail.com:9b071db7b8e265d4cadd3eb65ac0864a"},
		{"35000", "sap-issha512", "{x-isSHA512, 15000}YZH/V2T7zlQMGeWLBarm5Oi3qV9Y8ByXQijD28+bjtLdo7YssXaUBkxMXbS3l4yVlYw97tvYj+vu/L37sg1reDEzODQ4MDY1NzQ1NjQ="},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatMoreRecordDetection(t *testing.T) {
	for target, want := range map[string]string{
		"AK1FCIhM0IUIQVFJgcDFwLCMi7GppdwtRzMyDpFOFxdpH8=": "fortigate",
		"{x-isSHA512, 15000}YZH/V2T7zlQMGeWLBarm5Oi3qV9Y8ByXQijD28+bjtLdo7YssXaUBkxMXbS3l4yVlYw97tvYj+vu/L37sg1reDEzODQ4MDY1NzQ1NjQ=": "sap-issha512",
		"02eb97e869e0ddc7dc760fc633b4b54d:100100:pmix@trash-mail.com:9b071db7b8e265d4cadd3eb65ac0864a":                                "lastpass",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
}

func TestJohnMoreRecordAliases(t *testing.T) {
	for alias, want := range map[string]string{
		"john:saph":      "sap-issha512",
		"john:fortigate": "fortigate",
		"john:lastpass":  "lastpass",
	} {
		if got := canonicalHashType(alias); got != want {
			t.Errorf("canonicalHashType(%q) = %q, want %q", alias, got, want)
		}
	}
}

func TestHashcatNewestRecordVectors(t *testing.T) {
	cases := []struct {
		mode, typ, target string
	}{
		{"9900", "radmin2", "22527bee5c29ce95373c4e0f359f079b"},
		{"13500", "peoplesoft-token", "24eea51b53d02b4c5ff99bcb05a6847fdb2d9308:4f10a0de76e242040c28e9d3dd15c903343489c79765f9118c098c266b9ff505c95bd75bbe406ff3404849eea73930ad17937c0ba6fc3e7bb6d37362941318938b8af96d1292a310b3fd29a67e411ecb10d30247c99183a16951b3859054d4eba9dcd50709c7b21dee836d7ed195cc6b33317aeb557cc56392dc551faa8d5a0fb42212"},
		{"18700", "java-hashcode", "29937c08"},
		{"19500", "rails-restful-auth", "d7d5ea3e09391da412b653ae6c8d7431ec273ea2:238769868762:8962783556527653675"},
		{"21600", "web2py-pbkdf2", "pbkdf2(1000,20,sha512)$744943$c5f8cdef76e3327c908d8d96d4abdb3d8caba14c"},
		{"29100", "flask-session", "eyJ1c2VybmFtZSI6ImFkbWluIn0.YjdgRQ.1OTlf1PD0H9wXsu_qS0aywAJVD8"},
		{"35500", "wordpress-bcrypt", "$wp$2y$10$lzlQrRRhLSjz486bA9CKHuZRPoKz4uviT251Sq/r5OzKUBbrXwnQW"},
		{"28900", "krb5db", "$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestNewestRecordDetectionAndJohnAliases(t *testing.T) {
	for target, want := range map[string]string{
		"pbkdf2(1000,20,sha512)$744943$c5f8cdef76e3327c908d8d96d4abdb3d8caba14c":                      "web2py-pbkdf2",
		"eyJ1c2VybmFtZSI6ImFkbWluIn0.YjdgRQ.1OTlf1PD0H9wXsu_qS0aywAJVD8":                              "flask-session",
		"$wp$2y$10$lzlQrRRhLSjz486bA9CKHuZRPoKz4uviT251Sq/r5OzKUBbrXwnQW":                             "wordpress-bcrypt",
		"$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7": "krb5db",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
	for alias, want := range map[string]string{
		"john:pstoken":      "peoplesoft-token",
		"john:restful-auth": "rails-restful-auth",
		"john:web2py":       "web2py-pbkdf2",
		"john:flask":        "flask-session",
		"john:wpbcrypt":     "wordpress-bcrypt",
		"john:krb5db":       "krb5db",
	} {
		if got := canonicalHashType(alias); got != want {
			t.Errorf("canonicalHashType(%q) = %q, want %q", alias, got, want)
		}
	}
}

func TestHashcatAuthenticationAndDocumentVectors(t *testing.T) {
	cases := []struct {
		mode, typ, target string
	}{
		{"11200", "mysql-cram", "$mysqlna$2576670568531371763643101056213751754328*5e4be686a3149a12847caa9898247dcc05739601"},
		{"16100", "tacacs-plus", "$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006"},
		{"16200", "apple-secure-notes", "$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41"},
		{"20600", "oracle-otm", "otm_sha256:1000:1234567890:S5Q9Kc0ETY6ZPyQU+JYY60oFjaJuZZaSinggmzU8PC4="},
		{"23200", "xmpp-scram", "$xmpp-scram$0$4096$45$353835323736323530353932363531393630313632353634313335323434323038393931323138373138343134$6d5b543b985dc6c0645da3c83d114fce121aa51d"},
		{"25300", "office2016-sheet", "$office$2016$0$100000$876MLoKTq42+/DLp415iZQ==$TNDvpvYyvlSUy97UOLKNhXynhUDDA7H8kLql0ISH5SxcP6hbthdjaTo4Z3/MU0dcR2SAd+AduYb3TB5CLZ8+ow=="},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestAuthenticationAndDocumentDetection(t *testing.T) {
	for target, want := range map[string]string{
		"$mysqlna$2576670568531371763643101056213751754328*5e4be686a3149a12847caa9898247dcc05739601":                                                                "mysql-cram",
		"$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006":                                                                                                                 "tacacs-plus",
		"$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41":                                                           "apple-secure-notes",
		"otm_sha256:1000:1234567890:S5Q9Kc0ETY6ZPyQU+JYY60oFjaJuZZaSinggmzU8PC4=":                                                                                   "oracle-otm",
		"$xmpp-scram$0$4096$45$353835323736323530353932363531393630313632353634313335323434323038393931323138373138343134$6d5b543b985dc6c0645da3c83d114fce121aa51d": "xmpp-scram",
		"$office$2016$0$100000$876MLoKTq42+/DLp415iZQ==$TNDvpvYyvlSUy97UOLKNhXynhUDDA7H8kLql0ISH5SxcP6hbthdjaTo4Z3/MU0dcR2SAd+AduYb3TB5CLZ8+ow==":                   "office2016-sheet",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
}

func TestAuthenticationAndDocumentJohnAliases(t *testing.T) {
	for alias, want := range map[string]string{
		"john:mysqlna":    "mysql-cram",
		"john:tacacs":     "tacacs-plus",
		"john:notes":      "apple-secure-notes",
		"john:oracle-otm": "oracle-otm",
		"john:xmpp-scram": "xmpp-scram",
		"john:office2016": "office2016-sheet",
	} {
		if got := canonicalHashType(alias); got != want {
			t.Errorf("canonicalHashType(%q) = %q, want %q", alias, got, want)
		}
	}
}

func TestAuthenticationAndDocumentMalformedRecords(t *testing.T) {
	for typ, target := range map[string]string{
		"mysql-cram":         "$mysqlna$bad*bad",
		"tacacs-plus":        "$tacacs-plus$0$bad$bad$bad",
		"apple-secure-notes": "$ASN$*1*0*bad*bad",
		"oracle-otm":         "otm_sha256:0:salt:bad",
		"xmpp-scram":         "$xmpp-scram$0$0$1$00$bad",
		"office2016-sheet":   "$office$2016$0$0$bad$bad",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
