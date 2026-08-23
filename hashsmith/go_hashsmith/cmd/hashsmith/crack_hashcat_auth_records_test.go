package main

import "testing"

func TestHashcatProtocolAndApplicationVectors(t *testing.T) {
	cases := []struct {
		mode, typ, password, target string
	}{
		{"11100", "postgres-cram", "hashcat", "$postgres$postgres*74402844*4e7fabaaf34d780c4a5822d28ee1c83e"},
		{"18100", "totp", "hashcat", "597056:3600:613004:1234567890:322664:9876543210"},
		{"25000", "snmpv3", "hashcat1", snmpV3Mode0Vector},
		{"25100", "snmpv3", "hashcat1", snmpV3Mode1Vector},
		{"25500", "stellar-wallet", "hashcat", "$stellar$YAlIJziURRcBEWUwRSRDWA==$EutMmmcV5Hbf3p1I$rfSAF349RvGKG4R4Z2VCrH9WjNEKjbJa9hpOja9Yn8MwXruuFEMtw47HPn9CYj+JJ5Rb4Z87Wejj1c4fqpbMZHFOnqtQsVAr"},
		{"26200", "openedge", "hashcat", "lebVZteiEsdpkncc"},
		{"28700", "aws-sig-v4", "hashcat", "$AWS-Sig-v4$0$20220221T000000Z$us-east-1$s3$421ab6e4af9f49fa30fa9c253fcfeb2ce91668e139e6b23303c5f75b04f8a3c4$3755ed2bc1b2346e003ccaa7d02ae8b73c72bcbe9f452ccf066c78504d786bbb"},
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

func TestSNMPv3SHA1Vector(t *testing.T) {
	ok, err := verifyCandidate("hashcat1", snmpV3SHA1Vector, "25000", "", "prefix")
	if err != nil || !ok {
		t.Fatalf("correct password: ok=%v err=%v", ok, err)
	}
	if bad, err := verifyCandidate("wrong-password", snmpV3SHA1Vector, "25000", "", "prefix"); err != nil || bad {
		t.Fatalf("wrong password: ok=%v err=%v", bad, err)
	}
}

func TestProtocolAndApplicationDetection(t *testing.T) {
	for target, want := range map[string]string{
		"$postgres$postgres*74402844*4e7fabaaf34d780c4a5822d28ee1c83e": "postgres-cram",
		"597056:3600:613004:1234567890:322664:9876543210":              "totp",
		snmpV3Mode0Vector: "snmpv3",
		"$stellar$YAlIJziURRcBEWUwRSRDWA==$EutMmmcV5Hbf3p1I$rfSAF349RvGKG4R4Z2VCrH9WjNEKjbJa9hpOja9Yn8MwXruuFEMtw47HPn9CYj+JJ5Rb4Z87Wejj1c4fqpbMZHFOnqtQsVAr":                           "stellar-wallet",
		"$AWS-Sig-v4$0$20220221T000000Z$us-east-1$s3$421ab6e4af9f49fa30fa9c253fcfeb2ce91668e139e6b23303c5f75b04f8a3c4$3755ed2bc1b2346e003ccaa7d02ae8b73c72bcbe9f452ccf066c78504d786bbb": "aws-sig-v4",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
}

func TestProtocolJohnAliases(t *testing.T) {
	postgresTarget := "$postgres$postgres*74402844*4e7fabaaf34d780c4a5822d28ee1c83e"
	if ok, err := verifyCandidate("hashcat", postgresTarget, "john:postgres", "", "prefix"); err != nil || !ok {
		t.Fatalf("John postgres alias: ok=%v err=%v", ok, err)
	}
	if got := canonicalHashType("john:SNMP"); got != "snmpv3" {
		t.Fatalf("John SNMP alias = %q", got)
	}
}

func TestProtocolAndApplicationMalformedRecords(t *testing.T) {
	for typ, target := range map[string]string{
		"postgres-cram":  "$postgres$bad",
		"totp":           "123:bad",
		"snmpv3":         "$SNMPv3$0$bad",
		"stellar-wallet": "$stellar$bad$bad$bad",
		"openedge":       "short",
		"aws-sig-v4":     "$AWS-Sig-v4$bad",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
