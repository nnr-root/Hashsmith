package main

import (
	"strings"
	"testing"
)

func TestHashcatLUKSSplitModes(t *testing.T) {
	want := map[string]string{
		"29511": "luks-sha1-aes", "29512": "luks-sha1-serpent", "29513": "luks-sha1-twofish",
		"29521": "luks-sha256-aes", "29522": "luks-sha256-serpent", "29523": "luks-sha256-twofish",
		"29531": "luks-sha512-aes", "29532": "luks-sha512-serpent", "29533": "luks-sha512-twofish",
		"29541": "luks-ripemd160-aes", "29542": "luks-ripemd160-serpent", "29543": "luks-ripemd160-twofish",
	}
	vectors := map[string]selfTestVector{}
	for _, v := range universalHashRegistry.vectors {
		if _, ok := luksModeSpecs[v.typ]; ok {
			vectors[v.typ] = v
		}
	}
	for mode, typ := range want {
		if got := canonicalHashType(mode); got != typ {
			t.Errorf("canonicalHashType(%s) = %q, want %q", mode, got, typ)
		}
		v, ok := vectors[typ]
		if !ok {
			t.Errorf("missing self-test vector for %s", typ)
			continue
		}
		matched, err := verifyCandidate(v.password, v.target, mode, "", "prefix")
		if err != nil || !matched {
			t.Errorf("Hashcat %s (%s): matched=%v err=%v", mode, typ, matched, err)
		}
	}

	aesVector := vectors["luks-sha1-aes"]
	if ok, err := verifyCandidate(aesVector.password, aesVector.target, "luks-sha1-twofish", "", "prefix"); err == nil || ok {
		t.Fatalf("mismatched LUKS mode should fail: ok=%v err=%v", ok, err)
	}
	badHex := strings.Replace(aesVector.target, "$317296", "$zz7296", 1)
	if _, err := parseLUKSHash(badHex); err == nil {
		t.Fatal("malformed LUKS hex should be rejected")
	}
}

func TestOldOfficePublishedVectorsAndAliases(t *testing.T) {
	const md5Record = "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2"
	const sha1Record = "$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd"

	for _, tc := range []struct {
		typ, target string
	}{
		{"office-old", md5Record},
		{"office-old", sha1Record},
		{"office-old-md5", md5Record},
		{"office-old-sha1", sha1Record},
		{"9700", md5Record},
		{"9800", sha1Record},
		{"john:oldoffice", md5Record},
	} {
		ok, err := verifyCandidate("hashcat", tc.target, tc.typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v", tc.typ, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", tc.target, tc.typ, "", "prefix"); bad {
			t.Errorf("%s accepted wrong password", tc.typ)
		}
	}

	if ok, err := verifyCandidate("hashcat", md5Record, "9800", "", "prefix"); err == nil || ok {
		t.Fatalf("9800 must reject an MD5-family record: ok=%v err=%v", ok, err)
	}
	if ok, err := verifyCandidate("hashcat", sha1Record, "9700", "", "prefix"); err == nil || ok {
		t.Fatalf("9700 must reject a SHA-1-family record: ok=%v err=%v", ok, err)
	}
	if got := detectHashTypes(md5Record); len(got) != 1 || got[0] != "office-old-md5" {
		t.Errorf("MD5 oldoffice detection = %v", got)
	}
	if got := detectHashTypes(sha1Record); len(got) != 1 || got[0] != "office-old-sha1" {
		t.Errorf("SHA-1 oldoffice detection = %v", got)
	}
}

func TestOldOfficeVersionPairCoverage(t *testing.T) {
	// Versions 0 and 1 share the MD5/RC4 derivation; changing the published
	// version-0 marker exercises the version-1 parser branch with the same blob.
	const version1 = "$oldoffice$1*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2"
	// Independently generated with Python hashlib plus a small RFC 6229-style
	// RC4 implementation. Version 4 uses the full 128-bit SHA-1-derived key.
	const version4 = "$oldoffice$4*00112233445566778899aabbccddeeff*aa1bbfc8a6f969321f7fd498bbc2b67d*b7d53ac272cee4722061f0cfb099d82476d18fbd"
	for _, tc := range []struct {
		typ, target string
	}{
		{"office-old-md5", version1},
		{"office-old-sha1", version4},
	} {
		ok, err := verifyCandidate("hashcat", tc.target, tc.typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("%s paired-version vector: ok=%v err=%v", tc.typ, ok, err)
		}
	}
}

func TestAdditionalCompatibilityModes(t *testing.T) {
	for mode, want := range map[string]string{
		"7701": "sap-b-rfc-read-table", "7801": "sap-fg-rfc-read-table", "10510": "pdf",
	} {
		if got := canonicalHashType(mode); got != want {
			t.Errorf("canonicalHashType(%s) = %q, want %q", mode, got, want)
		}
	}
	for _, tc := range []struct {
		mode, password, target string
	}{
		{"7701", "hashcat", "027642760180$77EC386300000000"},
		{"7801", "hashcat", "604020408266$32837BA7B97672BA4E5A00000000000000000000"},
		{"10510", "hashcat", "$pdf$1*3*40*-4*1*16*5e1f73575e1f73575e1f73575e1f7357*32*c0be424bef466277092f2a1ba0fbe506ebabe5c01db100dedc0ffeebabe5c01d*32*0ff1cedeadce110ff1cedeadce110ff1cedeadce110ff1cedeadce11babebabe"},
	} {
		ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("Hashcat %s published vector: ok=%v err=%v", tc.mode, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", tc.target, tc.mode, "", "prefix"); bad {
			t.Errorf("Hashcat %s accepted wrong password", tc.mode)
		}
	}
	if got := detectHashTypes("027642760180$77EC386300000000"); len(got) != 1 || got[0] != "sap-b-rfc-read-table" {
		t.Errorf("SAP 7701 detection = %v", got)
	}
	if got := detectHashTypes("604020408266$32837BA7B97672BA4E5A00000000000000000000"); len(got) != 1 || got[0] != "sap-fg-rfc-read-table" {
		t.Errorf("SAP 7801 detection = %v", got)
	}
}
