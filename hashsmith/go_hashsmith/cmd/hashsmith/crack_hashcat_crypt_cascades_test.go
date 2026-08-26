package main

import "testing"

func TestHashcatCryptCascadeModes(t *testing.T) {
	cases := []struct{ mode, typ string }{
		{"29312", "truecrypt-ripemd160-xts1024"}, {"29313", "truecrypt-ripemd160-xts1536"},
		{"29322", "truecrypt-sha512-xts1024"}, {"29323", "truecrypt-sha512-xts1536"},
		{"29332", "truecrypt-whirlpool-xts1024"}, {"29333", "truecrypt-whirlpool-xts1536"},
		{"29341", "truecrypt-ripemd160-boot-xts512"}, {"29342", "truecrypt-ripemd160-boot-xts1024"},
		{"29343", "truecrypt-ripemd160-boot-xts1536"},
		{"29412", "veracrypt-ripemd160-xts1024"}, {"29413", "veracrypt-ripemd160-xts1536"},
		{"29422", "veracrypt-sha512-xts1024"}, {"29423", "veracrypt-sha512-xts1536"},
		{"29432", "veracrypt-whirlpool-xts1024"}, {"29433", "veracrypt-whirlpool-xts1536"},
		{"29441", "veracrypt-ripemd160-boot-xts512"}, {"29442", "veracrypt-ripemd160-boot-xts1024"},
		{"29443", "veracrypt-ripemd160-boot-xts1536"},
		{"29452", "veracrypt-sha256-xts1024"}, {"29453", "veracrypt-sha256-xts1536"},
		{"29461", "veracrypt-sha256-boot-xts512"}, {"29462", "veracrypt-sha256-boot-xts1024"},
		{"29463", "veracrypt-sha256-boot-xts1536"},
		{"6231", "truecrypt-whirlpool"}, {"6232", "truecrypt-whirlpool-xts1024"},
		{"6233", "truecrypt-whirlpool-xts1536"},
		{"6241", "truecrypt-ripemd160-boot-xts512"}, {"6242", "truecrypt-ripemd160-boot-xts1024"},
		{"6243", "truecrypt-ripemd160-boot-xts1536"},
		{"13731", "veracrypt-whirlpool"}, {"13732", "veracrypt-whirlpool-xts1024"},
		{"13733", "veracrypt-whirlpool-xts1536"},
		{"13741", "veracrypt-ripemd160-boot-xts512"}, {"13742", "veracrypt-ripemd160-boot-xts1024"},
		{"13743", "veracrypt-ripemd160-boot-xts1536"},
		{"13761", "veracrypt-sha256-boot-xts512"}, {"13762", "veracrypt-sha256-boot-xts1024"},
		{"13763", "veracrypt-sha256-boot-xts1536"},
		{"13771", "veracrypt-streebog512"}, {"13772", "veracrypt-streebog512-xts1024"},
		{"13773", "veracrypt-streebog512-xts1536"},
		{"13781", "veracrypt-streebog512-boot-xts512"}, {"13782", "veracrypt-streebog512-boot-xts1024"},
		{"13783", "veracrypt-streebog512-boot-xts1536"},
		{"29471", "veracrypt-streebog512"}, {"29472", "veracrypt-streebog512-xts1024"},
		{"29473", "veracrypt-streebog512-xts1536"},
		{"29481", "veracrypt-streebog512-boot-xts512"}, {"29482", "veracrypt-streebog512-boot-xts1024"},
		{"29483", "veracrypt-streebog512-boot-xts1536"},
	}
	for _, tc := range cases {
		if got := canonicalHashType(tc.mode); got != tc.typ {
			t.Errorf("mode %s resolves to %q, want %q", tc.mode, got, tc.typ)
		}
		if _, ok := cryptCascadeModes[tc.typ]; !ok {
			t.Errorf("mode %s target %q is not wired", tc.mode, tc.typ)
		}
	}
}

func TestTrueCryptCascadeAndBootPublishedVectors(t *testing.T) {
	// TrueCrypt's iteration counts are low enough to exercise every new mode in
	// the ordinary Go suite. The more expensive VeraCrypt matrix remains in the
	// opt-in self-test suite, with two representatives exercised below.
	for _, typ := range []string{
		"truecrypt-ripemd160-xts1024", "truecrypt-ripemd160-xts1536",
		"truecrypt-sha512-xts1024", "truecrypt-sha512-xts1536",
		"truecrypt-whirlpool-xts1024", "truecrypt-whirlpool-xts1536",
		"truecrypt-ripemd160-boot-xts512", "truecrypt-ripemd160-boot-xts1024",
		"truecrypt-ripemd160-boot-xts1536",
	} {
		v := publishedVectorForType(t, typ)
		ok, err := verifyCandidate(v.password, v.target, typ, "", "prefix")
		if err != nil || !ok {
			t.Fatalf("%s published vector failed: ok=%v err=%v", typ, ok, err)
		}
	}
}

func TestVeraCryptCascadeRepresentatives(t *testing.T) {
	for _, typ := range []string{"veracrypt-sha256-xts1536", "veracrypt-ripemd160-boot-xts1536"} {
		v := publishedVectorForType(t, typ)
		ok, err := verifyCandidate(v.password, v.target, typ, "", "prefix")
		if err != nil || !ok {
			t.Fatalf("%s published vector failed: ok=%v err=%v", typ, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", v.target, typ, "", "prefix"); bad {
			t.Fatalf("%s accepted a wrong password", typ)
		}
	}
}

func TestGenericTrueCryptDetectsCascadeHeader(t *testing.T) {
	v := publishedVectorForType(t, "truecrypt-ripemd160-xts1536")
	if got := detectHashTypes(v.target); len(got) != 1 || got[0] != "truecrypt" {
		t.Fatalf("cascade detection = %v, want [truecrypt]", got)
	}
	ok, err := verifyCandidate(v.password, v.target, "truecrypt", "", "prefix")
	if err != nil || !ok {
		t.Fatalf("generic TrueCrypt cascade verification failed: ok=%v err=%v", ok, err)
	}
}
