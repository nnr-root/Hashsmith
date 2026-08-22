package main

import (
	"strings"
	"testing"
)

// These vectors are published on Hashcat's example-hashes page. The password
// for every case is "hashcat".
func TestHashcatGenericModeVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"10", "01dfae6e5d4d90d9892622325959afbe:7050461"},
		{"20", "f0fda58630310a6dd91a7d8f0a4ceda2:4225637426"},
		{"30", "b31d032cfdcf47a399990a71e43c5d2a:144816"},
		{"40", "d63d0e21fdc05f618d55ef306c54af82:13288442151473"},
		{"70", "2303b15bfa48c74a74758135a0df1201"},
		{"110", "2fc5a684737ce1bf7b3b239df432416e0dd07357:2014"},
		{"120", "cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024"},
		{"130", "c57f6ac1b71f45a07dbd91a59fa47c23abcd87c2:631225"},
		{"140", "5db61e4cd8776c7969cfd62456da639a4c87683a:8763434884872"},
		{"170", "b9798556b741befdbddcbf640d1dd59d19b1e193"},
		{"1310", "0cf361904f4b0234cf4ade8496d8c11c04e5982db967603e82f22b2f:89452466460220844541730694146873525188525677"},
		{"1320", "4258a61d3d0d5a5b6796f0ab02d081e998fe657d55d22091d3b51409:36669207"},
		{"1410", "c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528"},
		{"1420", "eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617"},
		{"1430", "4cc8eb60476c33edac52b5a7548c2c50ef0f9e31ce656c6f4b213f901bc87421:890128"},
		{"1440", "a4bd99e1e0aba51814e81388badb23ecc560312c4324b2018ea76393ea1caca9:12345678"},
		{"1470", "9e9283e633f4a7a42d3abc93701155be8afe5660da24c8758e7d3533e2f2dc82"},
		{"1710", "e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260"},
		{"1720", "976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127"},
		{"1730", "13070359002b6fbb3d28e50fba55efcf3d7cc115fe6e3f6c98bf0e3210f1c6923427a1e1a3b214c1de92c467683f6466727ba3a51684022be5cc2ffcb78457d2:341351589"},
		{"1740", "bae3a3358b3459c761a3ed40d34022f0609a02d90a0d7274610b16147e58ece00cd849a0bd5cf6a92ee5eb5687075b4e754324dfa70deca6993a85b2ca865bc8:1237015423"},
		{"1770", "79bba09eb9354412d0f2c037c22a777b8bf549ab12d49b77d5b25faa839e4378d8f6fa11aceb6d9413977ae5ad5d011568bad2de4f998d75fd4ce916eda83697"},
	}
	for _, tc := range cases {
		for _, typ := range []string{tc.mode, "hashcat:" + tc.mode} {
			ok, err := verifyCandidate("hashcat", tc.target, typ, "", "prefix")
			if err != nil || !ok {
				t.Errorf("mode %s (%s): ok=%v err=%v", tc.mode, typ, ok, err)
			}
			if bad, _ := verifyCandidate("wrong", tc.target, typ, "", "prefix"); bad {
				t.Errorf("mode %s accepted a wrong password", tc.mode)
			}
		}
	}
}

func TestHashcatNestedAndRepresentationVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"2600", "a936af92b0ae20b1ff6c3347a72e5fbe"},
		{"3500", "9882d0778518b095917eb589f6998441"},
		{"4300", "b8c385461bb9f9d733d3af832cf60b27"},
		{"4400", "288496df99b33f8f75a7ce4837d1b480"},
		{"4500", "3db9184f5da4e463832b086211af8d2314919951"},
		{"4700", "92d85978d884eb1d99a51652b1139c8279fa8663"},
		{"300", "fcf7c1b8749cf99d88e5f34271d636178fb5d130"},
		{"3000", "299bd128c1101fd6"},
	}
	for _, tc := range cases {
		ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
	}

	const blake = "$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e"
	if ok, err := verifyCandidate("hashcat", blake, "600", "", "prefix"); err != nil || !ok {
		t.Fatalf("Hashcat BLAKE2 wrapper: ok=%v err=%v", ok, err)
	}
	if got := detectHashTypes(blake); len(got) != 1 || got[0] != "blake2b" {
		t.Fatalf("BLAKE2 detection = %v", got)
	}
	if got := identifyText(blake); !strings.Contains(got, "BLAKE2b-512") {
		t.Fatalf("BLAKE2 identification = %q", got)
	}
}

func TestJohnFormatAliases(t *testing.T) {
	cases := []struct {
		alias, canonical string
	}{
		{"john:raw-md5", "md5"},
		{"jtr-raw-sha256", "sha256"},
		{"nt", "ntlm"},
		{"mscash2", "dcc2"},
		{"dynamic_1", "md5-pass-salt"},
		{"john:dynamic_2", "md5-md5"},
		{"john:dynamic_3", "md5-md5-md5"},
	}
	for _, tc := range cases {
		if got := canonicalHashType(tc.alias); got != tc.canonical {
			t.Errorf("canonicalHashType(%q) = %q, want %q", tc.alias, got, tc.canonical)
		}
	}
}

func TestGenericSaltedAutoDetection(t *testing.T) {
	cases := []struct {
		target, want string
	}{
		{"bdc87b9c894da5168059e00ebffb9077:1234", "md5-pass-salt"},
		{"2fc5a684737ce1bf7b3b239df432416e0dd07357:2014", "sha1-pass-salt"},
		{"c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528", "sha256-pass-salt"},
	}
	for _, tc := range cases {
		got := detectHashTypes(tc.target)
		found := false
		for _, typ := range got {
			found = found || typ == tc.want
		}
		if !found {
			t.Errorf("detectHashTypes(%q) = %v, missing %q", tc.target, got, tc.want)
		}
		if identified := identifyText(tc.target); !strings.Contains(identified, "Generic salted") {
			t.Errorf("identifyText(%q) = %q", tc.target, identified)
		}
	}
}

func TestHashcatSHA384ModeVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"10800", "07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42"},
		{"10810", "ca1c843a7a336234baf9db2e10bc38824ce523402fbd7741286b1602bdf6cb869a45289bb9fb706bd404b9f3842ff729:2746460797049820734631508"},
		{"10820", "63f63d7f82d4a4cb6b9ff37a6bc7c5ec39faaf9c9078551f5cbf7960e76ded87b643d37ac53c45bc544325e7ff83a1f2:93362"},
		{"10830", "3516a589d2ed4071bf5e36f22e11212b3ad9050b9094b23067103d51e99dcb25c4dc397dba8034fed11a8184acfbb699:577730514588712"},
		{"10840", "316e93ea8e04de3e5a909c53d36923a31a16c1b9e89b44201d6082f87ca49c5bca53cad65f685207db3ea2ccc7ca40f8:700067651"},
		{"10870", "48e61d68e93027fae35d405ed16cd01b6f1ae66267833b4a7aa1759e45bab9bba652da2e4c07c155a3d8cf1d81f3a7e8"},
	}
	for _, tc := range cases {
		ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
	}
}

func TestHashcatKDFCompatibilityVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"8900", "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo="},
		{"10900", "sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt"},
		{"11900", "md5:1000:MTg1MzA=:Lz84VOcrXd699Edsj34PP98+f4f3S0rTZ4kHAIHoAjs="},
		{"12000", "sha1:1000:MzU4NTA4MzIzNzA1MDQ=:19ofiY+ahBXhvkDsp0j2ww=="},
		{"12100", "sha512:1000:ODQyMDEwNjQyODY=:MKaHNWXUsuJB3IEwBHbm3w=="},
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
	if got := detectHashTypes(cases[0].target); len(got) != 1 || got[0] != "scrypt" {
		t.Errorf("Hashcat SCRYPT detection = %v", got)
	}
}

func TestSHA1CryptCompatibility(t *testing.T) {
	const target = "$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q"
	if ok, err := verifyCandidate("hashcat", target, "15100", "", "prefix"); err != nil || !ok {
		t.Fatalf("Hashcat 15100: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyCandidate("wrong", target, "john:sha1crypt", "", "prefix"); bad {
		t.Fatal("sha1crypt accepted a wrong password")
	}
	if got := detectHashTypes(target); len(got) != 1 || got[0] != "sha1crypt" {
		t.Fatalf("sha1crypt detection = %v", got)
	}
	if got := identifyText(target); !strings.Contains(got, "sha1crypt") {
		t.Fatalf("sha1crypt identification = %q", got)
	}
}

func TestCompatibilityKDFLimits(t *testing.T) {
	bad := []struct {
		typ, target string
	}{
		{"8900", "SCRYPT:3:1:1:c2FsdA==:ZGlnZXN0"},
		{"8900", "SCRYPT:1073741824:8:1:c2FsdA==:ZGlnZXN0"},
		{"15100", "$sha1$100000001$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q"},
	}
	for _, tc := range bad {
		if _, err := verifyCandidate("x", tc.target, tc.typ, "", "prefix"); err == nil {
			t.Errorf("%s accepted unsafe/malformed target %q", tc.typ, tc.target)
		}
	}
}

func TestExtendedExistingModeAliases(t *testing.T) {
	cases := []struct {
		mode, canonical string
	}{
		{"9200", "cisco8"}, {"9300", "cisco9"}, {"9400", "office"},
		{"10000", "django"}, {"10200", "cram-md5"}, {"10901", "ldap-pbkdf2"},
		{"11300", "bitcoin"}, {"11400", "sip"}, {"12300", "oracle12c"},
		{"12700", "blockchain"}, {"13100", "krb5tgs"}, {"13400", "keepass"},
		{"14600", "luks"}, {"14700", "itunes"}, {"15700", "ethereum"},
		{"16600", "electrum"}, {"18200", "krb5asrep"}, {"22000", "wpa"},
		{"22100", "bitlocker"},
	}
	for _, tc := range cases {
		if got := canonicalHashType(tc.mode); got != tc.canonical {
			t.Errorf("mode %s = %q, want %q", tc.mode, got, tc.canonical)
		}
	}
}
