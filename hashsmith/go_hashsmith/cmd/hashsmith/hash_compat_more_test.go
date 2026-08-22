package main

import "testing"

// Published Hashcat example hashes; unless Hashcat documents otherwise, the
// password is "hashcat".
func TestHashcatAdditionalDigestVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"610", "$BLAKE2$41fcd44c789c735c08b43a871b81c8f617ca43918d38aee6cf8291c58a0b00a03115857425e5ff6f044be7a5bec8536b52d6c9992e21cd43cdca8a55bbf1f5c1:1033"},
		{"620", "$BLAKE2$f0325fdfc3f82a014935442f7adbc069d4636d67276a85b09f8de368f122cf5195a0b780d7fee709fbf1dcd02ddcb581df84508cf1fb0f3393af1be0565491c6:3301"},
		{"31000", "$BLAKE2$2c719b484789ad5f6fc1739012182169b25484af156adc91d4f64f72400e574a"},
		{"31100", "51227e48ea74827b77fc142c3ec21d25cc42c794e6ac422825cd47ad4ac7913d"},
		{"33300", "0d541ae24d30aff2627c4d1a910f766088a64809edb46a05d29649a9b944da6c:1234"},
		{"33600", "8339009b816d4e4c2a6be3c6e1daac6aca69a7670ecdc583adfca0db17cc8f08ce35d6c759b038ab"},
		{"33650", "e740440e7bd65056a90f1aa4eb00e00308a9f1788866b4eacbd46cfc8032301d4e5b3a9d179be044:95454599772294521162217"},
		{"33660", "345136b13b3a6e52901e2a414efa0cf5fca2fecf8b03279656d3b0f42c30df3006c5ad186494996b:2436077107013929602"},
		{"34800", "$BLAKE2$68b163391b3e779dcddba4e6d8fa03e962c29569b430efa5ba014303358557e1"},
		{"34810", "$BLAKE2$2b51353016a512b60e587bea98d799c2de243468085ca6cd67f983b2e55bfb67:2353288289"},
		{"34820", "$BLAKE2$a4cad0b026ed24adf13fb70ec31d35b02751dcb33354e2c9d20ef3f968748501:3601"},
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
	if got := detectHashTypes(cases[2].target); len(got) != 2 || got[0] != "blake2s" || got[1] != "blake2b256" {
		t.Errorf("256-bit BLAKE2 detection = %v", got)
	}
	if got := detectHashTypes(cases[9].target); len(got) != 2 || got[0] != "blake2b256-pass-salt" || got[1] != "blake2b256-salt-pass" {
		t.Errorf("salted BLAKE2b-256 detection = %v", got)
	}
}

func TestHashcatSeededChecksumVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"10100", "ad61d78c06037cd9:2:4:81533218127174468417660201434054"},
		{"11500", "c762de4a:00000000"},
		{"25700", "b69e7687:05094309"},
		{"34200", "ef3014941bf1102d:837163b2348dfae1"},
		{"34201", "73f8142b4326d36a"},
		{"34211", "73f8142b"},
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

	if got := detectHashTypes(cases[1].target); len(got) != 2 || got[0] != "crc32-hashcat" || got[1] != "murmurhash" {
		t.Errorf("8:8 checksum detection = %v", got)
	}
	if got := detectHashTypes(cases[3].target); len(got) != 1 || got[0] != "murmur64a" {
		t.Errorf("MurmurHash64A detection = %v", got)
	}
}

func TestHashcatAdditionalCompositeVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"32410", "25d509824028a999f4ee851b5de404bb316b78ae8e974874376484018f58520e082747a7ce9f769bcaccb5f63878356c780f602e23393f12b650a6931e4b9338:21881837027919828109608"},
		{"32420", "c1bade2bd4ebc8db841ac6ab3e0a5035a29619e5b1a6135782b77da5d7cfaccee096f3ddb9ee23b9866378cfc2fb19f2c013fed1b7e1fffd18340a4f39238412:789"},
		{"32800", "7b4f60b54472980e922280e225150dfa"},
		{"33100", "866244ca1d318292a6f40b60e03fd29c:72219426709"},
		{"34400", "b7d9a0e57e6e94e8b87996b81ffa64b05d237c58fff1d7a4e4fe2a77"},
		{"34500", "10d302483c927df95abba98d69dcd9608365241d1523a8cc5fcbcedc"},
	}
	for _, tc := range cases {
		ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
		if err != nil || !ok {
			t.Errorf("mode %s: ok=%v err=%v", tc.mode, ok, err)
		}
	}
}

func TestHashcatFurtherCompositeVectors(t *testing.T) {
	cases := []struct {
		mode, target string
	}{
		{"2630", "0127eecea3120e34c8934ba3b72a390a:0"},
		{"3610", "a0ab79f9e2b5a4434d2da61673b56362:1234"},
		{"3910", "250920b3a5e31318806a032a4674df7e:1234"},
		{"4410", "bc8319c0220bff8a0d7f5d703114a725:34659348756345251"},
		{"4420", "34ebbba3e5c98f6253c160eae53da092:6224378456121050285"},
		{"4430", "df0e9ede5b6c7d1f1b47199f86029002:59132809201799180722359939692710461886"},
		{"4510", "9138d472fce6fe50e2a32da4eec4ecdc8860f4d5:hashcat1"},
		{"4710", "53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1"},
		{"5000", "05ac0c544060af48f993f9c3cdf2fc03937ea35b:232725102020"},
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

func TestHashcatPBKDF1Vector(t *testing.T) {
	const target = "PBKDF1:sha1:1000:cGVuZ3VpbmtlZXBlcg==:J4BrIhXDUHNQ9lPPrWKn4V7Of9Y="
	if ok, err := verifyCandidate("hashcat", target, "32900", "", "prefix"); err != nil || !ok {
		t.Fatalf("mode 32900: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyCandidate("wrong", target, "pbkdf1", "", "prefix"); bad {
		t.Fatal("PBKDF1 accepted a wrong password")
	}
	if got := detectHashTypes(target); len(got) != 1 || got[0] != "pbkdf1" {
		t.Fatalf("PBKDF1 detection = %v", got)
	}
	const excessive = "PBKDF1:sha1:100000001:c2FsdA==:MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
	if _, err := verifyCandidate("x", excessive, "32900", "", "prefix"); err == nil {
		t.Fatal("PBKDF1 accepted an excessive iteration count")
	}
	if got := detectHashTypes(excessive); len(got) != 0 {
		t.Fatalf("malformed PBKDF1 detection = %v", got)
	}
}

func TestHashcatBridgeAliases(t *testing.T) {
	want := map[string]string{
		"34000": "argon2", "70000": "argon2", "70100": "scrypt", "70200": "scrypt",
	}
	for mode, canonical := range want {
		if got := canonicalHashType(mode); got != canonical {
			t.Errorf("mode %s = %q, want %q", mode, got, canonical)
		}
	}
}
