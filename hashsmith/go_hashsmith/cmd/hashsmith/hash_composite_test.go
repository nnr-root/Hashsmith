package main

import "testing"

// Every construction, cross-checked against values computed independently with
// Python's hashlib for password "hashsmith" and salt "Zx9".  These pin the
// formula each name claims to implement.
func TestCompositeConstructionVectors(t *testing.T) {
	const pass, salt = "hashsmith", "Zx9"
	cases := []struct{ name, want string }{
		{"md5-salt-md5pass", "b20c905b199b3e72785c8c7708aeddfb"},
		{"md5-md5pass-salt", "209a1ebf02b22c103e1b3896b895ecd2"},
		{"md5-md5passsalt", "9c8f24db072a519a4a29a4b97528a71c"},
		{"md5-md5-md5pass-salt", "2808706c2b0dabd05402334b0c86ccb6"},
		{"md5-salt-pass-salt", "903d7e353140c6e09b6bcf38a574594f"},
		{"md5-salt-md5saltpass", "a5aeb932f0287ad8a1836b0d86afaf72"},
		{"md5-salt-md5passsalt", "2e846cdc2719016d9ee23c059720c4e9"},
		{"md5-md5salt-md5pass", "d9afd016defaf2c9cc7ec7d91b674b09"},
		{"md5-md5salt-pass", "893f3cc8bad70b141e5db30be7d9ba05"},
		{"md5-md5pass-md5salt", "bf02be677a7a78ec04bb7c643a4abec3"},
		{"md5-sha1pass-salt", "963f8f2caff708cada234f70534d424d"},
		{"md5-sha1passsalt", "85dbdfeb8e4e48568943ba1e764cd418"},
		{"md5-sha1saltpass", "db61f6b4d56d22d6d15634316d1eeb73"},
		{"md5-sha1salt-md5pass", "84ae3d9f82d03e46af6bd9c2b5313619"},
		{"md5-salt-sha1saltpass", "1a5145c92871f364197e17bb911e4299"},
		{"md5-md5salt-md5-md5pass", "32392048854f2a3ce10c070da4a944ed"},
		{"md5-salt-pass-md5pass", "e342ff10cd8b9136d57d54dc811bc161"},
		{"sha1-salt-pass-salt", "238ebc97ea594044edf384144bd232bd8701cd9e"},
		{"sha1-sha1pass-salt", "fd7e4e7f0fe37ff2940bb7c79b183f613f9a83f2"},
		{"sha1-salt-sha1pass", "1498106ecd17f9f820d38a7578ba444d33351e54"},
		{"sha1-salt-sha1passsalt", "c33911d143efbca0be646db445728330dc92a237"},
		{"sha1-md5pass-salt", "ec17b6fa8703c4a828ecf11e8813edbda9494eb7"},
		{"sha1-sha1saltpasssalt", "9fc74215928b87ed87b694a801c5e1a9594c744f"},
		{"sha1-salt-sha1saltsha1pass", "50612325df8d5aee7963756f9cf2cad85092a7d2"},
		{"sha256-salt-pass-salt", "e96b01deda9eee797d01383bb9e611f755cdc2f35cbe0778e5d0e69f3a47aafb"},
		{"sha256-sha256pass-salt", "2d2d6fef33075c2eda14616d8d027805727800304fc034c517fb608a75d729ba"},
		{"sha256-salt-sha256pass", "05416de0b63ebcc347527d071f0cf5b2898377d92efe6767c17ac9c7446c8049"},
		{"sha256-sha256passsalt", "7678afe1fffbf3d93874a905e60c9402c52a1179da83c65b0c54ad8509f3fee6"},
		{"sha256-md5pass", "35a6e3fc7293a428a3d6c9019f83e2049e100d1cef5adaebb5000fbaf98ef201"},
		{"sha256-sha256binpass", "1b966ba4c44c4c629ae2494a34812b7caf6ceaf7ba7949623dfa15d5cd3ccf3c"},
		{"sha256-salt-sha256binpass", "847667cc7fb5b4145f5697d76d19a214338cce4bb4a49a1e5419df14e85861d6"},
		{"sha1-md5passsalt", "faf80857fba0c38ee1d1b8320dfd2348aad39238"},
		{"md5-pass-pass", "21bb8f8b1c1d616f63edfa05db64d986"},
		{"md5-md5pass-pass", "c7be174d24a361c6a7d070968ae3ba9e"},
		{"md5-pass-md5pass", "d65f9db8aaadb8808b5d3d80ca9c3038"},
		{"md5-md5binpass", "741f5cad0ba709ad9990a5558c8704e7"},
		{"sha1-sha1binpass", "662c0d7b4cd66ef4e64da9b7b20d247d37a1d7bd"},
		{"sha1-sha1-sha1pass", "9f0ea4b9415ccf2adf31fc8737d7fc47166ce043"},
		{"sha512-pass-pass", "0a466c2b72b0012a14b56761716a12ffc75fdd17bfb19d7f2109d1005c03d4694c5cffeb0f516013b25f6b044a87f430265fafc3a3964e37e178092579500037"},
		{"md5-sha1pass-md5pass-sha1pass", "743aaa6545dc3fec867bd2d9eaed4823"},
		{"md5-salt-md5pass-salt", "45de7cfe6bd006b8eab2849b5fa009e1"},
		{"sha1-salt-md5pass", "cc3faaa528e2e92d41c83f401d398fba38410bac"},
		{"sha256-salt-uppersha1pass", "1a93033337810e3624427730236f76fcd3ecbb91123711401d58b54b8b2b38ec"},
		{"sha256-salt-utf16lepass", "7debd89b3b350568a11e74d36e26b85b7cc395483a273f30e3b67f3e5cfc1ac4"},
		{"sha512-sha512binpass", "67744bf0ad8a06ccc73359acf47a469430958dc95ea59dc92651466fd5708740077b21d59dad321aa61f7feafe2a92c75521745a4ee2fedcc7912b7e3ccf6c67"},
		{"sha512-salt-pass-salt", "71fe7fe5fe55e18f4114bed4d8af3a7855e78945c8f8dcd40cd336724cab12b7498775a6b25336eb3ea0fba679608b7dad70aa1adf5b3dcf3ded5c6c6cf7c613"},
		{"sha512-sha512pass-salt", "654121afbcc26ef1df97a173887424307178b6d9dc9a8d0ea8d2716b77acb16b5ee3404c5add8e7bbc15b40cf2363876983be3fa5067a9e849cd9cfb8b7f6d88"},
		{"sha512-sha512binpass-salt", "95aa0bd4339522b6e80e6f8a93fb48b2cdfacb79ae3fc3b29f1e77bd9513bde263d7429012e654334e0ae74b8ca1c2980cf3aa98f806b5dbfdc7e11ffca03d27"},
		{"whirlpool-salt-pass-salt", "72f3362b7ec1e86666fa1c12ba00029c47f2866d9cabdadb558195a69d18768d9e81c61d82a3f199d5da414b6ead98cdd4109c358a782b2871be0ef604de6a20"},
		{"md5-sha1-md5pass", "0c65d94106b21cf99f518ac02b8cc1a4"},
		{"sha224-sha224pass", "fe984e0537cbb81cbb97e6ae6b3b7b7961bba671507a00a079ee6c2a"},
		{"sha224-sha1pass", "3ad8453bf7856ef0d6ea9056263475a4f2c2b8acbf7078b0ac8e0ce7"},
	}
	if len(cases) != len(compositeConstructions) {
		t.Fatalf("%d constructions declared but %d pinned to a vector",
			len(compositeConstructions), len(cases))
	}
	for _, c := range cases {
		got, err := hashText(pass, c.name, salt, "prefix")
		if err != nil || got != c.want {
			t.Errorf("%s = %q, %v; want %s", c.name, got, err, c.want)
			continue
		}
		// Unsalted constructions carry the bare digest; salted ones are
		// distributed in the hash:salt form.
		target := c.want
		if compositeNeedsSalt(compositeConstructions[c.name]) {
			target += ":" + salt
		}
		if ok, err := verifyCandidate(pass, target, c.name, "", "prefix"); err != nil || !ok {
			t.Errorf("%s hash:salt verify: ok=%v err=%v", c.name, ok, err)
		}
		// The explicit -s form.
		if ok, err := verifyCandidate(pass, c.want, c.name, salt, "prefix"); err != nil || !ok {
			t.Errorf("%s -s verify: ok=%v err=%v", c.name, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", target, c.name, "", "prefix"); bad {
			t.Errorf("%s accepted a wrong password", c.name)
		}
	}
}

// Two constructions reproduce hashes the repo already verifies through
// purpose-written code, which ties the generic evaluator to known-good output.
func TestCompositeMatchesDedicatedImplementations(t *testing.T) {
	const pass = "hashsmith"

	vb := "209a1ebf02b22c103e1b3896b895ecd2:Zx9"
	if ok, err := verifyComposite(pass, vb, "md5-md5pass-salt", ""); err != nil || !ok {
		t.Errorf("composite disagrees with verifyVBulletin: ok=%v err=%v", ok, err)
	}

	rm := "e68c45f4f20e4e1958daa2c1a7ff80ea39f1dd97:3f8b1c2d4e5f6a7b8c9d0e1f2a3b4c5d"
	if ok, err := verifyComposite(pass, rm, "sha1-salt-sha1pass", ""); err != nil || !ok {
		t.Errorf("composite disagrees with verifyRedmine: ok=%v err=%v", ok, err)
	}
}

// A construction that reads the salt must refuse to run without one rather than
// silently hashing the empty string.
func TestCompositeRequiresSalt(t *testing.T) {
	if _, err := hashComposite("pw", "md5-salt-md5pass", ""); err == nil {
		t.Error("salted construction accepted an empty salt")
	}
	if _, err := verifyComposite("pw", "deadbeef", "md5-salt-md5pass", ""); err == nil {
		t.Error("verify accepted a target with no salt to parse")
	}
	// sha256-md5pass and sha256-sha256binpass take no salt at all.
	for _, name := range []string{"sha256-md5pass", "sha256-sha256binpass"} {
		if _, err := hashComposite("pw", name, ""); err != nil {
			t.Errorf("%s should not require a salt: %v", name, err)
		}
	}
}

// Auto-detection must offer the composites for an ambiguous hash:salt target,
// but only behind the cheaper plain concatenations.
func TestCompositesAreOfferedAfterSimpleForms(t *testing.T) {
	got := detectCompatSaltedTypes("209a1ebf02b22c103e1b3896b895ecd2:Zx9")
	if len(got) < 5 {
		t.Fatalf("detectCompatSaltedTypes returned only %v", got)
	}
	for i, want := range []string{"md5-pass-salt", "md5-salt-pass"} {
		if got[i] != want {
			t.Errorf("candidate %d = %q, want %q (simple forms must come first)", i, got[i], want)
		}
	}
	found := false
	for _, name := range got {
		if name == "md5-md5pass-salt" {
			found = true
		}
		if spec, ok := compositeConstructions[name]; ok && spec.algo != "md5" {
			t.Errorf("candidate %q has the wrong digest width for a 32-hex target", name)
		}
	}
	if !found {
		t.Error("md5-md5pass-salt was not offered for a 32-hex hash:salt target")
	}
}

// The Hashcat mode numbers and John dynamic labels must reach these types.
func TestCompositeModeNumbers(t *testing.T) {
	for alias, want := range map[string]string{
		"3710": "md5-salt-md5pass", "3800": "md5-salt-pass-salt",
		"2811": "md5-md5salt-md5pass", "22300": "sha256-salt-pass-salt",
		"hashcat:4900": "sha1-salt-pass-salt", "john:dynamic_8": "md5-salt-md5pass",
		"dynamic_12": "md5-md5salt-md5pass",
	} {
		if got := canonicalHashType(alias); got != want {
			t.Errorf("canonicalHashType(%q) = %q, want %q", alias, got, want)
		}
	}
}
