package main

import "testing"

const ethereumPresaleVector = "$ethereum$w*e94a8e49deac2d62206bf9bfb7d2aaea7eb06c1a378cfc1ac056cc599a569793c0ecc40e6a0c242dee2812f06b644d70f43331b1fa2ce4bd6cbb9f62dd25b443235bdb4c1ffb222084c9ded8c719624b338f17e0fd827b34d79801298ac75f74ed97ae16f72fccecf862d09a03498b1b8bd1d984fc43dd507ede5d4b6223a582352386407266b66c671077eefc1e07b5f42508bf926ab5616658c984968d8eec25c9d5197a4a30eed54c161595c3b4d558b17ab8a75ccca72b3d949919d197158ea5cfbc43ac7dd73cf77807dc2c8fe4ef1e942ccd11ec24fe8a410d48ef4b8a35c93ecf1a21c51a51a08f3225fbdcc338b1e7fdafd7d94b82a81d88c2e9a429acc3f8a5974eafb7af8c912597eb6fdcd80578bd12efddd99de47b44e7c8f6c38f2af3116b08796172eda89422e9ea9b99c7f98a7e331aeb4bb1b06f611e95082b629332c31dbcfd878aed77d300c9ed5c74af9cd6f5a8c4a261dd124317fb790a04481d93aec160af4ad8ec84c04d943a869f65f07f5ccf8295dc1c876f30408eac77f62192cbb25842470b4a5bdb4c8096f56da7e9ed05c21f61b94c54ef1c2e9e417cce627521a40a99e357dd9b7a7149041d589cbacbe0302db57ddc983b9a6d79ce3f2e9ae8ad45fa40b934ed6b36379b780549ae7553dbb1cab238138c05743d0103335325bd90e27d8ae1ea219eb8905503c5ad54fa12d22e9a7d296eee07c8a7b5041b8d56b8af290274d01eb0e4ad174eb26b23b5e9fb46ff7f88398e6266052292acb36554ccb9c2c03139fe72d3f5d30bd5d10bd79d7cb48d2ab24187d8efc3750d5a24980fb12122591455d14e75421a2074599f1cc9fdfc8f498c92ad8b904d3c4307f80c46921d8128*f3abede76ac15228f1b161dd9660bb9094e81b1b*d201ccd492c284484c7824c4d37b1593"

func TestHashcatWalletExpansionPublishedVectors(t *testing.T) {
	tests := []struct {
		mode, password, target string
	}{
		{"16300", "hashcat", ethereumPresaleVector},
		{"16800", "hashcat!", "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4:ed487162465a774bfba60eb603a39f3a"},
		{"16801", "5b13d4babb3714ccc62c9f71864bc984efd6a55f237c7a87fc2151e1ca658a9d", "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4"},
		{"22400", "hashcat", "$aescrypt$1*efc648908ca7ec727f37f3316dfd885c*eff5c87a35545406a57b56de57bd0554*3a66401271aec08cbd10cf2070332214093a33f36bd0dced4a4bb09fab817184*6a3c49fea0cafb19190dc4bdadb787e73b1df244c51780beef912598bd3bdf7e"},
		{"22500", "hashcat", "$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de"},
		{"29600", "hashcat", "67445496c838e96c1424a8dae4b146f0fc247c8c34ef33feffeb1e4412018512wZGtBMeN84XZE2LoOKwTGvA4Ee4m7PR1lDGIdWUV6OSUZKRiKFx9tlrnZLt8r8OfOzbwUS2a2Uo+nrrP6F85fh4eHstwPJw0KwzHWB8br58="},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate(wrongPassword(tc.password), tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatIKECompatibilityAliases(t *testing.T) {
	for mode := range map[string]bool{"5300": true, "5400": true} {
		if got := canonicalHashType(mode); got != "ike" {
			t.Errorf("canonicalHashType(%s) = %q, want ike", mode, got)
		}
	}
}

func TestHashcatWalletExpansionRejectsMalformedRecords(t *testing.T) {
	tests := map[string]string{
		"16300": "$ethereum$w*bad",
		"16800": "bad:record",
		"16801": "bad:record",
		"22400": "$aescrypt$1*bad",
		"22500": "$multibit$1*bad",
		"29600": "not-a-terra-wallet",
	}
	for mode, target := range tests {
		if _, err := verifyCandidate("hashcat", target, mode, "", "prefix"); err == nil {
			t.Errorf("mode %s accepted malformed record %q", mode, target)
		}
	}
}

func TestHashcatWalletExpansionAutoDetection(t *testing.T) {
	tests := map[string]string{
		"2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4:ed487162465a774bfba60eb603a39f3a": "wpa-pmkid",
		"2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4":                                  "wpa-pmk",
		ethereumPresaleVector: "ethereum-presale",
		"$aescrypt$1*efc648908ca7ec727f37f3316dfd885c*eff5c87a35545406a57b56de57bd0554*3a66401271aec08cbd10cf2070332214093a33f36bd0dced4a4bb09fab817184*6a3c49fea0cafb19190dc4bdadb787e73b1df244c51780beef912598bd3bdf7e": "aescrypt",
		"$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de":                                                                                                                   "multibit-key",
		"67445496c838e96c1424a8dae4b146f0fc247c8c34ef33feffeb1e4412018512wZGtBMeN84XZE2LoOKwTGvA4Ee4m7PR1lDGIdWUV6OSUZKRiKFx9tlrnZLt8r8OfOzbwUS2a2Uo+nrrP6F85fh4eHstwPJw0KwzHWB8br58=":                                    "terra-wallet",
	}
	for target, want := range tests {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detectHashTypes(%q) = %v, want [%s]", target, got, want)
		}
	}
}
