package main

import "testing"

func TestHashcatCompositeRecordBatchVectors(t *testing.T) {
	cases := []struct {
		mode, typ, target string
	}{
		{"19300", "sha1-salt1-pass-salt2", "630d2e918ab98e5fad9c61c0e4697654c4c16d73:18463812876898603420835420139870031762867:4449516425193605979760642927684590668549584534278112685644182848763890902699756869283142014018311837025441092624864168514500447147373198033271040848851687108629922695275682773136540885737874252666804716579965812709728589952868736177317883550827482248620334"},
		{"20720", "sha256-salt-sha256pass", "bae9edada8358fcebcd811f7d362f46277fb9d488379869fba65d79701d48b8b:869dc2ed80187919"},
		{"20730", "sha256-sha256passsalt", "ad66bdc0841d7e08d96c03de271ce14e77de078746b535adbf9d4b6ccbf2a517:7218532375810603"},
		{"21100", "sha1-md5passsalt", "aade80a61c6e3cd3cac614f47c1991e0a87dd028:6"},
		{"21310", "md5-salt1-sha1salt2pass", "dc91b5a658ef4b7d859e90742f340e24:708237:d270e9eea5802e346bcaa9b229f37766"},
		{"21420", "sha256-salt-sha256binpass", "5934ea4d670c13a71155faba42056b2525f71bdc9215d31108990c11bf3d98e3:9269771356270099311432765354522635185291064175409115041569"},
		{"21900", "md5-triple-passsalt-dual", "2c749af6c65cf3e82e5837e3056727f5:59331674906582121215362940957615121466283616005471:17254656838978443692786064919357750120910718779182716907569266"},
		{"27200", "rails-restful-auth-one-round", "3999d08db95797891ec77f07223ca81bf43e1be2:5dcc47b04c49d3c8e1b9e4ec367fddeed21b7b85"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			if ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix"); err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong-password", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestHashcatCompositeRecordBatchDetection(t *testing.T) {
	cases := []struct {
		target, want string
	}{
		{"630d2e918ab98e5fad9c61c0e4697654c4c16d73:salt-one:salt-two", "sha1-salt1-pass-salt2"},
		{"dc91b5a658ef4b7d859e90742f340e24:salt-one:salt-two", "md5-salt1-sha1salt2pass"},
		{"3999d08db95797891ec77f07223ca81bf43e1be2:5dcc47b04c49d3c8e1b9e4ec367fddeed21b7b85", "rails-restful-auth-one-round"},
		{"bae9edada8358fcebcd811f7d362f46277fb9d488379869fba65d79701d48b8b:salt", "sha256-salt-sha256pass"},
	}
	for _, tc := range cases {
		got := detectHashTypes(tc.target)
		found := false
		for _, candidate := range got {
			if candidate == tc.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("detection = %v, missing %s", got, tc.want)
		}
	}
}

func TestHashcatCompositeRecordBatchMalformedInputs(t *testing.T) {
	for typ, target := range map[string]string{
		"sha1-salt1-pass-salt2":        "bad:one:two",
		"md5-salt1-sha1salt2pass":      "bad:one:two",
		"md5-triple-passsalt-dual":     "bad:one:two",
		"rails-restful-auth-one-round": "bad:salt",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
