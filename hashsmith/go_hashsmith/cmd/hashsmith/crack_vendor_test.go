package main

import "testing"

// PeopleSoft, Episerver and MS-AzureSync vectors for the passphrase
// "hashsmith".  The digests were computed independently with Python's hashlib;
// the MS-AzureSync case starts from Hashsmith's own NT hash, which the NTLM
// tests already pin to a published vector.
func TestVendorFormatVectors(t *testing.T) {
	const pass = "hashsmith"

	t.Run("PeopleSoft", func(t *testing.T) {
		h := "2uCd2T/LX41DjVEwFi9KoRahpX4="
		if ok, err := verifyPeopleSoft(h, pass); err != nil || !ok {
			t.Errorf("verify failed: ok=%v err=%v", ok, err)
		}
		if bad, _ := verifyPeopleSoft(h, "wrong"); bad {
			t.Error("accepted a wrong passphrase")
		}
		if !isPeopleSoft(h) {
			t.Error("isPeopleSoft rejected a well-formed hash")
		}
		if ok, err := verifyCandidate(pass, h, "133", "", "prefix"); err != nil || !ok {
			t.Errorf("Hashcat mode 133 did not reach peoplesoft: ok=%v err=%v", ok, err)
		}
	})

	t.Run("Episerver", func(t *testing.T) {
		v0 := "$episerver$*0*MjEwNDE5NzcyNg==*aKdKfczl/7l2BtCK8vtVQ0sZoMQ="
		v1 := "$episerver$*1*MjEwNDE5NzcyNg==*2AS3xW1AuqiQczMED1VAxsUwuUzlgR0pRikE3r09tKI="
		for _, h := range []string{v0, v1} {
			if ok, err := verifyEpiserver(h, pass); err != nil || !ok {
				t.Errorf("%s: verify failed: ok=%v err=%v", h[:16], ok, err)
			}
			if bad, _ := verifyEpiserver(h, "wrong"); bad {
				t.Errorf("%s: accepted a wrong passphrase", h[:16])
			}
			if got := detectHashTypes(h); len(got) != 1 || got[0] != "episerver" {
				t.Errorf("detectHashTypes = %v, want [episerver]", got)
			}
		}
		// The version field must actually select the digest: a SHA-1 record
		// relabelled as SHA-256 has the wrong digest length and must be refused.
		swapped := "$episerver$*1*MjEwNDE5NzcyNg==*aKdKfczl/7l2BtCK8vtVQ0sZoMQ="
		if _, err := verifyEpiserver(swapped, pass); err == nil {
			t.Error("accepted a SHA-1 digest under the SHA-256 version")
		}
		for _, mode := range []string{"141", "1441"} {
			h := v0
			if mode == "1441" {
				h = v1
			}
			if ok, err := verifyCandidate(pass, h, mode, "", "prefix"); err != nil || !ok {
				t.Errorf("Hashcat mode %s did not reach episerver: ok=%v err=%v", mode, ok, err)
			}
		}
	})

	t.Run("AzureSync", func(t *testing.T) {
		h := "v1;PPH1_MD4,10920c8b4d1f2a3b,100,112751a58105737a61461ec5c0ea567c068b154e5e89e723b1f2b80997557f16"
		if ok, err := verifyAzureSync(h, pass); err != nil || !ok {
			t.Errorf("verify failed: ok=%v err=%v", ok, err)
		}
		if bad, _ := verifyAzureSync(h, "wrong"); bad {
			t.Error("accepted a wrong passphrase")
		}
		if got := detectHashTypes(h); len(got) != 1 || got[0] != "azuresync" {
			t.Errorf("detectHashTypes = %v, want [azuresync]", got)
		}
		if ok, err := verifyCandidate(pass, h, "12800", "", "prefix"); err != nil || !ok {
			t.Errorf("Hashcat mode 12800 did not reach azuresync: ok=%v err=%v", ok, err)
		}
		// The iteration count must be honoured, not assumed.
		wrongIter := "v1;PPH1_MD4,10920c8b4d1f2a3b,101,112751a58105737a61461ec5c0ea567c068b154e5e89e723b1f2b80997557f16"
		if bad, _ := verifyAzureSync(wrongIter, pass); bad {
			t.Error("ignored the iteration count")
		}
	})
}

func TestVendorFormatsRejectMalformedRecords(t *testing.T) {
	cases := []struct {
		name   string
		verify func(string, string) (bool, error)
		bad    []string
	}{
		{"peoplesoft", verifyPeopleSoft, []string{"not base64!!", "c2hvcnQ=", ""}},
		{"episerver", verifyEpiserver, []string{
			"$episerver$*2*MjEwNDE5NzcyNg==*aKdKfczl/7l2BtCK8vtVQ0sZoMQ=",
			"$episerver$*0*MjEwNDE5NzcyNg==", "$episerver$*0**aKdKfczl/7l2BtCK8vtVQ0sZoMQ=",
			"nonsense",
		}},
		{"azuresync", verifyAzureSync, []string{
			"v1;PPH1_MD4,zz,100,ab", "v1;PPH1_MD4,10920c8b,0,abcd",
			"v1;PPH1_MD4,10920c8b,100", "v2;PPH1_MD4,10920c8b,100,abcd",
		}},
	}
	for _, c := range cases {
		for _, bad := range c.bad {
			if ok, err := c.verify(bad, "pw"); ok || err == nil {
				t.Errorf("%s: verify(%q) = %v, %v; want a rejection", c.name, bad, ok, err)
			}
		}
	}
}

// hMailServer keeps the salt inline as the first six characters of the record,
// which is easy to mis-parse as part of the digest.
func TestHMailServerVector(t *testing.T) {
	const record = "aB3xY9f7e20052c00664fe2b773123e52b8cdd393bcb09518b63ea390fe30eefa11688"
	if ok, err := verifyHMailServer(record, "hashsmith"); err != nil || !ok {
		t.Errorf("verify failed: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyHMailServer(record, "wrong"); bad {
		t.Error("accepted a wrong passphrase")
	}
	if ok, err := verifyCandidate("hashsmith", record, "1421", "", "prefix"); err != nil || !ok {
		t.Errorf("Hashcat mode 1421 did not reach hmailserver: ok=%v err=%v", ok, err)
	}
	for _, bad := range []string{
		"aB3xY9f7e20052c00664fe2b773123e52b8cdd393bcb09518b63ea390fe30eefa116",  // short
		"aB3xY9zzzzzzzz00664fe2b773123e52b8cdd393bcb09518b63ea390fe30eefa11688", // digest not hex
	} {
		if ok, err := verifyHMailServer(bad, "hashsmith"); ok || err == nil {
			t.Errorf("verifyHMailServer(%q) = %v, %v; want a rejection", bad, ok, err)
		}
	}
}
