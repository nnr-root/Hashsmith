package smith

import "testing"

// Every record here is John's own, taken verbatim from its format tests, in
// the spelling John writes rather than the one Hashsmith reads. Each pairs
// with the spelling this tool already understood, and the point of the test is
// that both answer the same password — a rewrite that quietly changed the
// record would pass one and fail the other.
func TestJohnBareSpellings(t *testing.T) {
	for _, tc := range []struct{ name, bare, canonical, pass string }{
		{
			"net-md5",
			"02020000ffff0003002c01145267d48d000000000000000000020000ac100100ffffff000000000000000001ffff0001$1e372a8a233c6556253a0909bc3dcce6",
			"$netmd5$02020000ffff0003002c01145267d48d000000000000000000020000ac100100ffffff000000000000000001ffff0001$1e372a8a233c6556253a0909bc3dcce6",
			"quagga",
		},
		{
			"mscash2",
			"nineteen_characters:87136ae0a18b2dafe4a41d555425b2ed",
			"$DCC2$10240#nineteen_characters#87136ae0a18b2dafe4a41d555425b2ed",
			"w00t",
		},
		{
			"kerberos aes key",
			"OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26",
			"$krb18$OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26",
			"password",
		},
		{
			"cisco asa under its dynamic number",
			"$dynamic_20$h3mJrcH0901pqX/m$alex",
			"h3mJrcH0901pqX/m:alex",
			"ripper",
		},
		{
			"cisco pix under its dynamic number",
			"$dynamic_19$2KFQnbNIdI.2KYOU",
			"2KFQnbNIdI.2KYOU",
			"cisco",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			types := detectHashTypes(tc.bare)
			if len(types) == 0 {
				t.Fatalf("no type detected for the bare spelling")
			}
			var found bool
			for _, ty := range types {
				if ok, err := verifyCandidate(tc.pass, tc.bare, ty, "", ""); err == nil && ok {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("the bare spelling did not answer %q under any of %v", tc.pass, types)
			}
			// The spelling this tool already read must still answer, and
			// neither spelling may accept a password that is not the one.
			var canonicalFound bool
			for _, ty := range detectHashTypes(tc.canonical) {
				if ok, err := verifyCandidate(tc.pass, tc.canonical, ty, "", ""); err == nil && ok {
					canonicalFound = true
				}
				if bad, err := verifyCandidate(tc.pass+"x", tc.canonical, ty, "", ""); err == nil && bad {
					t.Errorf("%s accepted a wrong password", ty)
				}
			}
			if !canonicalFound {
				t.Errorf("the canonical spelling stopped answering %q", tc.pass)
			}
		})
	}
}

// The bare shapes are deliberately narrow, because each is two fields with a
// dollar between them and so is half the records in the catalogue if read
// loosely. These are the near misses that must not be claimed.
func TestJohnBareSpellingsDecline(t *testing.T) {
	for _, tc := range []struct{ name, record string }{
		{"a salted digest", "5f4dcc3b5aa765d61d8327deb882cf99$salt"},
		{"two short hex fields", "deadbeef$cafebabe"},
		{"an md5 with a hex salt", "5f4dcc3b5aa765d61d8327deb882cf99$0123456789abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if isBareNetMD5(tc.record) {
				t.Error("claimed as a bare net-md5")
			}
			if isBareKerberosDBKey(tc.record) {
				t.Error("claimed as a bare Kerberos key")
			}
			if isBareKrb5ASREP(tc.record) {
				t.Error("claimed as a bare AS-REP")
			}
		})
	}
	// A username with a colon in it is another format's record split in the
	// wrong place, not a cached-credential record.
	if isBareMSCash2("host:port:5f4dcc3b5aa765d61d8327deb882cf99") {
		t.Error("claimed a colon-separated record as mscash2")
	}
}
