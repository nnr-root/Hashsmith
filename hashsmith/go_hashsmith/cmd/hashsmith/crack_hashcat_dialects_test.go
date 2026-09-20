package main

import "testing"

// Several formats are spelled one way by John (and by Hashsmith's own
// extractors) and another way by hashcat. Each case below is a record shape
// that Hashsmith rejected outright until the dialect was accepted; the
// expectations come from hashcat's own published example records, which are
// checked into testdata/hashcat_example_hashes.tsv.
func TestHashcatRecordDialects(t *testing.T) {
	cases := []struct {
		mode   string
		verify func(hash, candidate string) (bool, error)
		note   string
	}{
		{"112", verifyOracle11g, "hashcat separates the 40-hex SHA-1 from the 20-hex salt with a colon"},
		{"22", verifyJuniper, "hashcat spells a NetScreen record hash:user, John spells it user$hash"},
		{"141", verifyEpiserver, "hashcat omits base64 padding"},
		{"1441", verifyEpiserver, "hashcat omits base64 padding (SHA-256 variant)"},
		{"13300", verifyAxCryptSHA1, "hashcat truncates the in-memory SHA-1 to 16 bytes"},
		{"24100", verifyMongoDB, "hashcat uses '*' separators and always means the ServerKey"},
		{"24200", verifyMongoDB, "hashcat uses '*' separators and always means the ServerKey"},
		{"23", verifySkype, "Skype is md5(user + \"\\nskyper\\n\" + pass), not the generic md5(salt+pass)"},
		{"131", verifyMSSQL2000, "SQL Server 2000 keeps two digests; -m 131 cracks the case-insensitive one"},
	}
	for _, c := range cases {
		c := c
		t.Run("m"+c.mode, func(t *testing.T) {
			rec, pass := hashcatExampleRecord(t, c.mode)
			ok, err := c.verify(rec, pass)
			if err != nil {
				t.Fatalf("%s\n  verify(%s): %v", c.note, c.mode, err)
			}
			if !ok {
				t.Errorf("%s\n  hashcat's own password %q did not verify", c.note, pass)
			}
			// A near-miss must still be rejected: accepting the record shape
			// must not have loosened the comparison itself.
			// MSSQL 2000's case-insensitive digest is correct up to case by
			// design, so the near-miss must differ by more than case.
			bad, err := c.verify(rec, pass+"x")
			if err != nil {
				t.Fatalf("verify (wrong password): %v", err)
			}
			if bad {
				t.Error("a wrong password verified")
			}
		})
	}
}
