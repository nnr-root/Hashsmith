package main

import (
	"strings"
	"testing"
)

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

// A verifier must error only when the TARGET is malformed. A candidate that
// cannot possibly be the answer — the wrong length, the wrong alphabet — is an
// ordinary negative, because a wordlist is expected to contain entries that do
// not fit. Returning an error for one aborts the entire run on the first such
// entry, which is how these modes rejected every target outright.
//
// verifyWPAPMKID already drew the line this way; these now match it.
func TestWrongShapedCandidateIsANegativeNotAnError(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		verify   func(hash, candidate string) (bool, error)
		unusable string
		why      string
	}{
		{"Skip32", "14900", verifySkip32, "short", "Skip32 keys are exactly 10 bytes"},
		{"NetNTLMv2-NT", "27100", verifyNetNTLMv2NT, "not-an-nt-hash", "candidates are 32-hex NT hashes"},
		{"SNMPv3", "25000", verifySNMPv3, "short", "SNMPv3 localized keys need at least 8 characters"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			rec, pass := hashcatExampleRecord(t, c.mode)
			// The unusable candidate must not raise an error.
			if _, err := c.verify(rec, c.unusable); err != nil {
				t.Errorf("a candidate that cannot fit raised an error (%s): %v", c.why, err)
			}
			// And the real one must still be found.
			ok, err := c.verify(rec, pass)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Error("hashcat's own password did not verify")
			}
		})
	}
	// A malformed RECORD must still be an error — that is a usage problem.
	if _, err := verifyNetNTLMv2NT("user::domain:bad", "not-an-nt-hash"); err == nil {
		t.Error("a malformed NetNTLMv2 record was accepted")
	}
	if _, err := verifySkip32("not-a-record", "0123456789"); err == nil {
		t.Error("a malformed Skip32 record was accepted")
	}
}

// Formats whose hashcat spelling differs from the one Hashsmith's own
// extractors emit. Both must work; neither may displace the other.
func TestBothSpellingsCoexist(t *testing.T) {
	// PostgreSQL: hashcat writes <md5>:<username>, PostgreSQL stores md5<hex>
	// and takes the username through -s.
	rec, pass := hashcatExampleRecord(t, "12")
	if ok, err := verifyCandidate(pass, rec, "postgres", "", "prefix"); err != nil || !ok {
		t.Errorf("hashcat's -m 12 spelling: ok=%v err=%v", ok, err)
	}
	i := len(rec) - len("27032153220030464358344758762807") - 1
	stored, user := "md5"+rec[:i], rec[i+1:]
	if ok, err := verifyCandidate(pass, stored, "postgres", user, "prefix"); err != nil || !ok {
		t.Errorf("PostgreSQL's own stored spelling: ok=%v err=%v", ok, err)
	}
}

// Werkzeug before 2.3 wrote "<digest>$<salt>$<hmac>" with no iteration count.
// Those methods were rejected as unsupported, so every -m 30000 and -m 30120
// target failed at parse time.
func TestWerkzeugLegacyHMACMethods(t *testing.T) {
	for _, mode := range []string{"30000", "30120"} {
		mode := mode
		t.Run("m"+mode, func(t *testing.T) {
			rec, pass := hashcatExampleRecord(t, mode)
			ok, err := verifyWerkzeug(rec, pass)
			if err != nil {
				t.Fatalf("verifyWerkzeug: %v", err)
			}
			if !ok {
				t.Error("hashcat's own password did not verify")
			}
			if bad, _ := verifyWerkzeug(rec, pass+"x"); bad {
				t.Error("a wrong password verified")
			}
		})
	}
	// The modern methods must be untouched.
	const modern = "pbkdf2:sha256:260000$salt$" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := parseWerkzeugHash(modern); err != nil {
		t.Errorf("pbkdf2 method broke: %v", err)
	}
	if _, err := parseWerkzeugHash("nonsense$salt$0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("an unknown method was accepted")
	}
}

// Records whose field order or field count differs between the tools.
func TestRecordShapeVariants(t *testing.T) {
	for _, c := range []struct {
		mode   string
		verify func(hash, candidate string) (bool, error)
		was    string
	}{
		{"16900", verifyAnsible,
			"an Ansible Vault file stores salt, HMAC, ciphertext; john and hashcat both reorder to salt, ciphertext, HMAC"},
		{"23400", verifyBitwarden,
			"hashcat carries the second PBKDF2 round count in a fifth field; the four-field form leaves it implicit at 1"},
		{"12700", verifyBlockchain,
			"the original wallet record is $blockchain$<len>$<data> with the iteration count implicit at 10"},
	} {
		c := c
		t.Run("m"+c.mode, func(t *testing.T) {
			rec, pass := hashcatExampleRecord(t, c.mode)
			ok, err := c.verify(rec, pass)
			if err != nil {
				t.Fatalf("%s\n  verify: %v", c.was, err)
			}
			if !ok {
				t.Errorf("%s\n  hashcat's own password did not verify", c.was)
			}
			if bad, _ := c.verify(rec, pass+"x"); bad {
				t.Error("a wrong password verified")
			}
		})
	}
}

// The older Ansible spelling must keep working: widening a parser to accept a
// second field order must not drop the first. The HMAC's fixed 32-byte length
// is what tells them apart.
func TestAnsibleReadsBothFieldOrders(t *testing.T) {
	rec, pass := hashcatExampleRecord(t, "16900")
	f := strings.Split(rec[len("$ansible$"):], "*")
	if len(f) != 5 {
		t.Fatalf("expected 5 fields, got %d", len(f))
	}
	legacy := "$ansible$" + f[0] + "*" + f[1] + "*" + f[2] + "*" + f[4] + "*" + f[3]
	ok, err := verifyAnsible(legacy, pass)
	if err != nil {
		t.Fatalf("legacy order: %v", err)
	}
	if !ok {
		t.Error("the pre-existing salt*hmac*ciphertext order stopped working")
	}
}

// Bitwarden's four-field spelling leaves the second round count implicit at 1
// and must keep working alongside hashcat's explicit five-field one.
func TestBitwardenReadsBothFieldCounts(t *testing.T) {
	rec, pass := hashcatExampleRecord(t, "23400")
	f := strings.Split(rec[len("$bitwarden$"):], "*")
	if len(f) != 5 {
		t.Fatalf("expected 5 fields, got %d", len(f))
	}
	// The five-field record states 2 rounds, so the four-field reading of the
	// same fields (which assumes 1) must NOT verify — that is the whole point
	// of the field existing.
	four := "$bitwarden$" + f[0] + "*" + f[1] + "*" + f[3] + "*" + f[4]
	if ok, _ := verifyBitwarden(four, pass); ok {
		t.Error("the four-field reading verified a record that specifies 2 rounds")
	}
	if _, err := verifyBitwarden(four, pass); err != nil {
		t.Errorf("the four-field spelling should still parse: %v", err)
	}
}
