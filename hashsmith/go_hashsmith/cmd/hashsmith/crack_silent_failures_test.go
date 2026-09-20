package main

import "testing"

// Five formats parsed their target, ran the full KDF, and reported the correct
// password as "not found". That is the worst failure a cracker has, because it
// is indistinguishable from an uncrackable password: there is no error, no
// warning, and the exit status is the ordinary "some targets not cracked".
//
// Each case is pinned against hashcat's own published record and password, and
// each also asserts that a wrong candidate is still rejected — a fix that makes
// the right password work by loosening the check would be worse than the bug.
func TestFormatsThatSilentlyReportedNotFound(t *testing.T) {
	cases := []struct {
		mode   string
		verify func(hash, candidate string) (bool, error)
		wrong  string // a candidate that must NOT verify
		was    string
	}{
		{"9500", verifyOffice, "hashcat1",
			"Office 2010 was routed to the ECMA-376 standard scheme; it is agile with SHA-1 and AES-128"},
		{"12800", verifyAzureSync, "hashcat1",
			"the PBKDF2 password is utf16le(UPPERCASE hex of the NT hash), not the raw NT hash"},
		{"13400", verifyKeePass, "hashcat1",
			"the record carries an inline keyfile that the composite key must include"},
		{"29700", verifyKeePassKeyfile,
			"227e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
			"the candidate is the keyfile key in hex and must be decoded before hashing"},
	}
	for _, c := range cases {
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
			bad, err := c.verify(rec, c.wrong)
			if err != nil {
				t.Fatalf("verify (wrong candidate): %v", err)
			}
			if bad {
				t.Errorf("a wrong candidate verified — the check was loosened, not fixed")
			}
		})
	}
}

// Windows Phone 8+ (-m 13800) is a composite construction rather than a
// dedicated verifier, so it is checked through the composite engine. Its salt
// is 128 BINARY bytes carried as 256 hex characters; splicing those characters
// literally hashes the transport encoding instead of the salt.
func TestWindowsPhone8CompositeUsesTheDecodedSalt(t *testing.T) {
	rec, pass := hashcatExampleRecord(t, "13800")
	ok, err := verifyComposite(pass, rec, "sha256-utf16lepass-hexsalt", "")
	if err != nil {
		t.Fatalf("verifyComposite: %v", err)
	}
	if !ok {
		t.Error("hashcat's own -m 13800 password did not verify")
	}
	bad, err := verifyComposite(pass+"x", rec, "sha256-utf16lepass-hexsalt", "")
	if err != nil {
		t.Fatalf("verifyComposite (wrong password): %v", err)
	}
	if bad {
		t.Error("a wrong password verified")
	}
	// The salt-first construction must still exist and must NOT satisfy this
	// record: the two orders are different hashes, and conflating them is what
	// caused the original defect.
	if same, _ := verifyComposite(pass, rec, "sha256-salt-utf16lepass", ""); same {
		t.Error("the salt-first construction also verified; the two orders are not distinguished")
	}
}
