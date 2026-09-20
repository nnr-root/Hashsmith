package main

import "testing"

// BSDi extended DES crypt, with the long-password case that hashcat's own
// published vector cannot reach.
//
// That vector's password is "hashcat" — seven characters — so it never enters
// the loop that folds the ninth character onward into the key. Two different
// readings of that loop passed it. What caught them was generating records
// here and handing them to john, which cracked the short passwords and refused
// every long one; the records below are the ones john then cracked, so they
// are evidence about the format rather than a transcript of this code.
func TestBSDiCryptLongPasswords(t *testing.T) {
	for _, c := range []struct{ password, record string }{
		{"hashcat", "_GW..8841inaTltazRsQ"},                      // hashcat's published example
		{"abcdefgh", "_GW..88415R.1nbfALjo"},                     // exactly 8: still one block
		{"abcdefghi", "_GW..8841BWVjA6kkh/Y"},                    // 9: the fold runs once
		{"correcthorse", "_GW..8841ferW8os/srY"},                 // 12
		{"correct horse battery staple", "_GW..8841Q0CPWkzzIys"}, // 28, with spaces
		{"0123456789abcdefghij", "_GW..88416mVuR9sOsco"},         // 20
	} {
		ok, err := verifyCandidate(c.password, c.record, "bsdicrypt", "", "")
		if err != nil {
			t.Errorf("%q: %v", c.password, err)
			continue
		}
		if !ok {
			t.Errorf("%q did not verify against %s", c.password, c.record)
		}
		// Truncation at eight characters is the classic way to get this
		// wrong, and it shows up as two different passwords sharing a hash.
		if len(c.password) > 8 {
			if ok, _ := verifyCandidate(c.password[:8], c.record, "bsdicrypt", "", ""); ok {
				t.Errorf("%q verifies against a record for %q, so the password is being "+
					"truncated to eight characters", c.password[:8], c.password)
			}
		}
		if ok, _ := verifyCandidate(c.password+"x", c.record, "bsdicrypt", "", ""); ok {
			t.Errorf("a longer password also verified against %s", c.record)
		}
	}
}

// The iteration count is per record, so a record asking for a different number
// of rounds must produce a different answer for the same password. Without
// this, a verifier that ignored the count and always ran 25 rounds — the
// traditional crypt constant — would pass every test above that happens to
// use one count.
func TestBSDiCryptHonoursItsIterationCount(t *testing.T) {
	const password = "hashcat"
	a, err := bsdiCryptRaw(password, "_GW..8841inaTltazRsQ")
	if err != nil {
		t.Fatal(err)
	}
	// "J9.." is a different count with the same salt.
	b, err := bsdiCryptRaw(password, "_J9..8841inaTltazRsQ")
	if err != nil {
		t.Fatal(err)
	}
	if a[9:] == b[9:] {
		t.Error("two records with different iteration counts produced the same result, so the " +
			"count is being ignored")
	}
}

func TestBSDiCryptRejectsMalformedRecords(t *testing.T) {
	for _, bad := range []string{
		"", "_", "_GW..8841", "_GW..8841inaTltazRsQx",
		"GW..8841inaTltazRsQ_", // no leading underscore
		"_GW..8841inaTltazRs!", // not crypt-64
		"rQGjyzsjR/Cr2",        // traditional descrypt, not this
		"_....8841inaTltazRsQ", // zero iterations
	} {
		if _, err := verifyCandidate("hashcat", bad, "bsdicrypt", "", ""); err == nil {
			t.Errorf("malformed record accepted: %q", bad)
		}
	}
}
