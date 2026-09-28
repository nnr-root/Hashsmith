package smith

import "testing"

// hashcat's published -m 13600 example.
const winZipPublishedRecord = "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$"

// The $zip2$ record carries an authentication code — ten bytes of HMAC-SHA1
// over the encrypted data — as well as the two-byte password verifier that the
// shorter $zipaes*$ form has room for.
//
// The verifier alone accepts one wrong password in 65,536. Over a
// rockyou-sized run that is several thousand false hits, each one a "cracked"
// password that does not open the archive. The authentication code closes it
// to one in 2^80, so the thing worth testing is not that the record parses but
// that the code is CHECKED — a verifier-only implementation passes every
// happy-path test there is.
func TestWinZipAuthenticationCodeIsChecked(t *testing.T) {
	const password = "hashcat"

	ok, err := verifyCandidate(password, winZipPublishedRecord, "winzip", "", "")
	if err != nil {
		t.Fatalf("published record rejected: %v", err)
	}
	if !ok {
		t.Fatal("the published -m 13600 record did not crack with its own password")
	}

	// Corrupt only the authentication code. The verifier still matches, so a
	// verifier-only implementation still says yes here — which is exactly the
	// bug this test exists to catch.
	corrupt := "$zip2$*0*1*0*0675369741458183*5dc5*0**00000000000000000000*$/zip2$"
	ok, err = verifyCandidate(password, corrupt, "winzip", "", "")
	if err != nil {
		t.Fatalf("record with a corrupt authentication code errored: %v", err)
	}
	if ok {
		t.Error("a record whose authentication code is wrong still cracked, so only the " +
			"two-byte verifier is being checked and one wrong password in 65,536 will be " +
			"reported as correct")
	}

	if ok, err := verifyCandidate("definitely-not-it-9137", winZipPublishedRecord, "winzip", "", ""); err != nil || ok {
		t.Errorf("a wrong password was accepted (ok=%v err=%v)", ok, err)
	}
}

// The key size lives in a field rather than in the type tag, and the salt
// length is tied to it. A record whose two disagree is malformed, and saying so
// is better than deriving a key from the wrong number of salt bytes and
// reporting "not found" for a password that is right.
func TestWinZipRejectsMismatchedSaltLength(t *testing.T) {
	// Mode 3 is AES-256, which takes a 16-byte salt; this record carries the
	// 8-byte salt of an AES-128 archive.
	mismatched := "$zip2$*0*3*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$"
	if _, err := verifyCandidate("hashcat", mismatched, "winzip", "", ""); err == nil {
		t.Error("a record declaring AES-256 with an AES-128 salt was accepted; it should be " +
			"reported as malformed rather than silently cracked against the wrong key size")
	}

	for _, bad := range []string{
		"$zip2$*0*9*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$", // no such mode
		"$zip2$*0*1*0*zzzz*5dc5*0**36b85538918416712640*$/zip2$",             // salt not hex
		"$zip2$*0*1*0*0675369741458183*5d*0**36b85538918416712640*$/zip2$",   // verifier too short
		"$zip2$*0*1*0*0675369741458183*5dc5*0**36b8*$/zip2$",                 // authcode too short
		"$zip2$*0*1*0*0675369741458183*$/zip2$",                              // too few fields
	} {
		if _, err := verifyCandidate("hashcat", bad, "winzip", "", ""); err == nil {
			t.Errorf("malformed record accepted: %s", bad)
		}
	}
}
