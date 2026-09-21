package main

import "testing"

// TestEncodingGuessDoesNotOutrankAHashMatch pins the rule that a crack target
// which already reads as a hash is never rewritten as an encoded digest.
//
// This completes defect F. That fix stopped an explicit -t from being
// overruled by the normalizer, but left auto-detection — the far more common
// path — taking the encoding reading instead of the hash one.
//
// The case that motivated it: a descrypt hash is thirteen characters from the
// crypt-64 alphabet, which is also valid z-base-32 and decodes to eight bytes
// — the length of a half-MD5. crack used to take that reading and try
// mysql323, cisco-pix and half-md5, never descrypt, while identify on the same
// input reported descrypt correctly.
func TestEncodingGuessDoesNotOutrankAHashMatch(t *testing.T) {
	// Every one of these is a real hash that normalizeHashInput alone would
	// happily reinterpret as some encoding.
	for _, tc := range []struct{ name, target string }{
		{"john descrypt vector", "CCNf8Sbh3HDfQ"},
		{"john descrypt vector with a dot", "CC4rMpbg9AMZ."},
		// The record from defect F, which was fixed only for the explicit -t
		// path; auto-detection kept rewriting it until this rule landed.
		{"hashcat descrypt record", "24leDr0hHfb3A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, enc := normalizeHashInput(tc.target); enc == "" {
				t.Skipf("normalizeHashInput no longer rewrites %q; the guard is moot for it", tc.target)
			}
			resolved, enc := resolveCrackTarget(tc.target, "")
			if enc != "" || resolved != tc.target {
				t.Fatalf("crack would rewrite %q as %s (%q); a hash match must win",
					tc.target, enc, resolved)
			}
			if got := detectHashTypes(tc.target); len(got) == 0 {
				t.Fatalf("%q is no longer detected as any hash type", tc.target)
			}
		})
	}
}

// TestEncodingGuessStillAppliesWithNoHashMatch keeps the feature the rule
// above narrows: an encoded digest that nothing recognises is still decoded.
func TestEncodingGuessStillAppliesWithNoHashMatch(t *testing.T) {
	// Base64 of the 16-byte MD5 of "abc" — no hash type claims this spelling.
	const encoded = "kAFQmDzST7DWlj99KOF/cg=="
	resolved, enc := resolveCrackTarget(encoded, "")
	if enc == "" {
		t.Fatalf("expected %q to be normalized, got it unchanged", encoded)
	}
	if resolved != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("normalized to %q, want the MD5 of \"abc\"", resolved)
	}
}

// TestExplicitTypeStillSuppressesNormalization re-checks defect F's original
// guarantee through the new entry point; TestExplicitTypeSuppressesNormalization
// in phase0_input_test.go covers shouldNormalizeTarget directly.
func TestExplicitTypeStillSuppressesNormalization(t *testing.T) {
	const encoded = "kAFQmDzST7DWlj99KOF/cg=="
	if resolved, enc := resolveCrackTarget(encoded, "md5"); enc != "" || resolved != encoded {
		t.Fatalf("explicit -t was overridden: %q %q", resolved, enc)
	}
}

// TestArgon2dVectors covers the PHC variant x/crypto does not provide. These
// are John the Ripper's own argon2 test vectors; before this, identify named
// "argon2" for them and crack then refused every one.
func TestArgon2dVectors(t *testing.T) {
	for _, tc := range []struct{ encoded, password string }{
		{"$argon2d$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$w9w3s5/zV8+PcAZlJhnTCOE+vBkZssmZf6jOq3dKv50", "password"},
		{"$argon2i$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$N59QwnpxDQZRj1/cO6bqm408dD6Z2Z9LKYpwFJSPVKA", "password"},
		{"$argon2d$v=19$m=4096,t=3,p=1$c2hvcnRfc2FsdA$zMrTcOAOUje6UqObRVh84Pe1K6gumcDqqGzRM0ILzYmj", "sacrificed"},
		{"$argon2i$v=19$m=4096,t=3,p=1$c2hvcnRfc2FsdA$1l4kAwUdAApoCbFH7ghBEf7bsdrOQzE4axIJ3PV0Ncrd", "sacrificed"},
		{"$argon2d$v=19$m=16384,t=3,p=1$c2hvcnRfc2FsdA$TLSTPihIo+5F67Y1vJdfWdB9", "blessed_dead"},
		{"$argon2i$v=19$m=16384,t=3,p=1$c2hvcnRfc2FsdA$vvjDVog22A5x9eljmB+2yC8y", "blessed_dead"},
		{"$argon2d$v=19$m=16384,t=4,p=3$YW5vdGhlcl9zYWx0$yw93eMxC8REPAwbQ0e/q43jR9+RI9HI/DHP75uzm7tQfjU734oaI3dzcMWjYjHzVQD+J4+MG+7oyD8dN/PtnmPCZs+UZ67E+rkXJ/wTvY4WgXgAdGtJRrAGxhy4rD7d5G+dCpqhrog", "death_dying"},
		{"$argon2i$v=19$m=16384,t=4,p=3$YW5vdGhlcl9zYWx0$K7unxwO5aeuZCpnIJ06FMCRKod3eRg8oIRzQrK3E6mGbyqlTvvl47jeDWq/5drF1COJkEF9Ty7FWXJZHa+vqlf2YZGp/4qSlAvKmdtJ/6JZU32iQItzMRwcfujHE+PBjbL5uz4966A", "death_dying"},
	} {
		if !verifyArgon2(tc.encoded, tc.password) {
			t.Errorf("verifyArgon2 rejected the correct password for %.32s...", tc.encoded)
		}
		if verifyArgon2(tc.encoded, tc.password+"x") {
			t.Errorf("verifyArgon2 accepted a wrong password for %.32s...", tc.encoded)
		}
	}
}

// TestJohnEnvelopesReachTheRightVerifier checks the two halves of the envelope
// mechanism together: that John's spelling resolves to the intended type, and
// that the verifier for that type then sees a payload it accepts.
func TestJohnEnvelopesReachTheRightVerifier(t *testing.T) {
	for _, tc := range []struct{ record, typ, password string }{
		{"$md2$ab4f496bfb2a530b219ff33031fe06b0", "md2", "message digest"},
		{"$LM$a9c604d244c4e99d", "lm", "aaaaaa"},
	} {
		types := detectHashTypes(tc.record)
		if !containsString(types, tc.typ) {
			t.Errorf("detectHashTypes(%q) = %v, want it to include %q", tc.record, types, tc.typ)
			continue
		}
		ok, err := verifyCandidate(tc.password, tc.record, tc.typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("verifyCandidate rejected the right password for %q: ok=%v err=%v", tc.record, ok, err)
		}
	}
}

// TestJohnHMACSpelling pins the `<message>#<digest>` reading, including the
// cases the predicate must refuse. A '#' is an ordinary field separator in
// several records, so reading every one of them as an HMAC message would be a
// worse bug than not reading John's at all.
func TestJohnHMACSpelling(t *testing.T) {
	msg, digest, ok := splitJohnHMAC("what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738")
	if !ok || msg != "what do ya want for nothing?" || digest != "750c783e6ab0b503eaa86e310a5db738" {
		t.Fatalf("splitJohnHMAC = %q %q %v", msg, digest, ok)
	}
	for _, bad := range []string{
		"$DCC2$10240#6848#e2829c8af2232fa53797e29b51f4e0cd", // '#' as a field separator
		"no-digest-here#zzzz",                               // not hex
		"#750c783e6ab0b503eaa86e310a5db738",                 // empty message
		"what do ya want for nothing?#",                     // empty digest
		"abc#750c783e6ab0b503eaa86e310a5db7",                // not a digest length
	} {
		if _, _, ok := splitJohnHMAC(bad); ok {
			t.Errorf("splitJohnHMAC accepted %q; it must not", bad)
		}
	}
	// End to end, through the verifier, with John's own vector.
	ok, err := verifyCandidate("Jefe", "what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738",
		"hmac-md5", "", "prefix")
	if err != nil || !ok {
		t.Errorf("hmac-md5 rejected John's vector: ok=%v err=%v", ok, err)
	}
}

// TestSHA1CryptAcceptsBothTrailingByteConventions pins the fix for a real
// disagreement between the two tools' published vectors.
//
// The 28-character checksum encodes 21 bytes while the digest is 20, and what
// goes in the last byte is not agreed: NetBSD (and passlib, and John) wraps
// around to digest[0], hashcat pads with zero. Comparing the ENCODED STRING
// accepts whichever convention the implementation happens to use and rejects
// the other — this tool cracked hashcat's record and refused all of John's,
// with the digest computed correctly every time. Comparing the decoded digest
// accepts both, which is what John does.
func TestSHA1CryptAcceptsBothTrailingByteConventions(t *testing.T) {
	for _, tc := range []struct{ record, password, origin string }{
		// Zero-padded trailing byte.
		{"$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q", "hashcat", "hashcat"},
		// Trailing byte wrapped to digest[0].
		{"$sha1$64000$wnUR8T1U$vt1TFQ50tBMFgkflAFAOer2CwdYZ", "password", "john"},
		{"$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq", "password", "john"},
		{"$sha1$64000$wnUR8T1U$azjCegpOIk0FjE61qzGWhdkpuMRL", "complexlongpassword@123456", "john"},
	} {
		ok, err := verifySHA1Crypt(tc.record, tc.password)
		if err != nil || !ok {
			t.Errorf("%s vector rejected: %q ok=%v err=%v", tc.origin, tc.record, ok, err)
		}
		if bad, _ := verifySHA1Crypt(tc.record, tc.password+"x"); bad {
			t.Errorf("%s vector accepted a wrong password: %q", tc.origin, tc.record)
		}
	}
}
