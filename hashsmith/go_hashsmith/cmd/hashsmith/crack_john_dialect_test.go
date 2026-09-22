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

// TestPBKDF2HMACRecordSeparators pins that either separator is read for any
// algorithm in the "$pbkdf2-hmac-<alg>$" family.
//
// The separator is inconsistent within each tool, not just between them:
// hashcat's SHA-1 record uses '$' and its SHA-512 record uses '.', while
// John's SHA-1 record uses '.'. Hard-coding one per algorithm parsed three of
// those four and refused the fourth.
func TestPBKDF2HMACRecordSeparators(t *testing.T) {
	for _, tc := range []struct{ record, password, origin string }{
		// John's vectors: MD4 and MD5 with '$', SHA-1 and SHA-512 with '.'.
		{"$pbkdf2-hmac-md4$1000$6d61676e756d$32ebfcea201e61cc498948916a213459", "magnum", "john"},
		{"$pbkdf2-hmac-md5$1000$38333335343433323338$f445d6d0ed5cbe9fc12c03ea9530c1c6", "hashcat", "john"},
		{"$pbkdf2-hmac-sha1$1000.fd11cde0.27de197171e6d49fc5f55c9ef06c0d8751cd7250", "3956", "john"},
	} {
		ok, err := verifyNetIQPBKDF2(tc.record, tc.password)
		if err != nil || !ok {
			t.Errorf("%s vector rejected: %q ok=%v err=%v", tc.origin, tc.record, ok, err)
		}
		if bad, _ := verifyNetIQPBKDF2(tc.record, tc.password+"x"); bad {
			t.Errorf("%s vector accepted a wrong password: %q", tc.origin, tc.record)
		}
		if !isNetIQPBKDF2(tc.record) {
			t.Errorf("%q is not recognised as a PBKDF2-HMAC record", tc.record)
		}
	}
	// An unknown algorithm in the envelope must not be claimed.
	if isNetIQPBKDF2("$pbkdf2-hmac-nosuchhash$1000$aa$bb") {
		t.Error("an unknown algorithm was claimed as a PBKDF2-HMAC record")
	}
}

// TestRACFKDFAESJohnSpelling pins that John's envelope resolves to the same
// four fields hashcat's does. John writes KDFAES under the SAME "$racf$*"
// prefix as the legacy DES format, with parameters, salt and digest run
// together into one 96-character field.
func TestRACFKDFAESJohnSpelling(t *testing.T) {
	const record = "$racf$*USER123*E7D7E66D00018000001000340010001054FDAABCDEF012345674A0F58EE6137D3B3AD9EC21E371BE67D5A75BE0E892B8"
	user, params, salt, digest, ok := johnRACFKDFAESFields(record)
	if !ok {
		t.Fatal("John's RACF KDFAES record was not recognised")
	}
	if user != "USER123" || len(params) != 32 || len(salt) != 32 || len(digest) != 32 {
		t.Fatalf("fields split wrongly: %q %q %q %q", user, params, salt, digest)
	}
	// A legacy DES record under the same prefix must NOT be claimed here.
	if _, _, _, _, ok := johnRACFKDFAESFields("$racf$*8481*6095E8FCA59F8E3E"); ok {
		t.Error("a legacy RACF DES record was read as KDFAES")
	}
	// And detection must still offer the cheap legacy reading first.
	types := detectHashTypes("$racf$*8481*6095E8FCA59F8E3E")
	if len(types) == 0 || types[0] != "racf" {
		t.Errorf("detectHashTypes for a legacy RACF record = %v; want racf first", types)
	}
}

// TestDjangoScryptBothLayouts pins that both "scrypt$" layouts are read.
//
// Django core writes scrypt$<n>$<salt>$<r>$<p>$<digest>; the third-party
// django-scrypt package writes scrypt$<salt>$<log2 n>$<r>$<p>$<dklen>$<digest>.
// They share a prefix and nothing else, so reading only one refused the
// other as malformed rather than trying it.
func TestDjangoScryptBothLayouts(t *testing.T) {
	// django-scrypt package layout, John's vector.
	const pkg = "scrypt$NBGmaGIXijJW$14$8$1$64$achPt01SbytSt+F3CcCFgEPr96+/j9iCTdejFdAARZ8mzfejrP64TJ5XBJa3gYwuCKOEGlw2E/lWCWS7LeS6CA=="
	ok, err := verifyDjango(pkg, "notastrongpassword")
	if err != nil || !ok {
		t.Errorf("django-scrypt package layout rejected: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyDjango(pkg, "notastrongpassword!"); bad {
		t.Error("django-scrypt package layout accepted a wrong password")
	}
	if !isDjangoHash(pkg) {
		t.Error("the package layout is not recognised as a Django record")
	}
	// And detection must prefer Django over the bare scrypt reading.
	if types := detectHashTypes(pkg); len(types) == 0 || types[0] != "django" {
		t.Errorf("detectHashTypes = %v; want django first", types)
	}
}

// TestJohnRawDigestEnvelopes covers John's "$NAME$<hex>" spelling for raw
// digests. These are the records the John ratchet cannot see: its corpus
// takes one vector per format and John lists the BARE digest first for most
// of these, so the envelope spelling is only exercised here.
//
// The envelope is what makes them identifiable at all — a bare 128-hex digest
// is SHA-512, SHA3-512, BLAKE2b, Whirlpool, Streebog-512 or Keccak-512 with
// nothing to choose between them.
func TestJohnRawDigestEnvelopes(t *testing.T) {
	for _, tc := range []struct{ record, password string }{
		{"$gost$d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd", "a"},
		{"$SHA512$f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
		{"$keccak256$4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "abc"},
		{"$MD4$6d78785c44ea8dfa178748b245d8c3ae", "magnum"},
		{"$SHA224$d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", "password"},
		{"$SHA256$71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
		{"$SHA384$a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", "password"},
	} {
		typ, _, ok := johnWrapperFor(tc.record)
		if !ok {
			t.Errorf("no envelope recognised in %.28s...", tc.record)
			continue
		}
		types := detectHashTypes(tc.record)
		if !containsString(types, typ) {
			t.Errorf("detectHashTypes(%.28s...) = %v, want %q", tc.record, types, typ)
		}
		got, err := verifyCandidate(tc.password, tc.record, typ, "", "prefix")
		if err != nil || !got {
			t.Errorf("%.28s... rejected the right password: ok=%v err=%v", tc.record, got, err)
		}
		if bad, _ := verifyCandidate(tc.password+"x", tc.record, typ, "", "prefix"); bad {
			t.Errorf("%.28s... accepted a wrong password", tc.record)
		}
	}
	// The envelope is matched case-insensitively, since John is not
	// consistent: $SHA512$ and $MD4$ are upper, $gost$ and $keccak256$ lower.
	if _, _, ok := johnWrapperFor("$sha512$aa"); !ok {
		t.Error("a lower-case $sha512$ envelope was not recognised")
	}
	// And an envelope only unwraps for the type it names.
	if got := stripJohnWrapper("$md4$abc", "sha256"); got != "$md4$abc" {
		t.Errorf("stripJohnWrapper unwrapped for the wrong type: %q", got)
	}
}

// TestKerberosJohnSpellings pins the three ways John's Kerberos records differ
// from hashcat's, each of which made every record of that kind unreadable.
func TestKerberosJohnSpellings(t *testing.T) {
	for _, tc := range []struct{ name, record, password string }{
		// AS-REP etype 23: no principal at all, and '$' where hashcat has ':'.
		// Nothing is lost — for etype 23 the key is the NTLM hash of the
		// password alone, so the principal is decoration in this record.
		{"asrep-rc4", "$krb5asrep$23$771adbc2397abddef676742924414f2b$2df6eb2d9c71820dc3fa2c098e071d920f0e412f5f12411632c5ee70e004da1be6f003b78661f8e4507e173552a52da751c45887c19bc1661ed334e0ccb4ef33975d4bd68b3d24746f281b4ca4fdf98fca0e50a8e845ad7d834e020c05b1495bc473b0295c6e9b94963cb912d3ff0f2f48c9075b0f52d9a31e5f4cc67c7af1d816b6ccfda0da5ccf35820a4d7d79073fa404726407ac840910357ef210fcf19ed81660106dfc3f4d9166a89d59d274f31619ddd9a1e2712c879a4e9c471965098842b44fae7ca6dd389d5d98b7fd7aca566ca399d072025e81cf0ef5075447687f80100307145fade7a8", "P@$$w0rd123"},
	} {
		ok, err := verifyKrb5(tc.record, tc.password)
		if err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.name, ok, err)
		}
		if bad, _ := verifyKrb5(tc.record, tc.password+"x"); bad {
			t.Errorf("%s: accepted a wrong password", tc.name)
		}
	}
	// hashcat's own spelling must keep working: the principal-bearing form
	// with ':' is what its records use.
	types := detectHashTypes("$krb5asrep$23$771adbc2397abddef676742924414f2b$2df6eb2d9c")
	if !containsString(types, "krb5asrep") {
		t.Errorf("John's AS-REP spelling is not detected as krb5asrep: %v", types)
	}
}

// TestAS400JohnSpellings pins John's two AS/400 envelopes. The DES one keeps
// hashcat's body and only renames the envelope; the SSHA1 one also writes the
// digest BEFORE the profile name, the reverse of hashcat's order.
func TestAS400JohnSpellings(t *testing.T) {
	// The wrong password must differ within the first EIGHT characters: AS/400
	// DES is a DES key schedule over the EBCDIC password, so it truncates
	// there and "AAAAAAAA" and "AAAAAAAAx" are genuinely the same hash. That
	// is the format, not a weak check.
	for _, tc := range []struct{ name, record, password, wrong, typ string }{
		{"des", "$as400des$AAAAAAA*CA2E330B2FD1820E", "AAAAAAAA", "BBBBBBBB", "as400-des"},
		{"ssha1", "$as400ssha1$4C106E52CA196986E1C52C7FCD02AF046B76C73C$ROB", "banaan", "banaanx", "as400-ssha1"},
	} {
		if types := detectHashTypes(tc.record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes = %v, want %q", tc.name, types, tc.typ)
		}
		ok, err := verifyCandidate(tc.password, tc.record, tc.typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.name, ok, err)
		}
		if bad, _ := verifyCandidate(tc.wrong, tc.record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.name)
		}
	}
	// hashcat's spellings must keep working.
	if ok, err := verifyAS400DES("$as400$des$*OPEN3*EC76FC0DEF5B0A83", "SYS1"); err != nil || !ok {
		t.Errorf("hashcat's AS/400 DES record regressed: ok=%v err=%v", ok, err)
	}
}

// TestNetNTLMJohnSpellings pins John's two NetNTLM forms.
//
// The envelope form matters most for NTLMv2: its identity is upper(user)
// plus domain, and John stores it ALREADY CONCATENATED. Re-uppercasing that
// would be wrong, because the spec uppercases the user and takes the domain
// verbatim, so an identity with a lower-case domain half must not be folded.
func TestNetNTLMJohnSpellings(t *testing.T) {
	for _, tc := range []struct{ name, record, password, typ string }{
		{"v1 envelope", "$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "g3rg3g3rg3g3rg3", "netntlmv1"},
		{"v2 envelope", "$NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000", "password", "netntlmv2"},
		// John's pwdump-shaped form writes the literal text "lm-hash" where
		// it has no LM response. That field is only consulted to detect
		// extended session security, so the placeholder is a real record.
		{"v1 pwdump, lm placeholder", "User:::lm-hash:BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB:1122334455667788", "g3rg3g3rg3g3rg3", "netntlmv1"},
	} {
		if types := detectHashTypes(tc.record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %q: %v", tc.name, tc.typ, types)
		}
		ok, err := verifyCandidate(tc.password, tc.record, tc.typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.name, ok, err)
		}
		if bad, _ := verifyCandidate(tc.password+"x", tc.record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.name)
		}
	}
	// hashcat's own spelling must keep working.
	if ok, err := verifyNetNTLMv2("0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700", "hashcat"); err != nil || !ok {
		t.Errorf("hashcat's NetNTLMv2 record regressed: ok=%v err=%v", ok, err)
	}
}
