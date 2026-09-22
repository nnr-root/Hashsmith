package main

import "testing"

// TestJohnSpellings runs John's spelling of each record through the verifier
// Hashsmith already had, and then the spelling Hashsmith writes through the
// same verifier, so neither reading can regress without the other noticing.
func TestJohnSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, typ, format, own, ownPass string
	}{
		{"CRC-32", "crc32-hashcat", "CRC32 $crc32$", "fa455f6b:00000000", "ripper"},
		{"CRC-32C", "crc32c-hashcat", "CRC32 $crc32c$", "98a61e94:00000000", "ripper"},
		{"iSCSI CHAP", "chap", "chap $chap$", "81474a4f7a3dbf22e071a02c10e54b47:abcdef0123456789:1b", "hashsmith"},
		{"scrypt, crypt spelling", "scrypt", "scrypt $7$", "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=", "hashcat"},
		{"scrypt, the Perl module's", "scrypt", "scrypt $scryptkdf.pm$", "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=", "hashcat"},
		{"MongoDB MONGODB-CR", "mongodb", "MongoDB $mongodb$", "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM=", "hashsmith"},
		{"MongoDB SCRAM-SHA-1", "mongodb", "scram $scram$", "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM=", "hashsmith"},
		{"plaintext", "plaintext", "plaintext $0$", "hashcat", "hashcat"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.name, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.name, ok, err)
		}
		if bad, _ := verifyCandidate(pass+"x", record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.name)
		}
		// Hashsmith's own spelling of the same format must keep working.
		if ok, err := verifyCandidate(tc.ownPass, tc.own, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: its own spelling regressed: ok=%v err=%v", tc.name, ok, err)
		}
	}
}

// TestJohnSpellingsRefused pins the records these readers must not claim: a
// prefix alone is not enough, the fields behind it have to parse.
func TestJohnSpellingsRefused(t *testing.T) {
	for _, tc := range []struct{ name, record string }{
		{"a seeded CRC with no seed", "$crc32$fa455f6b"},
		{"a seeded CRC whose words are not hex", "$crc32$zzzzzzzz.fa455f6b"},
		{"a CHAP record with too few fields", "$chap$0*cc7e5247514551acdcbf782c4027bfb1"},
		{"a $7$ record with no digest", "$7$C6..../....SodiumChloride"},
		{"a Perl scrypt record with a bad count", "$ScryptKDF.pm$x*8*1*bjZkemVmZ3lWVi42*cmBflTPsqGIbg9ZIJRTQdbic8OCUH+904TFmNPBkuEA="},
		{"a MongoDB record naming the network hash", "$mongodb$1$sa$75692b1d11c072c6c79332e248c4f699"},
		{"a SCRAM record with too few fields", "$scram$someadmin$10000$wf42AF7JaU1NSeBaSmkKzw=="},
	} {
		if types := detectHashTypes(tc.record); len(types) > 0 {
			t.Errorf("%s: claimed as %v", tc.name, types)
		}
	}
}
