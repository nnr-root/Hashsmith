package main

import (
	"path/filepath"
	"testing"
)

// The potfile is keyed by the target string alone, and a 32-character hex
// digest is a well-formed MD5, a well-formed NTLM, a well-formed LM half and a
// well-formed MD4 all at once. Before every hit was re-derived, cracking one
// of those as NTLM taught the potfile an answer that `--show -t md5` then
// reported as the MD5 preimage — a confidently wrong password.
//
// 8846f7eaee8fb117ad06bdd830b7586c is NTLM("password"). MD5("password") is
// 5f4dcc3b5aa765d61d8327deb882cf99, so nothing about the NTLM entry is true of
// the same string read as an MD5, and the difference is exactly what the check
// has to notice.
func TestPotfileHitIsVerifiedAgainstTheTypeAsked(t *testing.T) {
	const ntlmOfPassword = "8846f7eaee8fb117ad06bdd830b7586c"

	pot, err := loadPotfile(filepath.Join(t.TempDir(), "hashsmith.pot"))
	if err != nil {
		t.Fatalf("loadPotfile: %v", err)
	}
	pot.add(ntlmOfPassword, "password")

	for _, tc := range []struct {
		name   string
		target string
		typ    string
		want   potHitStatus
		plain  string
	}{
		{"the type it was cracked as", ntlmOfPassword, "ntlm", potVerified, "password"},
		{"auto finds that type", ntlmOfPassword, "auto", potVerified, "password"},
		{"", ntlmOfPassword, "", potVerified, "password"},
		{"another type of the same width", ntlmOfPassword, "md5", potStale, "password"},
		{"and another", ntlmOfPassword, "md4", potStale, "password"},
		{"a string with no entry", "5f4dcc3b5aa765d61d8327deb882cf99", "md5", potMiss, ""},
		{"a type this build cannot check", ntlmOfPassword, "not-a-real-type", potUnchecked, "password"},
	} {
		name := tc.name
		if name == "" {
			name = "no type given"
		}
		t.Run(name, func(t *testing.T) {
			plain, status := pot.verifiedPlain(tc.target, tc.typ, "", "")
			if status != tc.want {
				t.Fatalf("status = %v, want %v", status, tc.want)
			}
			if plain != tc.plain {
				t.Fatalf("plaintext = %q, want %q", plain, tc.plain)
			}
		})
	}
}

// The same collision happens without two type names being involved: one digest
// string, two external salts, two different answers. Whichever run wrote the
// entry, the other run must not report it.
func TestPotfileHitIsVerifiedAgainstTheSaltAsked(t *testing.T) {
	// md5("password" + "salt1"), as -s salt1 -S suffix would check it.
	const digest = "05b604d36ceaeadd8c8fe358f112d98e"

	pot, err := loadPotfile(filepath.Join(t.TempDir(), "hashsmith.pot"))
	if err != nil {
		t.Fatalf("loadPotfile: %v", err)
	}
	good, err := verifyCandidate("password", digest, "md5", "salt1", "suffix")
	if err != nil || !good {
		t.Fatalf("test vector is wrong: verifyCandidate = %v, %v", good, err)
	}
	pot.add(digest, "password")

	if _, status := pot.verifiedPlain(digest, "md5", "salt1", "suffix"); status != potVerified {
		t.Fatalf("the salt it was cracked under: status = %v, want potVerified", status)
	}
	if _, status := pot.verifiedPlain(digest, "md5", "salt2", "suffix"); status != potStale {
		t.Fatalf("a different salt: status = %v, want potStale", status)
	}
	if _, status := pot.verifiedPlain(digest, "md5", "salt1", "prefix"); status != potStale {
		t.Fatalf("the other side of the plaintext: status = %v, want potStale", status)
	}
}
