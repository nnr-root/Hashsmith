package main

import (
	"strings"
	"testing"
)

// TestTypeCatalogueWired proves that every single-token type advertised by
// `hashsmith types` is actually handled by the crack engine — i.e. no type is
// listed but left unimplemented. Compound/descriptive catalogue entries (those
// with spaces, slashes, or placeholders) are skipped.
func TestTypeCatalogueWired(t *testing.T) {
	checked := 0
	for _, g := range universalHashRegistry.groups {
		for _, item := range g.items {
			tok := item[0]
			if strings.ContainsAny(tok, " /<(") {
				continue // descriptive entry, not a literal -t token
			}
			_, err := verifyCandidate("dummy-candidate", "dummy-target", tok, "", "prefix")
			if err != nil && strings.Contains(err.Error(), "unsupported hash algorithm") {
				t.Errorf("type %q is advertised in the catalogue but not wired into verifyCandidate", tok)
			}
			checked++
		}
	}
	if checked < 60 {
		t.Fatalf("only %d catalogue tokens checked; expected the full set", checked)
	}
	t.Logf("verified %d catalogue type tokens are wired", checked)
}

// TestDetectionResolvesToWiredTypes runs a representative hash of each detectable
// family through detectHashTypes and confirms every returned type token is
// crackable (not an unimplemented stub).
func TestDetectionResolvesToWiredTypes(t *testing.T) {
	samples := []string{
		"5f4dcc3b5aa765d61d8327deb882cf99", // md5
		"$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1", // sha512crypt
		"$ethereum$p*1000*aa*bb*cc", // ethereum
		"WPA*01*6d3c40446a165cfeb121c82f18bf97d8*001122334455*8899aabbccdd*49454545", // wpa
		"$bitcoin$96*aa$16*bb$100$", // bitcoin (parse only)
		"pbkdf2_sha256$36000$saltsalt$/7unVWV4lqLJuWJ8M0AkSFZLsgC7+Gh07a9xHYVRA54=", // django
		"$P$984478476IagS59wHZvyQMArzfx58u.",                                        // phpass
		"{SSHA}QZdDbujQQyJjuC5FgKJZDvWEEBxzNGx0",                                    // ldap
		"USER$ABCAD719B17E7F794DF7E686E563E9E2D24DE1D0",                             // sap-fg
	}
	for _, s := range samples {
		for _, typ := range detectHashTypes(s) {
			if _, err := verifyCandidate("x", s, typ, "", "prefix"); err != nil &&
				strings.Contains(err.Error(), "unsupported hash algorithm") {
				t.Errorf("detectHashTypes(%.20s…) returned unwired type %q", s, typ)
			}
		}
	}
}
