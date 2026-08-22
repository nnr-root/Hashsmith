package main

import (
	"strings"
	"testing"
)

// Every compatibility alias must name a type the crack engine actually
// implements.  verifyCandidate falls through to hashText for the raw-digest
// types, and hashText is the only place that reports "unsupported hash
// algorithm" — so an alias pointing at a type nobody handles surfaces here
// instead of failing a user mid-run.
func TestCompatibilityAliasesResolveToImplementedTypes(t *testing.T) {
	for alias, canonical := range compatibilityHashAliases {
		if got := canonicalHashType(alias); got != canonical {
			t.Errorf("canonicalHashType(%q) = %q, want %q", alias, got, canonical)
		}
		_, err := verifyCandidate("password", "0123456789abcdef", canonical, "salt", "prefix")
		if err != nil && strings.Contains(err.Error(), "unsupported hash algorithm") {
			t.Errorf("alias %q → %q: type is not implemented (%v)", alias, canonical, err)
		}
	}
}

// The namespaced spellings people use in scripts must reach the same type as
// the bare identifier.
func TestCompatibilityAliasPrefixes(t *testing.T) {
	for _, prefix := range []string{"hashcat:", "hashcat-", "hc:", "hc-", "john:", "john-", "jtr:", "jtr-"} {
		if got := canonicalHashType(prefix + "1000"); got != "ntlm" {
			t.Errorf("canonicalHashType(%q) = %q, want ntlm", prefix+"1000", got)
		}
	}
	if got := canonicalHashType("  HASHCAT:1400  "); got != "sha256" {
		t.Errorf("canonicalHashType with padding/case = %q, want sha256", got)
	}
}

// Aliases are only useful if the catalogue `hashsmith types` prints stays in
// step with them, so spot-check that each alias target is a name the
// catalogue or the generic-digest table knows about.
func TestAliasTargetsAreDocumented(t *testing.T) {
	documented := map[string]bool{}
	for _, group := range hashTypeCatalogue {
		for _, item := range group.items {
			documented[strings.Fields(item[0])[0]] = true
		}
	}
	for name := range compatSaltedDigests {
		documented[name] = true
	}
	// Types the catalogue lists under a combined heading rather than by name.
	for _, name := range []string{"zipcrypto", "zipaes128", "zipaes192", "zipaes256",
		"7z", "rar4", "rar5", "pdf", "ssh", "pkcs8", "gpg", "office", "keepass",
		"gost2012-256", "gost2012-512"} {
		documented[name] = true
	}
	for alias, canonical := range compatibilityHashAliases {
		if !documented[canonical] {
			t.Errorf("alias %q → %q is not listed by `hashsmith types`", alias, canonical)
		}
	}
}
