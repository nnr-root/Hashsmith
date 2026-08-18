package main

import "testing"

// LDAP salted-digest vectors (passphrase "hashsmith"), Python-generated.
func TestLDAPVectors(t *testing.T) {
	lines := []string{
		"{SSHA}QZdDbujQQyJjuC5FgKJZDvWEEBxzNGx0",
		"{SMD5}8XX/GhGj2YU+bCV3oANYZnM0bHQ=",
		"{SSHA256}v899PtNSobzUUSUrJ2GzKL4UcX5TglI5TTExOzl4Bz5zNGx0",
		"{SSHA512}jxx7Zc2ON06RjKvCHpyjQ1k/okyfsU+EPKfKFvGVHiXaZVuCQrt8n51mtVmAMsueKXh4cXEVzNb82t+VJUfVvXM0bHQ=",
	}
	for i, line := range lines {
		if ok, err := verifyLDAP(line, "hashsmith"); err != nil || !ok {
			t.Errorf("LDAP vector %d verify failed: ok=%v err=%v", i, ok, err)
		}
		if ok, _ := verifyLDAP(line, "wrong"); ok {
			t.Errorf("LDAP vector %d should reject the wrong passphrase", i)
		}
		if got := detectHashTypes(line); len(got) != 1 || got[0] != "ldap" {
			t.Errorf("detectHashTypes(vector %d) = %v, want [ldap]", i, got)
		}
	}
}
