package main

import "testing"

// Django PBKDF2 vectors (passphrase "hashsmith"), generated with Python.
func TestDjangoVectors(t *testing.T) {
	lines := []string{
		"pbkdf2_sha256$36000$saltsalt$/7unVWV4lqLJuWJ8M0AkSFZLsgC7+Gh07a9xHYVRA54=",
		"pbkdf2_sha1$36000$saltsalt$+6Qo6HdMPwwHQvlmc9N7EeFaEEI=",
	}
	for i, line := range lines {
		if ok, err := verifyDjango(line, "hashsmith"); err != nil || !ok {
			t.Errorf("Django vector %d verify failed: ok=%v err=%v", i, ok, err)
		}
		if ok, _ := verifyDjango(line, "wrong"); ok {
			t.Errorf("Django vector %d should reject the wrong passphrase", i)
		}
		if got := detectHashTypes(line); len(got) != 1 || got[0] != "django" {
			t.Errorf("detectHashTypes(vector %d) = %v, want [django]", i, got)
		}
	}
}
