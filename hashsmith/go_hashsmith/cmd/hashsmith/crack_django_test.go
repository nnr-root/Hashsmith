package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

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

func TestModernDjangoVectors(t *testing.T) {
	key, err := scrypt.Key([]byte("hashsmith"), []byte("salty"), 1024, 8, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hashsmith"))
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(digest[:])), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	argon, err := hashText("hashsmith", "argon2", "salty123", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	vectors := []string{
		fmt.Sprintf("scrypt$1024$salty$8$1$%s", base64.StdEncoding.EncodeToString(key)),
		"bcrypt_sha256$" + string(bcryptHash),
		"argon2" + argon,
		"md5$salty$37795b0102ce7e2ec07898d88690a638",
		"sha1$salty$9701cdd6ff14e844e0bd6c2a8264fb2007775c17",
	}
	for _, target := range vectors {
		if ok, err := verifyDjango(target, "hashsmith"); err != nil || !ok {
			t.Errorf("Django vector %q failed: ok=%v err=%v", target, ok, err)
		}
		if ok, _ := verifyDjango(target, "wrong"); ok {
			t.Errorf("Django vector %q accepted wrong password", target)
		}
		if got := detectHashTypes(target); len(got) != 1 || got[0] != "django" {
			t.Errorf("detectHashTypes(Django %q) = %v", target, got)
		}
	}
}

func TestDjangoCostLimits(t *testing.T) {
	if _, err := verifyDjango("pbkdf2_sha256$100000001$salty$AAAA", "x"); err == nil {
		t.Fatal("Django PBKDF2 accepted an unsafe iteration count")
	}
	if _, err := verifyDjango("scrypt$1073741824$salty$8$1$AAAA", "x"); err == nil {
		t.Fatal("Django scrypt accepted unsafe parameters")
	}
	for _, target := range []string{
		"argon2$argon2id$v=19$m=1073741824,t=2,p=1$c2FsdHNhbHQ$AAAAAA",
		"argon2$argon2id$v=19$m=1024,m=2048,t=2,p=1$c2FsdHNhbHQ$AAAAAA",
	} {
		if ok, err := verifyDjango(target, "x"); err != nil || ok {
			if err != nil {
				t.Errorf("Django Argon2 safety parser returned an envelope error: %v", err)
			} else {
				t.Error("Django Argon2 accepted unsafe parameters")
			}
		}
	}
}
