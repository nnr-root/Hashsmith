package main

import "testing"

// Generic PBKDF2 vectors (passphrase "hashsmith"), generated with Python.
func TestPBKDF2Vectors(t *testing.T) {
	lines := []string{
		"sha1:1000:c2FsdHNhbHQxMjM0:6jISIm7T4PpJvo5EJTRRXYTSMa4=",
		"sha256:1000:c2FsdHNhbHQxMjM0:/OzTSSgPVochJbagu+4vaVThQn0nApx5SHJsdvP4zgo=",
		"sha512:1000:c2FsdHNhbHQxMjM0:FIpTXcTGBp/ZKtZqZmm/+qaUbtP4HC6iEkqpRhuY9QXVM1zanjQ8A2JZlJ2ZAM1EcmiiXjAIEt89N8QjBTx9vw==",
		"md5:1000:c2FsdHNhbHQxMjM0:qTSAhVT6YAYDUcqRlepPhQ==",
	}
	for i, line := range lines {
		if ok, err := verifyPBKDF2(line, "hashsmith"); err != nil || !ok {
			t.Errorf("PBKDF2 vector %d verify failed: ok=%v err=%v", i, ok, err)
		}
		if ok, _ := verifyPBKDF2(line, "wrong"); ok {
			t.Errorf("PBKDF2 vector %d should reject the wrong passphrase", i)
		}
		if got := detectHashTypes(line); len(got) != 1 || got[0] != "pbkdf2" {
			t.Errorf("detectHashTypes(vector %d) = %v, want [pbkdf2]", i, got)
		}
	}
}
