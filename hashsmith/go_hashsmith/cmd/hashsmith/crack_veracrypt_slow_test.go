//go:build slowtest

package main

import "testing"

// The slow half of the TestVeraCryptVector split: PBKDF2-HMAC-SHA512 +
// AES-XTS verification at production iteration counts. See
// crack_veracrypt_test.go for the fast detection assertion that remains in
// the default suite.
func TestVeraCryptVector(t *testing.T) {
	if ok, err := verifyVeraCrypt(vcSHA512Header, "hashcat"); err != nil || !ok {
		t.Fatalf("VeraCrypt verify failed for the correct passphrase: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyVeraCrypt(vcSHA512Header, "wrongpass"); ok {
		t.Error("VeraCrypt should reject the wrong passphrase")
	}
}
