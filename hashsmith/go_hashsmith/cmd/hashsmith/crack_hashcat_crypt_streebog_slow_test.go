//go:build slowtest

package main

import "testing"

// Purely slow KDF verification at production iteration counts. Moved out of
// the default suite; see crack_hashcat_crypt_streebog_test.go for the
// HASHSMITH_EXHAUSTIVE_CRYPTO-gated exhaustive variant, which stays untagged
// and unchanged.
func TestVeraCryptStreebogPublishedVector(t *testing.T) {
	for _, mode := range []string{"29471", "29483"} {
		v := publishedCryptVectorForMode(t, mode)
		ok, err := verifyCandidate(v.password, v.target, mode, "", "prefix")
		if err != nil || !ok {
			t.Fatalf("Hashcat %s published vector: ok=%v err=%v", mode, ok, err)
		}
		ok, err = verifyCandidate("wrong", v.target, mode, "", "prefix")
		if err != nil || ok {
			t.Fatalf("Hashcat %s wrong candidate: ok=%v err=%v", mode, ok, err)
		}
	}
}

func publishedCryptVectorForMode(t *testing.T, mode string) selfTestVector {
	t.Helper()
	for _, item := range hashcatLegacyCryptAndStreebogVectorSeed() {
		if item.mode == mode {
			return item.vector
		}
	}
	t.Fatalf("missing published vector for Hashcat mode %s", mode)
	return selfTestVector{}
}
