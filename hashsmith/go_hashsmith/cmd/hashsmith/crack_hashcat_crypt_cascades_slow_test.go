//go:build slowtest

package main

import "testing"

// Purely slow KDF verification at production iteration counts. Moved out of
// the default suite; see crack_hashcat_crypt_cascades_test.go for the fast
// TrueCrypt representatives and mode-alias coverage that remain untagged.
func TestVeraCryptCascadeRepresentatives(t *testing.T) {
	for _, typ := range []string{"veracrypt-sha256-xts1536", "veracrypt-ripemd160-boot-xts1536"} {
		v := publishedVectorForType(t, typ)
		ok, err := verifyCandidate(v.password, v.target, typ, "", "prefix")
		if err != nil || !ok {
			t.Fatalf("%s published vector failed: ok=%v err=%v", typ, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", v.target, typ, "", "prefix"); bad {
			t.Fatalf("%s accepted a wrong password", typ)
		}
	}
}
