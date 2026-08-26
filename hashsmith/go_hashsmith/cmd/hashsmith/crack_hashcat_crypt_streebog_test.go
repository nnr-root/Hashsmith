package main

import (
	"os"
	"testing"
)

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

func TestHashcatLegacyCryptAndStreebogExhaustive(t *testing.T) {
	if os.Getenv("HASHSMITH_EXHAUSTIVE_CRYPTO") == "" {
		t.Skip("set HASHSMITH_EXHAUSTIVE_CRYPTO=1 to run all high-iteration container vectors")
	}
	for _, item := range hashcatLegacyCryptAndStreebogVectors {
		t.Run(item.mode, func(t *testing.T) {
			v := item.vector
			ok, err := verifyCandidate(v.password, v.target, item.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			if bad, _ := verifyCandidate("definitely-wrong", v.target, item.mode, "", "prefix"); bad {
				t.Fatal("accepted wrong candidate")
			}
		})
	}
}

func publishedCryptVectorForMode(t *testing.T, mode string) selfTestVector {
	t.Helper()
	for _, item := range hashcatLegacyCryptAndStreebogVectors {
		if item.mode == mode {
			return item.vector
		}
	}
	t.Fatalf("missing published vector for Hashcat mode %s", mode)
	return selfTestVector{}
}
