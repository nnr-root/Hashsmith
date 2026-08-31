package main

import (
	"os"
	"testing"
)

func TestHashcatLegacyCryptAndStreebogExhaustive(t *testing.T) {
	if os.Getenv("HASHSMITH_EXHAUSTIVE_CRYPTO") == "" {
		t.Skip("set HASHSMITH_EXHAUSTIVE_CRYPTO=1 to run all high-iteration container vectors")
	}
	for _, item := range hashcatLegacyCryptAndStreebogVectorSeed() {
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
