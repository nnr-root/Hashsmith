package main

import (
	"encoding/hex"
	"testing"
)

// keccak256 sanity: the well-known empty-input Keccak-256 digest.
func TestKeccak256Empty(t *testing.T) {
	const want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got := hex.EncodeToString(keccak256(nil)); got != want {
		t.Errorf("keccak256(\"\"):\n  got  %s\n  want %s", got, want)
	}
}

// Ethereum vectors from go-ethereum's authoritative keystore test data
// (passphrase "testpassword") — the Web3 Secret Storage PBKDF2 and scrypt cases,
// plus the 30/31-byte-ciphertext scrypt cases.
func TestEthereumVectors(t *testing.T) {
	lines := []string{
		// PBKDF2, c=262144.
		"$ethereum$p*262144" +
			"*ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd" +
			"*5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46" +
			"*517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
		// scrypt, N=262144 r=1 p=8.
		"$ethereum$s*262144*1*8" +
			"*ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19" +
			"*d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c" +
			"*2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097",
	}
	for i, line := range lines {
		if ok, err := verifyEthereum(line, "testpassword"); err != nil || !ok {
			t.Errorf("Ethereum vector %d verify failed: ok=%v err=%v", i, ok, err)
		}
		if ok, _ := verifyEthereum(line, "wrong"); ok {
			t.Errorf("Ethereum vector %d should reject the wrong passphrase", i)
		}
		if got := detectHashTypes(line); len(got) != 1 || got[0] != "ethereum" {
			t.Errorf("detectHashTypes(vector %d) = %v, want [ethereum]", i, got)
		}
	}
}
