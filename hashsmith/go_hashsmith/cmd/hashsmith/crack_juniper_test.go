package main

import "testing"

// Juniper NetScreen vectors from the reference test suite.
func TestJuniperVectors(t *testing.T) {
	cases := []struct{ hash, pass string }{
		{"admin$nMjFM0rdC9iOc+xIFsGEm3LtAeGZhn", "password"},
		{"a$nMf9FkrCIgHGccRAxsBAwxBtDtPHfn", "netscreen"},
		{"admin$nDa2MErEKCsMcuQOTsLNpGCtKJAq5n", "QUESTIONDEFENSE"},
	}
	for _, c := range cases {
		if ok, err := verifyJuniper(c.hash, c.pass); err != nil || !ok {
			t.Errorf("Juniper verify failed for %q: ok=%v err=%v", c.hash, ok, err)
		}
		if ok, _ := verifyJuniper(c.hash, "wrong"); ok {
			t.Errorf("Juniper should reject the wrong passphrase for %q", c.hash)
		}
		if got := detectHashTypes(c.hash); len(got) != 1 || got[0] != "juniper" {
			t.Errorf("detectHashTypes(%q) = %v, want [juniper]", c.hash, got)
		}
	}
}
