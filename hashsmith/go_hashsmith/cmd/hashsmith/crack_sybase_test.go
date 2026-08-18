package main

import "testing"

// Sybase ASE (hashcat mode 8000 example), password "hashcat".
func TestSybaseASE(t *testing.T) {
	h := "0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2"
	if ok, err := verifySybaseASE(h, "hashcat"); err != nil || !ok {
		t.Errorf("Sybase ASE verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifySybaseASE(h, "wrong"); ok {
		t.Error("Sybase ASE should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "sybase" {
		t.Errorf("detectHashTypes(sybase) = %v", got)
	}
}
