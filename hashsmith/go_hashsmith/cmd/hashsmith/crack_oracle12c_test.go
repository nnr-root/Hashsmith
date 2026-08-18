package main

import "testing"

// Oracle 12c "T:" (hashcat mode 12300 example), password "hashcat".
func TestOracle12cVector(t *testing.T) {
	h := "78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225"
	if ok, err := verifyOracle12c(h, "hashcat"); err != nil || !ok {
		t.Errorf("Oracle 12c verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyOracle12c(h, "wrong"); ok {
		t.Error("Oracle 12c should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "oracle12c" {
		t.Errorf("detectHashTypes(oracle12c) = %v", got)
	}
}
