package main

import "testing"

// Cisco IOS type 8/9 vectors (hashcat modes 9200/9300), passphrase "hashcat".
func TestCiscoVectors(t *testing.T) {
	type8 := "$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk"
	if ok, err := verifyCiscoType8(type8, "hashcat"); err != nil || !ok {
		t.Errorf("Cisco type8 verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyCiscoType8(type8, "wrong"); ok {
		t.Error("Cisco type8 should reject the wrong passphrase")
	}
	if got := detectHashTypes(type8); len(got) != 1 || got[0] != "cisco8" {
		t.Errorf("detectHashTypes(type8) = %v, want [cisco8]", got)
	}

	type9 := "$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6"
	if ok, err := verifyCiscoType9(type9, "hashcat"); err != nil || !ok {
		t.Errorf("Cisco type9 verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyCiscoType9(type9, "wrong"); ok {
		t.Error("Cisco type9 should reject the wrong passphrase")
	}
	if got := detectHashTypes(type9); len(got) != 1 || got[0] != "cisco9" {
		t.Errorf("detectHashTypes(type9) = %v, want [cisco9]", got)
	}
}
