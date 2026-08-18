package main

import "testing"

// Authoritative phpass and Drupal7 vectors (hashcat modes 400 and 7900),
// passphrase "hashcat".
func TestPhpassDrupal7Vectors(t *testing.T) {
	phpass := "$P$984478476IagS59wHZvyQMArzfx58u."
	if ok, err := verifyPhpass(phpass, "hashcat"); err != nil || !ok {
		t.Errorf("phpass verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyPhpass(phpass, "wrong"); ok {
		t.Error("phpass should reject the wrong passphrase")
	}
	if got := detectHashTypes(phpass); len(got) != 1 || got[0] != "phpass" {
		t.Errorf("detectHashTypes(phpass) = %v, want [phpass]", got)
	}

	drupal := "$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf"
	if ok, err := verifyDrupal7(drupal, "hashcat"); err != nil || !ok {
		t.Errorf("Drupal7 verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyDrupal7(drupal, "wrong"); ok {
		t.Error("Drupal7 should reject the wrong passphrase")
	}
	if got := detectHashTypes(drupal); len(got) != 1 || got[0] != "drupal7" {
		t.Errorf("detectHashTypes(drupal7) = %v, want [drupal7]", got)
	}
}
