package main

import "testing"

// Authoritative Bitcoin wallet.dat vector (hashcat mode 11300 example),
// passphrase "hashcat". A real wallet, so a true result validates the whole
// SHA-512-stretch + AES-256-CBC padding-check pipeline end to end.
func TestBitcoinVector(t *testing.T) {
	line := "$bitcoin$96$d011a1b6a8d675b7a36d0cd2efaca32a9f8dc1d57d6d01a58399ea04e703e8bbb44899039326f7a00f171a7bbc854a54$16$1563277210780230$158555$96$628835426818227243334570448571536352510740823233055715845322741625407685873076027233865346542174$66$625882875480513751851333441623702852811440775888122046360561760525"

	if ok, err := verifyBitcoin(line, "hashcat"); err != nil || !ok {
		t.Errorf("Bitcoin verify failed for the correct passphrase: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyBitcoin(line, "wrongpass"); ok {
		t.Error("Bitcoin should reject the wrong passphrase")
	}
	if got := detectHashTypes(line); len(got) != 1 || got[0] != "bitcoin" {
		t.Errorf("detectHashTypes = %v, want [bitcoin]", got)
	}
}
