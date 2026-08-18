package main

import "testing"

// Authoritative BitLocker vector (hashcat mode 22100 example), passphrase
// "hashcat". A real volume, so a true result validates the whole
// 1M-round SHA-256 stretch + AES-CTR + VMK-structure check end to end.
func TestBitLockerVector(t *testing.T) {
	line := "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb"

	if ok, err := verifyBitLocker(line, "hashcat"); err != nil || !ok {
		t.Fatalf("BitLocker verify failed for the correct passphrase: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyBitLocker(line, "wrongpass"); ok {
		t.Error("BitLocker should reject the wrong passphrase")
	}
	if got := detectHashTypes(line); len(got) != 1 || got[0] != "bitlocker" {
		t.Errorf("detectHashTypes = %v, want [bitlocker]", got)
	}
}
