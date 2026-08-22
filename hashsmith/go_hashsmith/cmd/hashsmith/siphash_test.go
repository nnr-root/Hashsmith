package main

import (
	"fmt"
	"testing"
)

// The reference vectors from the SipHash paper's appendix: key 00..0f, message
// 00..(len-1), SipHash-2-4.
func TestSipHash24ReferenceVectors(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	msg := make([]byte, 64)
	for i := range msg {
		msg[i] = byte(i)
	}
	// These four already exercise the empty message, the partial-word tail and
	// the length byte, which is where an implementation typically goes wrong.
	want := []uint64{
		0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
	}
	for n := range want {
		if got := sipHash(2, 4, key, msg[:n]); got != want[n] {
			t.Errorf("SipHash-2-4 len=%d = %016x, want %016x", n, got, want[n])
		}
	}
	// A full 8-byte word plus a tail must differ from the word alone.
	if sipHash(2, 4, key, msg[:8]) == sipHash(2, 4, key, msg[:9]) {
		t.Error("SipHash collided on messages of different length")
	}
}

// Changing any of key, message, or round counts must change the tag.
func TestSipHashRoundCountsAndKeyMatter(t *testing.T) {
	k1, k2 := sipHashKey("password"), sipHashKey("passworE")
	msg := []byte("message")
	if sipHash(2, 4, k1, msg) == sipHash(2, 4, k2, msg) {
		t.Error("distinct keys produced the same tag")
	}
	if sipHash(2, 4, k1, msg) == sipHash(4, 8, k1, msg) {
		t.Error("distinct round counts produced the same tag")
	}
}

func TestSipHashVerifyAcceptsBothHashForms(t *testing.T) {
	const pass, message = "hashsmith", "0011223344556677"
	tag, err := hashText(pass, "siphash", "\x00\x11\x22\x33\x44\x55\x66\x77", "prefix")
	if err != nil {
		t.Fatalf("hashText: %v", err)
	}

	// Long form follows Hashcat: the record carries the key and round counts,
	// while the password candidate is the SipHash message.
	keyHex := "00112233445566778899aabbccddeeff"
	longTag, _ := sipHashHashcatHex(pass, keyHex, 2, 4)
	long := fmt.Sprintf("%s:2:4:%s", longTag, keyHex)
	if ok, err := verifySipHash(long, pass, ""); err != nil || !ok {
		t.Errorf("long-form verify: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifySipHash(long, "wrong", ""); bad {
		t.Error("long-form verify accepted a wrong password")
	}
	if !isSipHash(long) {
		t.Error("isSipHash rejected a well-formed long-form hash")
	}

	// Short form takes the message from -s.
	if ok, err := verifyCandidate(pass, tag, "siphash", "\x00\x11\x22\x33\x44\x55\x66\x77", "prefix"); err != nil || !ok {
		t.Errorf("short-form verify: ok=%v err=%v", ok, err)
	}

	// A non-default round count in the hash line must actually be honoured.
	oddTag, _ := sipHashHashcatHex(pass, keyHex, 4, 8)
	odd := fmt.Sprintf("%s:4:8:%s", oddTag, keyHex)
	if ok, err := verifySipHash(odd, pass, ""); err != nil || !ok {
		t.Errorf("SipHash-4-8 verify: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifySipHash(odd, pass+"x", ""); bad {
		t.Error("SipHash-4-8 accepted a wrong password")
	}
}

func TestSipHashRejectsMalformedHashes(t *testing.T) {
	for _, bad := range []string{
		"nothex0000000000:2:4:00", "0011223344556677:0:4:00",
		"0011223344556677:2:0:00", "0011223344556677:2:4:zz",
		"short:2:4:00", "0011223344556677:2:4", "00112233445566",
	} {
		if ok, err := verifySipHash(bad, "pw", ""); ok || err == nil {
			t.Errorf("verifySipHash(%q) = %v, %v; want a rejection", bad, ok, err)
		}
	}
}
