package main

import (
	"bytes"
	"testing"
)

func TestRedHat389PBKDF2RoundTrip(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5a}, redHat389SaltLen)
	target, err := encodeRedHat389PBKDF2("hashsmith", salt, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := verifyRedHat389PBKDF2(target, "hashsmith"); err != nil || !ok {
		t.Fatalf("389-DS PBKDF2 vector failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyRedHat389PBKDF2(target, "wrong"); ok {
		t.Fatal("389-DS PBKDF2 accepted the wrong password")
	}
	if got := detectHashTypes(target); len(got) != 1 || got[0] != "ldap-pbkdf2" {
		t.Fatalf("detectHashTypes(389-DS) = %v", got)
	}
}

func TestRedHat389PBKDF2RejectsMalformedRecords(t *testing.T) {
	for _, target := range []string{
		"{PBKDF2_SHA256}AAAA",
		"{PBKDF2_SHA256}not-base64!",
		"{PBKDF2_SHA512}AAAA",
	} {
		if _, err := parseRedHat389PBKDF2(target); err == nil {
			t.Errorf("accepted malformed 389-DS record %q", target)
		}
	}
}
