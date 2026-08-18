package main

import "testing"

// macOS, Atlassian, and JWT vectors (passphrase/secret "hashsmith"), generated
// with Python's hashlib/hmac.
func TestAppVectors(t *testing.T) {
	macos := "$ml$1000$00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff$1f3e3cbfd3ff3d4020595957d886af6bfd081bfd7706734736d57780340b88806a9f92b21f7609ca2ace446c80d8db7162cee1e0c772f18e779c37ce3f7d2a7782007fcc031dcac973e14604f3632435d84213dd073a7dca187ac47c289a7b04ffe7003c27e8723cc7dc5c878831296485d5ce6eec3c5b00e23aac1db80ea11d"
	checkApp(t, "macos", verifyMacOS, macos)

	atlassian := "{PKCS5S2}ABEiM0RVZneImQCqu8zd7veGLWg0t3824DHQ9UQSJl9E1mxWba+TgfXT8+FCY2s7"
	checkApp(t, "atlassian", verifyAtlassian, atlassian)

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbWl0aCIsImFkbWluIjp0cnVlfQ.FnpR61iqT7rqJqNFIrEz9AkzR8LySOtfK-koWIhz1ZY"
	if ok, err := verifyJWT(jwt, "hashsmith"); err != nil || !ok {
		t.Errorf("JWT verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyJWT(jwt, "wrong"); ok {
		t.Error("JWT should reject the wrong secret")
	}
	if got := detectHashTypes(jwt); len(got) != 1 || got[0] != "jwt" {
		t.Errorf("detectHashTypes(jwt) = %v, want [jwt]", got)
	}
}

func checkApp(t *testing.T, name string, fn func(string, string) (bool, error), line string) {
	t.Helper()
	if ok, err := fn(line, "hashsmith"); err != nil || !ok {
		t.Errorf("%s verify failed: ok=%v err=%v", name, ok, err)
	}
	if ok, _ := fn(line, "wrong"); ok {
		t.Errorf("%s should reject the wrong passphrase", name)
	}
	if got := detectHashTypes(line); len(got) != 1 || got[0] != name {
		t.Errorf("detectHashTypes(%s) = %v, want [%s]", name, got, name)
	}
}
