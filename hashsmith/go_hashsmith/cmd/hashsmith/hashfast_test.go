package main

import "testing"

func TestFastVerifierMatchesGeneric(t *testing.T) {
	cases := []struct{ typ, pw string }{
		{"md5", "password"}, {"sha1", "hello"}, {"sha256", "abc"},
		{"sha512", "xyz"}, {"sha224", "q"}, {"sha384", "w"},
		{"ntlm", "Password1"}, {"md4", "test"}, {"ripemd160", "data"},
		{"blake2b", "b2"}, {"blake2s", "b2s"},
	}
	for _, c := range cases {
		target, _ := hashText(c.pw, c.typ, "", "prefix")
		f, ok := newFastVerifier(c.typ, target)
		if !ok {
			t.Errorf("%s: no fast verifier", c.typ)
			continue
		}
		if !f.match(c.pw) {
			t.Errorf("%s: fast verifier failed to match %q", c.typ, c.pw)
		}
		if f.match(c.pw + "x") {
			t.Errorf("%s: fast verifier false-matched", c.typ)
		}
	}
}
