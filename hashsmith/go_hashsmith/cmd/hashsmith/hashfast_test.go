package main

import (
	"bytes"
	"testing"
)

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
		// matchBytes must agree with match on both a matching and a
		// non-matching candidate. This is the only place every one of the
		// 11 fast types (including sha224/sha384, which aren't in
		// benchDefaultTypes and so are never exercised by `hashsmith
		// benchmark`) gets its matchBytes return value actually checked
		// against a real matching target, rather than just measured for
		// allocations.
		if !f.matchBytes([]byte(c.pw)) {
			t.Errorf("%s: matchBytes failed to match %q", c.typ, c.pw)
		}
		if f.matchBytes([]byte(c.pw + "x")) {
			t.Errorf("%s: matchBytes false-matched", c.typ)
		}
	}
}

// TestRawHasherBytesMatchesRawHasher is a differential test between
// rawHasher and rawHasherBytes: rawHasherBytes is a hand-maintained parallel
// implementation covering the same 11 types, and nothing else in the suite
// compares their outputs directly. A divergence introduced here (e.g. while
// wiring matchBytes into the real cracking path in a later task) would
// otherwise only surface as wrong crack results far from its cause. This
// asserts byte-identical digests from both hashers, for every shared type,
// across empty, plain-ASCII, and multi-byte UTF-8 inputs — the UTF-8 case
// matters because ntlm's byte path re-encodes through utf16le(string(s)).
func TestRawHasherBytesMatchesRawHasher(t *testing.T) {
	types := []string{
		"md5", "sha1", "sha224", "sha256", "sha384", "sha512",
		"blake2b", "blake2s", "md4", "ntlm", "ripemd160",
	}
	inputs := []string{
		"",             // empty
		"password",     // plain ASCII
		"héllo, 世界! 🎉", // multi-byte UTF-8
	}
	for _, typ := range types {
		hs, ok := rawHasher(typ)
		if !ok {
			t.Errorf("%s: rawHasher has no entry", typ)
			continue
		}
		hb, ok := rawHasherBytes(typ)
		if !ok {
			t.Errorf("%s: rawHasherBytes has no entry", typ)
			continue
		}
		for _, in := range inputs {
			var dstStr, dstBytes [64]byte
			nStr := hs(dstStr[:], in)
			nBytes := hb(dstBytes[:], []byte(in))
			if nStr != nBytes {
				t.Errorf("%s(%q): rawHasher wrote %d bytes, rawHasherBytes wrote %d",
					typ, in, nStr, nBytes)
				continue
			}
			if !bytes.Equal(dstStr[:nStr], dstBytes[:nBytes]) {
				t.Errorf("%s(%q): rawHasher and rawHasherBytes disagree: %x vs %x",
					typ, in, dstStr[:nStr], dstBytes[:nBytes])
			}
		}
	}
}
