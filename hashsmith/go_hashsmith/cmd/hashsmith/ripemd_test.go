package main

import (
	"encoding/hex"
	"hash"
	"testing"
)

// Published RIPEMD test vectors from the Bosselaers reference suite.
func TestRIPEMDVectors(t *testing.T) {
	cases := []struct {
		name string
		new  func() hash.Hash
		in   string
		want string
	}{
		{"RIPEMD-128", newRIPEMD128, "", "cdf26213a150dc3ecb610f18f6b38b46"},
		{"RIPEMD-128", newRIPEMD128, "a", "86be7afa339d0fc7cfc785e72f578d33"},
		{"RIPEMD-128", newRIPEMD128, "abc", "c14a12199c66e4ba84636b0f69144c77"},
		{"RIPEMD-128", newRIPEMD128, "message digest", "9e327b3d6e523062afc1132d7df9d1b8"},
		{"RIPEMD-256", newRIPEMD256, "", "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"},
		{"RIPEMD-256", newRIPEMD256, "abc", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"},
		{"RIPEMD-320", newRIPEMD320, "", "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"},
		{"RIPEMD-320", newRIPEMD320, "abc", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d"},
	}
	for _, c := range cases {
		h := c.new()
		_, _ = h.Write([]byte(c.in))
		if got := hex.EncodeToString(h.Sum(nil)); got != c.want {
			t.Errorf("%s(%q) = %s, want %s", c.name, c.in, got, c.want)
		}
	}
}

// A digest fed one byte at a time must agree with a single Write, and Sum must
// not disturb a digest that is still being written to.
func TestRIPEMDStreamingAndSumIsPure(t *testing.T) {
	const msg = "The quick brown fox jumps over the lazy dog"
	for _, newHash := range []func() hash.Hash{newRIPEMD128, newRIPEMD256, newRIPEMD320} {
		one := newHash()
		_, _ = one.Write([]byte(msg))
		want := hex.EncodeToString(one.Sum(nil))

		drip := newHash()
		for i := 0; i < len(msg); i++ {
			_, _ = drip.Write([]byte{msg[i]})
			drip.Sum(nil) // interim Sum must not corrupt the running state
		}
		if got := hex.EncodeToString(drip.Sum(nil)); got != want {
			t.Errorf("byte-at-a-time = %s, want %s", got, want)
		}
		// Sum is idempotent.
		if got := hex.EncodeToString(one.Sum(nil)); got != want {
			t.Errorf("second Sum = %s, want %s", got, want)
		}
	}
}

// Messages that straddle the 64-byte block and the 56-byte padding boundary are
// where length handling usually breaks.
func TestRIPEMDBlockBoundaries(t *testing.T) {
	for _, n := range []int{54, 55, 56, 57, 63, 64, 65, 119, 120, 128} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte('a' + i%26)
		}
		h := newRIPEMD128()
		_, _ = h.Write(msg)
		full := hex.EncodeToString(h.Sum(nil))

		split := newRIPEMD128()
		_, _ = split.Write(msg[:n/2])
		_, _ = split.Write(msg[n/2:])
		if got := hex.EncodeToString(split.Sum(nil)); got != full {
			t.Errorf("len %d: split write = %s, want %s", n, got, full)
		}
	}
}

// The digests must be reachable through the normal -t plumbing.
func TestRIPEMDThroughHashText(t *testing.T) {
	cases := map[string]string{
		"ripemd128":  "c14a12199c66e4ba84636b0f69144c77",
		"ripemd-128": "c14a12199c66e4ba84636b0f69144c77",
		"ripemd256":  "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
		"ripemd320":  "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
	}
	for typ, want := range cases {
		got, err := hashText("abc", typ, "", "prefix")
		if err != nil || got != want {
			t.Errorf("hashText(abc, %s) = %q, %v; want %s", typ, got, err, want)
		}
		ok, err := verifyCandidate("abc", want, typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("verifyCandidate(%s): ok=%v err=%v", typ, ok, err)
		}
		if bad, _ := verifyCandidate("wrong", want, typ, "", "prefix"); bad {
			t.Errorf("%s accepted a wrong password", typ)
		}
	}
}
