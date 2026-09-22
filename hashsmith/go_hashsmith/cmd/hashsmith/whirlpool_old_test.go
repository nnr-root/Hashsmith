package main

import (
	"encoding/hex"
	"hash"
	"strings"
	"testing"
)

// John's own vectors for its whirlpool0 and whirlpool1 formats. Both are the
// empty message, which is the case that reaches the padding with nothing else
// in it — and Whirlpool's padding carries a 256-bit length, four times the
// usual width, so it is worth having a vector that is nothing but padding.
//
// The second pair goes the other direction: Hashsmith computed them, and John
// recovered the plaintext from both under the matching format.
func TestWhirlpoolOldRevisions(t *testing.T) {
	for _, tc := range []struct {
		name, msg, want string
		new             func() hash.Hash
	}{
		{"whirlpool0", "", "b3e1ab6eaf640a34f784593f2074416accd3b8e62c620175fca0997b1ba2347339aa0d79e754c308209ea36811dfa40c1c32f1a2b9004725d987d3635165d3c8", newWhirlpool0},
		{"whirlpool-t", "", "470f0409abaa446e49667d4ebe12a14387cedbd10dd17b8243cad550a089dc0feea7aa40f6c2aaab71c6ebd076e43c7cfca0ad32567897dcb5969861049a0f5a", newWhirlpoolT},
		{"whirlpool0", "hashsmith", "e7ef990059d3a12b87888614b0915a193d72c8bf5647961622bbe383433e66b6ecbbb0d1ac5e94cb697a323694b957b9a575b123ce37ee4d7cf93dfca37fe7cf", newWhirlpool0},
		{"whirlpool-t", "hashsmith", "c5033622ed1d393183253077f2d279a85319dacc6091383a461d5d49cb68f4a6862d94ec882990336d6e0620d47da636e3ccebeaeddb9ed270f2ac844859d3a5", newWhirlpoolT},
	} {
		h := tc.new()
		_, _ = h.Write([]byte(tc.msg))
		if got := hex.EncodeToString(h.Sum(nil)); got != tc.want {
			t.Errorf("%s(%q) = %s, want %s", tc.name, tc.msg, got, tc.want)
		}
	}
}

// A message long enough to need several blocks, written one byte at a time,
// must agree with the same message written at once.
func TestWhirlpoolOldStreaming(t *testing.T) {
	msg := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40)
	for _, tc := range []struct {
		name string
		new  func() hash.Hash
	}{
		{"whirlpool0", newWhirlpool0},
		{"whirlpool-t", newWhirlpoolT},
	} {
		whole := tc.new()
		_, _ = whole.Write([]byte(msg))
		piecemeal := tc.new()
		for i := 0; i < len(msg); i++ {
			_, _ = piecemeal.Write([]byte(msg[i : i+1]))
		}
		if a, b := hex.EncodeToString(whole.Sum(nil)), hex.EncodeToString(piecemeal.Sum(nil)); a != b {
			t.Errorf("%s byte-at-a-time = %s, all at once = %s", tc.name, b, a)
		}
	}
}
