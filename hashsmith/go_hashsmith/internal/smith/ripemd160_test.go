package smith

import (
	"crypto/hmac"
	"encoding"
	"encoding/hex"
	"hash"
	"math/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

// The published RIPEMD-160 vectors from Dobbertin, Bosselaers and Preneel,
// "RIPEMD-160: A Strengthened Version of RIPEMD" (1996), appendix B.
func TestRIPEMD160PublishedVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
		{"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"},
		{"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb"}, // 8 x "1234567890"
	}
	for _, c := range cases {
		h := newRIPEMD160()
		_, _ = h.Write([]byte(c.in))
		if got := hex.EncodeToString(h.Sum(nil)); got != c.want {
			t.Errorf("RIPEMD160(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	// The million-a vector, the only one that exercises the length counter
	// past a single block count.
	h := newRIPEMD160()
	chunk := strings.Repeat("a", 1000)
	for i := 0; i < 1000; i++ {
		_, _ = h.Write([]byte(chunk))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != "52783243c1697bdbe16d37f97f68f08325dc1528" {
		t.Errorf("RIPEMD160(1e6 x 'a') = %s, want 52783243c1697bdbe16d37f97f68f08325dc1528", got)
	}
}

// The native implementation replaced golang.org/x/crypto/ripemd160 on the
// VeraCrypt path. Nothing about that is worth doing if the two disagree, so
// they are compared over random inputs at every length that straddles a block
// boundary, and over split writes, which is where a buffered implementation
// goes wrong if it goes wrong at all.
func TestRIPEMD160MatchesXCrypto(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for n := 0; n <= 200; n++ {
		msg := make([]byte, n)
		rnd.Read(msg)

		want := ripemd160.New()
		_, _ = want.Write(msg)

		got := newRIPEMD160()
		_, _ = got.Write(msg)
		if string(got.Sum(nil)) != string(want.Sum(nil)) {
			t.Fatalf("length %d: native and x/crypto disagree", n)
		}

		// Same message, delivered in two writes at every split point.
		for split := 0; split <= n; split++ {
			s := newRIPEMD160()
			_, _ = s.Write(msg[:split])
			_, _ = s.Write(msg[split:])
			if string(s.Sum(nil)) != string(want.Sum(nil)) {
				t.Fatalf("length %d split at %d: split write disagrees", n, split)
			}
		}
	}
}

// Sum must not disturb a digest that is still being written to.
func TestRIPEMDSumDoesNotConsumeState(t *testing.T) {
	for _, newHash := range []func() hash.Hash{newRIPEMD128, newRIPEMD160, newRIPEMD256, newRIPEMD320} {
		h := newHash()
		_, _ = h.Write([]byte("abc"))
		first := string(h.Sum(nil))
		if again := string(h.Sum(nil)); again != first {
			t.Fatalf("size %d: Sum is not idempotent", h.Size())
		}
		_, _ = h.Write([]byte("def"))
		full := newHash()
		_, _ = full.Write([]byte("abcdef"))
		if string(h.Sum(nil)) != string(full.Sum(nil)) {
			t.Fatalf("size %d: writing after Sum diverged", h.Size())
		}
		h.Reset()
		fresh := newHash()
		if string(h.Sum(nil)) != string(fresh.Sum(nil)) {
			t.Fatalf("size %d: Reset did not restore the initial state", h.Size())
		}
	}
}

// The marshaler is not a feature anyone asked for — it exists so crypto/hmac
// can cache the ipad and opad states. If it round-trips wrongly, every HMAC
// built on these hashes is silently wrong, so it is checked at every offset
// within a block rather than at one convenient length.
func TestRIPEMDMarshalRoundTrip(t *testing.T) {
	for _, newHash := range []func() hash.Hash{newRIPEMD128, newRIPEMD160, newRIPEMD256, newRIPEMD320} {
		for n := 0; n <= 130; n++ {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(i * 7)
			}
			saved := newHash()
			_, _ = saved.Write(msg)
			state, err := saved.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Fatalf("size %d length %d: %v", saved.Size(), n, err)
			}
			restored := newHash()
			if err := restored.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Fatalf("size %d length %d: %v", saved.Size(), n, err)
			}
			tail := []byte("tail bytes past the restore point")
			_, _ = saved.Write(tail)
			_, _ = restored.Write(tail)
			if string(saved.Sum(nil)) != string(restored.Sum(nil)) {
				t.Fatalf("size %d length %d: restored state diverged", saved.Size(), n)
			}
		}
	}
}

// A state from one width must not restore into another. They are otherwise
// plausible byte strings and a silent mismatch would corrupt a digest.
func TestRIPEMDMarshalRejectsForeignState(t *testing.T) {
	state, err := newRIPEMD160().(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := newRIPEMD320().(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err == nil {
		t.Error("a RIPEMD-160 state was accepted by RIPEMD-320")
	}
	if err := newRIPEMD160().(encoding.BinaryUnmarshaler).UnmarshalBinary(state[:len(state)-1]); err == nil {
		t.Error("a truncated state was accepted")
	}
	if err := newRIPEMD160().(encoding.BinaryUnmarshaler).UnmarshalBinary(nil); err == nil {
		t.Error("an empty state was accepted")
	}
}

// HMAC and PBKDF2 over the native hash must match the x/crypto hash exactly.
// This is the check that actually covers the VeraCrypt change: the marshaler
// makes crypto/hmac take a different code path, so agreeing on bare digests
// proves nothing about agreeing here.
func TestRIPEMD160HMACAndPBKDF2MatchXCrypto(t *testing.T) {
	key := []byte("a key longer than nothing")
	msg := []byte("the message")
	want := hmac.New(ripemd160.New, key)
	_, _ = want.Write(msg)
	got := hmac.New(newRIPEMD160, key)
	_, _ = got.Write(msg)
	if string(got.Sum(nil)) != string(want.Sum(nil)) {
		t.Fatal("HMAC-RIPEMD160 differs between native and x/crypto")
	}
	// A key longer than the 64-byte block, which HMAC hashes down first.
	long := make([]byte, 200)
	for i := range long {
		long[i] = byte(i)
	}
	want = hmac.New(ripemd160.New, long)
	_, _ = want.Write(msg)
	got = hmac.New(newRIPEMD160, long)
	_, _ = got.Write(msg)
	if string(got.Sum(nil)) != string(want.Sum(nil)) {
		t.Fatal("HMAC-RIPEMD160 with an oversized key differs")
	}
	// dkLen 192 is VeraCrypt's cascade width: ten PBKDF2 blocks at 20 bytes.
	a := pbkdf2.Key([]byte("passphrase"), []byte("salt"), 37, 192, ripemd160.New)
	b := pbkdf2.Key([]byte("passphrase"), []byte("salt"), 37, 192, newRIPEMD160)
	if string(a) != string(b) {
		t.Fatal("PBKDF2-HMAC-RIPEMD160 differs between native and x/crypto")
	}
}
