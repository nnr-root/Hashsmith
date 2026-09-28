package smith

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// TestDescryptFastMatchesReference is the whole warrant for the faster code:
// it must compute exactly what the bit-at-a-time version computes. The
// reference stays in the tree for this reason, and is the authority here —
// the fast version is never compared against itself.
func TestDescryptFastRoundFunctionMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		r := rng.Uint64() & 0xffffffff
		subkey := rng.Uint64() & 0xffffffffffff
		salt := uint32(rng.Intn(1 << 12))
		want := desFeistel(r, subkey, salt)
		got := desFeistelFast(r, subkey, descryptSaltMask(salt))
		if got != want {
			t.Fatalf("r=%08x subkey=%012x salt=%03x: fast %08x, reference %08x",
				r, subkey, salt, got, want)
		}
	}
}

// Every salt value, against a fixed input, so no salt bit pattern escapes by
// chance. The salt is only 12 bits, so this is exhaustive over it.
func TestDescryptSaltSwapIsExhaustivelyCorrect(t *testing.T) {
	const r = 0x0123abcd
	const subkey = 0x1234_5678_9abc
	for salt := uint32(0); salt < 1<<12; salt++ {
		want := desFeistel(r, subkey, salt)
		got := desFeistelFast(r, subkey, descryptSaltMask(salt))
		if got != want {
			t.Fatalf("salt=%03x: fast %08x, reference %08x", salt, got, want)
		}
	}
}

// And the whole block, which folds in the round ordering and the final
// permutation as well as the round function.
func TestDescryptFastBlockMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 3000; i++ {
		key := rng.Uint64()
		block := rng.Uint64()
		salt := uint32(rng.Intn(1 << 12))
		ks := desSubkeys(key)
		want := desEncryptBlock(block, ks, salt)
		got := desEncryptBlockFast(block, &ks, descryptSaltMask(salt))
		if got != want {
			t.Fatalf("key=%016x block=%016x salt=%03x: fast %016x, reference %016x",
				key, block, salt, got, want)
		}
	}
}

// TestDesIterateZeroBlockMatchesReference checks the IP-domain rewrite against
// the separate encryptions it replaces, computed with the bit-at-a-time block
// function. Round counts include descrypt's 25 and several BSDi-shaped ones,
// and the salt spans the full 24 bits BSDi uses rather than descrypt's 12.
func TestDesIterateZeroBlockMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, rounds := range []int{1, 2, 25, 26, 101} {
		for i := 0; i < 60; i++ {
			key := rng.Uint64()
			salt := uint32(rng.Intn(1 << 24))
			ks := desSubkeys(key)

			var want uint64
			for j := 0; j < rounds; j++ {
				want = desEncryptBlock(want, ks, salt)
			}
			got := desIterateZeroBlock(&ks, descryptSaltMask(salt), rounds)
			if got != want {
				t.Fatalf("rounds=%d key=%016x salt=%06x: fused %016x, repeated calls %016x",
					rounds, key, salt, got, want)
			}
		}
	}
}

func BenchmarkDescryptFeistel(b *testing.B) {
	const r = 0x0123abcd
	const subkey = 0x1234_5678_9abc
	const salt = 0x0a5
	b.Run("reference", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = desFeistel(r, subkey, salt)
		}
	})
	b.Run("sp-boxes", func(b *testing.B) {
		mask := descryptSaltMask(salt)
		for i := 0; i < b.N; i++ {
			_ = desFeistelFast(r, subkey, mask)
		}
	})
}

// TestDesSubkeysFastMatchesReference holds the byte-driven key schedule to the
// bit-at-a-time one, which stays in the tree as the authority. A wrong subkey
// fails identically to a wrong password: no signal, just nothing found.
func TestDesSubkeysFastMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		key := rng.Uint64()
		want := desSubkeys(key)
		got := desSubkeysFast(key)
		if got != want {
			t.Fatalf("key=%016x: fast schedule differs from the reference\n got  %v\n want %v",
				key, got, want)
		}
	}
	// And the edges, which a random sample will not reach.
	for _, key := range []uint64{0, ^uint64(0), 1, 1 << 63, 0x0101010101010101} {
		if got, want := desSubkeysFast(key), desSubkeys(key); got != want {
			t.Fatalf("key=%016x: fast schedule differs from the reference", key)
		}
	}
}

// ── Interleaved lanes ────────────────────────────────────────────────────────

// TestDescryptLanesMatchScalar holds the interleaved inner loop to the
// one-at-a-time one. They compute the same thing or the lanes are worthless.
func TestDescryptLanesMatchScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for trial := 0; trial < 200; trial++ {
		var ks [descryptLanes][16]uint64
		for k := range ks {
			ks[k] = desSubkeysFast(rng.Uint64())
		}
		mask := descryptSaltMask(uint32(rng.Intn(1 << 12)))
		got := descryptIterateLanes(&ks, mask)
		for k := range ks {
			if want := desIterateZeroBlock(&ks[k], mask, 25); got[k] != want {
				t.Fatalf("trial %d lane %d: %016x, want %016x", trial, k, got[k], want)
			}
		}
	}
}

// TestDescryptLaneHasherMatchesVerify is the differential that matters: for
// every candidate, the laned verdict and the scalar verifier's must agree.
//
// The batch sizes deliberately straddle the lane width, because a partial
// group is where a laned implementation goes wrong — by leaving a previous
// call's key schedule in the unused lanes, or by reading a verdict from one.
func TestDescryptLaneHasherMatchesVerify(t *testing.T) {
	// A real record: "password" under salt "ab", from selftest_vectors.go.
	const record = "abJnggxhB/yWI"
	h := newDescryptLaneHasher(record)
	if h == nil {
		t.Fatal("newDescryptLaneHasher refused a valid descrypt record")
	}

	candidates := []string{
		"password", "wrong", "", "a", "12345678", "123456789",
		"passwore", "passwor", "PASSWORD", "password1", "café",
	}
	for n := 1; n <= len(candidates); n++ {
		n := n
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			pw := make([][]byte, n)
			for i := 0; i < n; i++ {
				pw[i] = []byte(candidates[i])
			}
			out := make([]bool, n)
			h.Run(pw, out)
			for i := 0; i < n; i++ {
				want, err := verifyDescrypt(record, candidates[i])
				if err != nil {
					t.Fatalf("verifyDescrypt(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q: laned says %v, scalar says %v",
						n, candidates[i], out[i], want)
				}
			}
		})
	}
}

// TestDescryptLaneHasherIsStateless pins the partial-group rule: running a
// short batch after a full one must not let the earlier call's key schedules
// influence it.
func TestDescryptLaneHasherIsStateless(t *testing.T) {
	const record = "abJnggxhB/yWI"
	h := newDescryptLaneHasher(record)
	if h == nil {
		t.Fatal("no hasher")
	}
	full := [][]byte{[]byte("password"), []byte("aaaa"), []byte("bbbb"), []byte("cccc")}
	out := make([]bool, 4)
	h.Run(full, out)
	if !out[0] {
		t.Fatal("the right password did not verify in a full group")
	}
	// Now a single wrong candidate. A stale lane would still hold
	// "password"'s schedule; reading its verdict would report a false hit.
	one := [][]byte{[]byte("nope")}
	out1 := make([]bool, 1)
	h.Run(one, out1)
	if out1[0] {
		t.Fatal("a wrong candidate verified after a batch containing the right one")
	}
	// And the right password still verifies afterwards.
	h.Run([][]byte{[]byte("password")}, out1)
	if !out1[0] {
		t.Fatal("the right password stopped verifying after a wrong one")
	}
}

// TestDescryptLaneHasherRefusesNonRecords keeps the factory honest: it must
// decline anything that is not a descrypt record rather than hash against a
// target it cannot compare with.
func TestDescryptLaneHasherRefusesNonRecords(t *testing.T) {
	for _, bad := range []string{
		"", "abc", "$1$abc$def", strings.Repeat("a", 12), strings.Repeat("a", 14),
		"ab!nggxhB/yWI", // '!' is not crypt-base64
	} {
		if newDescryptLaneHasher(bad) != nil {
			t.Errorf("accepted %q as a descrypt record", bad)
		}
	}
}

// BenchmarkDescryptLaneHasherRun measures the hot verdict path: one Run()
// call per group of descryptLanes candidates, all non-matching (the common
// case in a real crack). It exists to keep descryptPackInto's zero-allocation
// claim honest against a benchmark rather than a comment.
func BenchmarkDescryptLaneHasherRun(b *testing.B) {
	const record = "abJnggxhB/yWI"
	h := newDescryptLaneHasher(record)
	if h == nil {
		b.Fatal("newDescryptLaneHasher refused a valid descrypt record")
	}
	pw := make([][]byte, descryptLanes)
	for i := range pw {
		pw[i] = []byte("wrongpw1")
	}
	out := make([]bool, descryptLanes)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Run(pw, out)
	}
}
