package smith

import (
	"math/rand"
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
