package bcryptlane

import (
	"bytes"
	"math/rand"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// randPassword returns the awkward cases on purpose: bcrypt's bug-compatible
// trailing NUL, its circular key reuse, and its 23-of-24-byte encoding all show
// up at boundaries, not in the middle.
func randPassword(rng *rand.Rand) []byte {
	switch rng.Intn(8) {
	case 0:
		return []byte{}
	case 1:
		return []byte("a")
	case 2:
		return bytes.Repeat([]byte("x"), 72)
	case 3:
		return bytes.Repeat([]byte("y"), 100)
	case 4:
		return []byte("pass\x00word")
	case 5:
		return []byte("pässwörd–ünïcode")
	default:
		n := 1 + rng.Intn(40)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(33 + rng.Intn(94))
		}
		return b
	}
}

func TestRunMatchesXCrypto(t *testing.T) {
	rng := rand.New(rand.NewSource(20260906))
	for i := 0; i < 300; i++ {
		cost := 4 + rng.Intn(3) // 4..6 keeps the suite fast; costs 7-10 in TestRunMatchesXCryptoSlow
		pw := randPassword(rng)
		crypt, err := bcrypt.GenerateFromPassword(pw, cost)
		if err == bcrypt.ErrPasswordTooLong {
			// x/crypto's GenerateFromPassword itself refuses to create a hash
			// for a >72-byte password (that check lives only at generation
			// time, not in CompareHashAndPassword or our Run - both hash the
			// full key with circular reuse and never truncate). There is no
			// exported x/crypto API to build a fixture from a >72-byte
			// password, so this iteration's shape can't be exercised as a
			// "correct password" case; the >72-byte comparison path is still
			// covered below via the "wrong" password derived by appending
			// '!' to the 72-byte case.
			continue
		}
		if err != nil {
			t.Fatalf("GenerateFromPassword(%q, %d): %v", pw, cost, err)
		}
		h, err := NewHasher(string(crypt))
		if err != nil {
			t.Fatalf("NewHasher(%q): %v", crypt, err)
		}
		out := make([]bool, 1)
		h.Run([][]byte{pw}, out)
		if !out[0] {
			t.Errorf("case %d: correct password %q rejected for %s", i, pw, crypt)
		}
		wrong := append(append([]byte{}, pw...), '!')
		h.Run([][]byte{wrong}, out)
		want := bcrypt.CompareHashAndPassword(crypt, wrong) == nil
		if out[0] != want {
			t.Errorf("case %d: %q against %s: got %v, x/crypto says %v", i, wrong, crypt, out[0], want)
		}
	}
}

// TestRunMatchesXCryptoSlow covers the costs real targets use. It is slow by
// nature; -short skips it.
func TestRunMatchesXCryptoSlow(t *testing.T) {
	if testing.Short() {
		t.Skip("cost 7-10 bcrypt; run without -short")
	}
	rng := rand.New(rand.NewSource(6092026))
	for cost := 7; cost <= 10; cost++ {
		pw := randPassword(rng)
		crypt, err := bcrypt.GenerateFromPassword(pw, cost)
		if err == bcrypt.ErrPasswordTooLong {
			// See the matching comment in TestRunMatchesXCrypto: generation,
			// not comparison, is where x/crypto enforces the 72-byte cap.
			continue
		}
		if err != nil {
			t.Fatalf("cost %d: %v", cost, err)
		}
		h, err := NewHasher(string(crypt))
		if err != nil {
			t.Fatalf("cost %d: NewHasher: %v", cost, err)
		}
		out := make([]bool, 1)
		h.Run([][]byte{pw}, out)
		if !out[0] {
			t.Errorf("cost %d: correct password rejected", cost)
		}
	}
}

// TestRunMatchesXCryptoOver72Bytes exercises the >=72-byte comparison path
// directly against bcrypt.CompareHashAndPassword, which - unlike
// GenerateFromPassword - has no length check at all. This is testable even
// though GenerateFromPassword cannot build a >72-byte fixture: build the
// target from exactly 72 bytes, then compare long candidates against it.
func TestRunMatchesXCryptoOver72Bytes(t *testing.T) {
	base := bytes.Repeat([]byte("x"), 72)
	crypt, err := bcrypt.GenerateFromPassword(base, 4)
	if err != nil {
		t.Fatalf("GenerateFromPassword(72 bytes): %v", err)
	}
	h, err := NewHasher(string(crypt))
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	out := make([]bool, 1)

	// 100 bytes sharing the same first 72. Blowfish's key schedule XORs exactly
	// 18 words of 4 bytes into the P-array, so bytes past 72 are never read and
	// this must MATCH — on both sides, identically.
	long := append(append([]byte{}, base...), bytes.Repeat([]byte("z"), 28)...)
	h.Run([][]byte{long}, out)
	if want := bcrypt.CompareHashAndPassword(crypt, long) == nil; out[0] != want {
		t.Errorf("100-byte same-prefix password: got %v, want %v", out[0], want)
	}

	// Same length, but differing INSIDE the first 72 bytes: must not match.
	diverged := append([]byte{}, long...)
	diverged[10] ^= 0xFF
	h.Run([][]byte{diverged}, out)
	if want := bcrypt.CompareHashAndPassword(crypt, diverged) == nil; out[0] != want {
		t.Errorf("divergent >72-byte password: got %v, want %v", out[0], want)
	}
}

// TestNewHasherRejects pins the parser to x/crypto's acceptance set. Where
// x/crypto errors, NewHasher must error too - a target Hashsmith would have
// refused before must not silently start being cracked against a misparse.
func TestNewHasherRejects(t *testing.T) {
	valid := "$2a$05$24WDYwDgT9qSmz02emE1F.0YDG14PWmeoq8n.xCD71R7fA8/A2TxC"
	bad := []string{
		"", "$1$abc", "not a hash",
		valid[:len(valid)-1],  // truncated
		"$2a$99$" + valid[7:], // cost out of range
		"$2a$0x$" + valid[7:], // non-numeric cost
		"$3a$05$" + valid[7:], // version too new
	}
	for _, s := range bad {
		if _, err := NewHasher(s); err == nil {
			t.Errorf("NewHasher(%q) accepted, want error", s)
		}
	}
	if _, err := NewHasher(valid); err != nil {
		t.Errorf("NewHasher(valid) = %v, want nil", err)
	}
	// Every minor version x/crypto accepts, this must accept.
	for _, minor := range []string{"$2$", "$2a$", "$2b$", "$2x$", "$2y$"} {
		s := minor + valid[4:]
		if _, err := NewHasher(s); err != nil {
			t.Errorf("NewHasher(%q) = %v, want nil", s, err)
		}
	}
}
