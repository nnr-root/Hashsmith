package smith

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"math/rand"
	"testing"
)

// hmacSHA256Reference computes HMAC-SHA256 via crypto/hmac directly — the
// independent oracle every case in this file is checked against.
func hmacSHA256Reference(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func hmacViaContinuation(key, message []byte) [32]byte {
	kb := hmacSHA256KeyBlock(key)
	inner := hmacSHA256InnerOuterIV(kb, 0x36)
	outer := hmacSHA256InnerOuterIV(kb, 0x5c)
	return hmacSHA256FromInnerOuter(inner, outer, message)
}

// TestHMACSHA256ContinuationMatchesReference is the load-bearing
// correctness check for the whole PBKDF2 lane hasher: every message length
// that matters (0, the block-boundary neighbourhood at 55/56/63/64/65, and
// a message spanning two full blocks plus a tail) against both a short and
// a >64-byte (hashed-down) key.
func TestHMACSHA256ContinuationMatchesReference(t *testing.T) {
	keys := [][]byte{
		[]byte(""),
		[]byte("short-key"),
		bytes.Repeat([]byte{0x42}, 64),  // exactly one block, no hashing needed
		bytes.Repeat([]byte{0x42}, 65),  // one byte over — must be hashed down
		bytes.Repeat([]byte{0x42}, 200), // well over
	}
	lengths := []int{0, 1, 31, 32, 55, 56, 63, 64, 65, 96, 119, 120, 121, 200}
	for _, key := range keys {
		for _, n := range lengths {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(i)
			}
			want := hmacSHA256Reference(key, msg)
			got := hmacViaContinuation(key, msg)
			if !bytes.Equal(got[:], want) {
				t.Fatalf("key len %d, msg len %d: got %x, want %x", len(key), n, got, want)
			}
		}
	}
}

// TestHMACSHA256ContinuationRandomMatchesReference extends the boundary
// table above with fully randomized keys and messages.
func TestHMACSHA256ContinuationRandomMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 500; i++ {
		key := make([]byte, rng.Intn(150))
		rng.Read(key)
		msg := make([]byte, rng.Intn(300))
		rng.Read(msg)
		want := hmacSHA256Reference(key, msg)
		got := hmacViaContinuation(key, msg)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("key %x msg %x: got %x, want %x", key, msg, got, want)
		}
	}
}

// TestSHA256ScalarSumMatchesCryptoSHA256 checks the plain-hash helper
// (used for hashing down oversized HMAC keys) directly, across the same
// block-boundary lengths, since it has its own tail-padding logic distinct
// from sha256FinalizeTail's HMAC-continuation callers.
func TestSHA256ScalarSumMatchesCryptoSHA256(t *testing.T) {
	for _, n := range []int{0, 1, 55, 56, 63, 64, 65, 119, 120, 121, 200} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i * 7)
		}
		got := sha256ScalarSum(msg)
		want := sha256.Sum256(msg)
		if got != want {
			t.Fatalf("len %d: got %x, want %x", n, got, want)
		}
	}
}
