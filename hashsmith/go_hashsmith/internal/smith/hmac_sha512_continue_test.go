package smith

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"math/rand"
	"testing"
)

func hmacSHA512Reference(key, message []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func hmacSHA512ViaContinuation(key, message []byte) [64]byte {
	kb := hmacSHA512KeyBlock(key)
	inner := hmacSHA512InnerOuterIV(kb, 0x36)
	outer := hmacSHA512InnerOuterIV(kb, 0x5c)
	return hmacSHA512FromInnerOuter(inner, outer, message)
}

// TestHMACSHA512ContinuationMatchesReference mirrors
// TestHMACSHA256ContinuationMatchesReference, with lengths spanning
// SHA-512's own (128-byte block, 16-byte length field) boundaries: 111 is
// the largest tail that still fits in one block, 112 forces a second.
func TestHMACSHA512ContinuationMatchesReference(t *testing.T) {
	keys := [][]byte{
		[]byte(""),
		[]byte("short-key"),
		bytes.Repeat([]byte{0x42}, 128), // exactly one block, no hashing down needed
		bytes.Repeat([]byte{0x42}, 129), // one byte over — must be hashed down
		bytes.Repeat([]byte{0x42}, 300),
	}
	lengths := []int{0, 1, 63, 64, 111, 112, 127, 128, 129, 200, 255, 256, 257}
	for _, key := range keys {
		for _, n := range lengths {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(i)
			}
			want := hmacSHA512Reference(key, msg)
			got := hmacSHA512ViaContinuation(key, msg)
			if !bytes.Equal(got[:], want) {
				t.Fatalf("key len %d, msg len %d: got %x, want %x", len(key), n, got, want)
			}
		}
	}
}

func TestHMACSHA512ContinuationRandomMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	for i := 0; i < 500; i++ {
		key := make([]byte, rng.Intn(300))
		rng.Read(key)
		msg := make([]byte, rng.Intn(500))
		rng.Read(msg)
		want := hmacSHA512Reference(key, msg)
		got := hmacSHA512ViaContinuation(key, msg)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("key %x msg %x: got %x, want %x", key, msg, got, want)
		}
	}
}

func TestSHA512ScalarSumMatchesCryptoSHA512(t *testing.T) {
	for _, n := range []int{0, 1, 111, 112, 127, 128, 129, 200, 255, 256, 257} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i * 7)
		}
		got := sha512ScalarSum(msg)
		want := sha512.Sum512(msg)
		if got != want {
			t.Fatalf("len %d: got %x, want %x", n, got, want)
		}
	}
}
