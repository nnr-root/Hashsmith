package smith

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"math/rand"
	"testing"
)

func hmacSHA1Reference(key, message []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func hmacSHA1ViaContinuation(key, message []byte) [20]byte {
	kb := hmacSHA1KeyBlock(key)
	inner := hmacSHA1InnerOuterIV(kb, 0x36)
	outer := hmacSHA1InnerOuterIV(kb, 0x5c)
	return hmacSHA1FromInnerOuter(inner, outer, message)
}

// TestHMACSHA1ContinuationMatchesReference mirrors
// TestHMACSHA256ContinuationMatchesReference exactly, for SHA-1.
func TestHMACSHA1ContinuationMatchesReference(t *testing.T) {
	keys := [][]byte{
		[]byte(""),
		[]byte("short-key"),
		bytes.Repeat([]byte{0x42}, 64),
		bytes.Repeat([]byte{0x42}, 65),
		bytes.Repeat([]byte{0x42}, 200),
	}
	lengths := []int{0, 1, 19, 20, 55, 56, 63, 64, 65, 96, 119, 120, 121, 200}
	for _, key := range keys {
		for _, n := range lengths {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(i)
			}
			want := hmacSHA1Reference(key, msg)
			got := hmacSHA1ViaContinuation(key, msg)
			if !bytes.Equal(got[:], want) {
				t.Fatalf("key len %d, msg len %d: got %x, want %x", len(key), n, got, want)
			}
		}
	}
}

func TestHMACSHA1ContinuationRandomMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	for i := 0; i < 500; i++ {
		key := make([]byte, rng.Intn(150))
		rng.Read(key)
		msg := make([]byte, rng.Intn(300))
		rng.Read(msg)
		want := hmacSHA1Reference(key, msg)
		got := hmacSHA1ViaContinuation(key, msg)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("key %x msg %x: got %x, want %x", key, msg, got, want)
		}
	}
}

// TestSHA1ScheduleFromWordsMatchesByteOrientedPath mirrors
// TestSHA256ScheduleFromWordsMatchesByteOrientedPath.
func TestSHA1ScheduleFromWordsMatchesByteOrientedPath(t *testing.T) {
	rng := rand.New(rand.NewSource(31))
	for trial := 0; trial < 200; trial++ {
		var data [5]uint32
		for i := range data {
			data[i] = rng.Uint32()
		}
		var digestBytes [20]byte
		for i := 0; i < 5; i++ {
			digestBytes[i*4] = byte(data[i] >> 24)
			digestBytes[i*4+1] = byte(data[i] >> 16)
			digestBytes[i*4+2] = byte(data[i] >> 8)
			digestBytes[i*4+3] = byte(data[i])
		}

		var wantW [80]uint32
		sha1OneBlockPaddedSchedule(digestBytes[:], 64, &wantW)

		var gotW [80]uint32
		sha1ScheduleFromWords(&data, &gotW)

		if gotW != wantW {
			t.Fatalf("trial %d: sha1ScheduleFromWords = %v, want %v (byte-oriented path)", trial, gotW, wantW)
		}
	}
}

func TestSHA1ScalarSumMatchesCryptoSHA1(t *testing.T) {
	for _, n := range []int{0, 1, 55, 56, 63, 64, 65, 119, 120, 121, 200} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i * 7)
		}
		got := sha1ScalarSum(msg)
		want := sha1.Sum(msg)
		if got != want {
			t.Fatalf("len %d: got %x, want %x", n, got, want)
		}
	}
}
