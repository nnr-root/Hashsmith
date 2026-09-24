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
// TestSHA256ScheduleFromWordsMatchesByteOrientedPath is the correctness
// backstop for the word-native fast path: for a random 32-byte digest,
// building the schedule directly from its uint32 words must produce
// byte-for-byte the same 64-word schedule as the original byte-oriented
// route (bytes -> sha256OneBlockPaddedSchedule -> sha256ExpandSchedule),
// which is itself already proven correct by every PBKDF2 differential test
// in this package. This is the one property that makes skipping the byte
// round trip safe rather than merely faster.
func TestSHA256ScheduleFromWordsMatchesByteOrientedPath(t *testing.T) {
	rng := rand.New(rand.NewSource(30))
	for trial := 0; trial < 200; trial++ {
		var data [8]uint32
		for i := range data {
			data[i] = rng.Uint32()
		}
		var digestBytes [32]byte
		for i := 0; i < 8; i++ {
			digestBytes[i*4] = byte(data[i] >> 24)
			digestBytes[i*4+1] = byte(data[i] >> 16)
			digestBytes[i*4+2] = byte(data[i] >> 8)
			digestBytes[i*4+3] = byte(data[i])
		}

		var wantW [64]uint32
		sha256OneBlockPaddedSchedule(digestBytes[:], 64, &wantW)

		var gotW [64]uint32
		sha256ScheduleFromWords(&data, &gotW)

		if gotW != wantW {
			t.Fatalf("trial %d: sha256ScheduleFromWords = %v, want %v (byte-oriented path)", trial, gotW, wantW)
		}
	}
}

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
