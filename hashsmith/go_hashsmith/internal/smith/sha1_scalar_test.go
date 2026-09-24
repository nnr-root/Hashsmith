package smith

import (
	"crypto/sha1"
	"math/rand"
	"testing"
)

func padOneBlockSHA1(msg []byte) [64]byte {
	if len(msg) > 55 {
		panic("padOneBlockSHA1: message too long for one block")
	}
	var block [64]byte
	copy(block[:], msg)
	block[len(msg)] = 0x80
	bitLen := uint64(len(msg)) * 8
	for i := 0; i < 8; i++ {
		block[63-i] = byte(bitLen >> (8 * i))
	}
	return block
}

// TestSHA1ScalarCompressMatchesCryptoSHA1 is SHA-1's version of
// TestSHA256ScalarCompressMatchesCryptoSHA256: the foundational oracle
// check every later SHA-1 test (the AVX2 core, HMAC continuation, the
// PBKDF2 lane hasher) is only as trustworthy as.
func TestSHA1ScalarCompressMatchesCryptoSHA1(t *testing.T) {
	cases := []string{
		"", "a", "abc", "message digest",
		"abcdefghijklmnopqrstuvwxyz",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890"[:55],
	}
	for _, msg := range cases {
		block := padOneBlockSHA1([]byte(msg))
		state := sha1IV
		var w [80]uint32
		sha1ExpandSchedule(&block, &w)
		sha1ScalarCompress(&state, &w)
		var got [20]byte
		for i := 0; i < 5; i++ {
			got[i*4] = byte(state[i] >> 24)
			got[i*4+1] = byte(state[i] >> 16)
			got[i*4+2] = byte(state[i] >> 8)
			got[i*4+3] = byte(state[i])
		}
		want := sha1.Sum([]byte(msg))
		if got != want {
			t.Fatalf("msg %q: sha1ScalarCompress = %x, want %x", msg, got, want)
		}
	}
}

// TestSHA1ScalarCompressRandomMatchesCryptoSHA1 extends the table above
// with randomized short messages, still all from sha1IV.
func TestSHA1ScalarCompressRandomMatchesCryptoSHA1(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	for i := 0; i < 500; i++ {
		n := rng.Intn(56)
		msg := make([]byte, n)
		rng.Read(msg)
		block := padOneBlockSHA1(msg)
		state := sha1IV
		var w [80]uint32
		sha1ExpandSchedule(&block, &w)
		sha1ScalarCompress(&state, &w)
		var got [20]byte
		for j := 0; j < 5; j++ {
			got[j*4] = byte(state[j] >> 24)
			got[j*4+1] = byte(state[j] >> 16)
			got[j*4+2] = byte(state[j] >> 8)
			got[j*4+3] = byte(state[j])
		}
		want := sha1.Sum(msg)
		if got != want {
			t.Fatalf("random msg %x: sha1ScalarCompress = %x, want %x", msg, got, want)
		}
	}
}
