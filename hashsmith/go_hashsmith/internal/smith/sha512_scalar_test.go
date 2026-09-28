package smith

import (
	"crypto/sha512"
	"math/rand"
	"testing"
)

// padOneBlockSHA512 pads msg per FIPS 180-4 Sec 5.1.2: a 1 bit, zero-fill,
// then a 128-bit big-endian length field, the whole thing a multiple of
// 128 bytes. Only the low 64 bits of that field can be non-zero for any
// message this project ever hashes (2^64 bits is far beyond any realistic
// input), so the upper 8 bytes are always left zero — exactly what real
// implementations do for every message that will ever exist in practice.
func padOneBlockSHA512(msg []byte) [128]byte {
	if len(msg) > 111 { // 128 - 1 (0x80) - 16 (length field)
		panic("padOneBlockSHA512: message too long for one block")
	}
	var block [128]byte
	copy(block[:], msg)
	block[len(msg)] = 0x80
	bitLen := uint64(len(msg)) * 8
	for i := 0; i < 8; i++ {
		block[127-i] = byte(bitLen >> (8 * i))
	}
	return block
}

func TestSHA512ScalarCompressMatchesCryptoSHA512(t *testing.T) {
	cases := []string{
		"", "a", "abc", "message digest",
		"abcdefghijklmnopqrstuvwxyz",
	}
	for _, msg := range cases {
		block := padOneBlockSHA512([]byte(msg))
		state := sha512IV
		var w [80]uint64
		sha512ExpandSchedule(&block, &w)
		sha512ScalarCompress(&state, &w)
		var got [64]byte
		for i := 0; i < 8; i++ {
			for b := 0; b < 8; b++ {
				got[i*8+b] = byte(state[i] >> (56 - 8*b))
			}
		}
		want := sha512.Sum512([]byte(msg))
		if got != want {
			t.Fatalf("msg %q: sha512ScalarCompress = %x, want %x", msg, got, want)
		}
	}
}

func TestSHA512ScalarCompressRandomMatchesCryptoSHA512(t *testing.T) {
	rng := rand.New(rand.NewSource(13))
	for i := 0; i < 500; i++ {
		n := rng.Intn(112) // 0..111
		msg := make([]byte, n)
		rng.Read(msg)
		block := padOneBlockSHA512(msg)
		state := sha512IV
		var w [80]uint64
		sha512ExpandSchedule(&block, &w)
		sha512ScalarCompress(&state, &w)
		var got [64]byte
		for j := 0; j < 8; j++ {
			for b := 0; b < 8; b++ {
				got[j*8+b] = byte(state[j] >> (56 - 8*b))
			}
		}
		want := sha512.Sum512(msg)
		if got != want {
			t.Fatalf("random msg %x: sha512ScalarCompress = %x, want %x", msg, got, want)
		}
	}
}
