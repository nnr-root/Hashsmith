package main

// Legacy Keccak-224 and Keccak-384. Go exposes the legacy 256- and 512-bit
// variants, but not these two output sizes. The sponge is otherwise identical:
// a Keccak-f[1600] permutation with the original 0x01 domain separator.

import (
	"encoding/binary"
	"math/bits"
)

var keccakRoundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRotation = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
var keccakPiLane = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func keccakF1600(a *[25]uint64) {
	for _, rc := range keccakRoundConstants {
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			for y := 0; y < 25; y += 5 {
				a[y+x] ^= d
			}
		}

		t := a[1]
		for i, lane := range keccakPiLane {
			next := a[lane]
			a[lane] = bits.RotateLeft64(t, keccakRotation[i])
			t = next
		}

		for y := 0; y < 25; y += 5 {
			row := [5]uint64{a[y], a[y+1], a[y+2], a[y+3], a[y+4]}
			for x := 0; x < 5; x++ {
				a[y+x] = row[x] ^ (^row[(x+1)%5] & row[(x+2)%5])
			}
		}
		a[0] ^= rc
	}
}

func legacyKeccakSum(data []byte, outputBytes int) []byte {
	rate := 200 - 2*outputBytes
	var state [25]uint64
	absorb := func(block []byte) {
		for i := 0; i < rate/8; i++ {
			state[i] ^= binary.LittleEndian.Uint64(block[i*8:])
		}
		keccakF1600(&state)
	}
	for len(data) >= rate {
		absorb(data[:rate])
		data = data[rate:]
	}
	block := make([]byte, rate)
	copy(block, data)
	block[len(data)] = 0x01
	block[rate-1] |= 0x80
	absorb(block)

	out := make([]byte, outputBytes)
	for i := 0; i < outputBytes; i++ {
		out[i] = byte(state[i/8] >> (8 * uint(i%8)))
	}
	return out
}
