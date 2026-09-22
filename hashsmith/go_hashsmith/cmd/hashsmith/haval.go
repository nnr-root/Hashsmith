package main

// HAVAL, a 1992 hash with five output sizes and three work levels.
//
// Fifteen formats in John's dynamic table name it — every combination of 128,
// 160, 192, 224 or 256 bits with three, four or five passes — which is why
// one implementation is worth more here than its obscurity suggests.
//
// The structure is MD5's: little-endian 32-bit words, a 128-byte block, a
// chaining state that is added to at the end. What differs:
//
//   - The state is eight words, 256 bits, whatever the output size. A shorter
//     output is FOLDED out of those eight words rather than truncated from
//     them, which is what havalTailor does and the only part of the algorithm
//     that differs between output sizes.
//   - Each pass runs 32 steps over the block's words in a fixed order, with
//     its own boolean function and its own permutation of the state — and the
//     permutation depends on the number of passes as well as which pass it
//     is, so a five-pass HAVAL's third pass is not a three-pass HAVAL's third
//     pass.
//   - The padding records the parameters: a byte holding the version, the
//     pass count and part of the output length, then the rest of the length,
//     then the message's bit count. Two HAVALs with different parameters
//     therefore differ from the padding onwards as well as in the rounds.
//
// The constants are the fractional part of pi: the first eight words are the
// initial state, and the next 128 are the per-pass constants. That is checked
// rather than asserted — the first eight are a published value (they are also
// Blowfish's, for the same reason) and havalIV holds them.

import (
	"encoding/binary"
	"math/bits"
	"strconv"
	"strings"
)

// havalIV is the first eight words of the fractional part of pi.
var havalIV = [8]uint32{
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
}

// havalK holds the constants for passes two through five: the next 128
// words of pi, thirty-two to a pass.
var havalK = [4][32]uint32{
	{
		0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
		0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
		0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac,
		0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
		0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
		0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
		0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
		0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
	},
	{
		0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0,
		0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
		0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27,
		0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
		0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
		0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
		0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6,
		0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
	},
	{
		0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af,
		0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
		0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
		0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
		0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004,
		0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
		0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68,
		0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4,
	},
	{
		0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
		0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4,
		0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073,
		0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
		0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248,
		0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
		0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b,
		0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4,
	},
}

// havalWordOrder gives the order each pass reads the block's 32 words in.
// The first pass reads them in order; the rest do not.
var havalWordOrder = [5][32]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
	{5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
		30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27},
	{19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
		31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2},
	{24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
		22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13},
	{27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
		5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15},
}

// havalPhi is the permutation of the state each pass applies before its
// boolean function, indexed by [passes-3][pass-1]. Each row says which state
// register supplies each of the function's seven arguments, x6 first.
var havalPhi = [3][5][7]int{
	// three passes
	{
		{1, 0, 3, 5, 6, 2, 4},
		{4, 2, 1, 0, 5, 3, 6},
		{6, 1, 2, 3, 4, 5, 0},
	},
	// four passes
	{
		{2, 6, 1, 4, 5, 3, 0},
		{3, 5, 2, 0, 1, 6, 4},
		{1, 4, 3, 6, 0, 2, 5},
		{6, 4, 0, 5, 2, 1, 3},
	},
	// five passes
	{
		{3, 4, 1, 0, 5, 2, 6},
		{6, 2, 1, 0, 3, 4, 5},
		{2, 6, 0, 4, 3, 1, 5},
		{1, 5, 3, 2, 0, 4, 6},
		{2, 5, 0, 6, 4, 3, 1},
	},
}

// havalF applies pass p's boolean function to seven words.
func havalF(p int, x6, x5, x4, x3, x2, x1, x0 uint32) uint32 {
	switch p {
	case 1:
		return (x1 & (x0 ^ x4)) ^ (x2 & x5) ^ (x3 & x6) ^ x0
	case 2:
		return (x2 & ((x1 &^ x3) ^ (x4 & x5) ^ x6 ^ x0)) ^ ((x4 & (x1 ^ x5)) ^ (x3 & x5) ^ x0)
	case 3:
		return (x3 & ((x1 & x2) ^ x6 ^ x0)) ^ ((x1 & x4) ^ (x2 & x5) ^ x0)
	case 4:
		return (x4 & ((x5 &^ x2) ^ (x3 | x6) ^ x1 ^ x0)) ^
			(x3 & ((x1 & x2) ^ x5 ^ x6)) ^ ((x2 & x6) ^ x0)
	default:
		return (x0 &^ ((x1 & x2 & x3) ^ x5)) ^ ((x1 & x4) ^ (x2 & x5) ^ (x3 & x6))
	}
}

// havalDigest is one HAVAL computation.
type havalDigest struct {
	state  [8]uint32
	passes int
	size   int // output bits
}

// havalBlock mixes one 128-byte block into the state.
func (d *havalDigest) block(w *[32]uint32) {
	e := d.state
	for pass := 1; pass <= d.passes; pass++ {
		phi := havalPhi[d.passes-3][pass-1]
		order := havalWordOrder[pass-1]
		for i := 0; i < 32; i++ {
			// Each step replaces one register and reads the other seven. The
			// register being replaced walks DOWN the state, so at step i the
			// argument the specification calls x_k is register k-i, and the
			// one being written is register 7-i.
			at := func(k int) uint32 { return e[((k-i)%8+8)%8] }
			t := havalF(pass,
				at(phi[0]), at(phi[1]), at(phi[2]), at(phi[3]),
				at(phi[4]), at(phi[5]), at(phi[6]))
			target := ((7-i)%8 + 8) % 8
			v := bits.RotateLeft32(t, -7) + bits.RotateLeft32(e[target], -11) + w[order[i]]
			if pass > 1 {
				v += havalK[pass-2][i]
			}
			e[target] = v
		}
	}
	for i := range d.state {
		d.state[i] += e[i]
	}
}

// havalSum hashes a message with the given output size and pass count.
func havalSum(msg []byte, size, passes int) []byte {
	d := &havalDigest{state: havalIV, passes: passes, size: size}
	var w [32]uint32
	full := len(msg) / 128 * 128
	for off := 0; off < full; off += 128 {
		for i := range w {
			w[i] = binary.LittleEndian.Uint32(msg[off+i*4:])
		}
		d.block(&w)
	}

	// The padding records the parameters as well as the length: a 0x01 byte,
	// zeros, then a byte holding the version, the pass count and the low two
	// bits of the output size, a byte with the rest of the size, and the
	// message's length in bits. Two HAVALs with different parameters differ
	// from here on as well as in their rounds.
	tail := append([]byte(nil), msg[full:]...)
	tail = append(tail, 0x01)
	for len(tail)%128 != 118 {
		tail = append(tail, 0)
	}
	const havalVersion = 1
	tail = append(tail,
		byte(((size&0x3)<<6)|((passes&0x7)<<3)|havalVersion),
		byte((size>>2)&0xff))
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(len(msg))*8)
	tail = append(tail, length[:]...)
	for off := 0; off < len(tail); off += 128 {
		for i := range w {
			w[i] = binary.LittleEndian.Uint32(tail[off+i*4:])
		}
		d.block(&w)
	}

	d.tailor()
	out := make([]byte, size/8)
	for i := 0; i < size/8; i += 4 {
		binary.LittleEndian.PutUint32(out[i:], d.state[i/4])
	}
	return out
}

// tailor folds the 256-bit state down to the requested output size. A shorter
// HAVAL is not a truncation: every word of the state contributes to every word
// of the output, which is why each size needs its own arithmetic.
func (d *havalDigest) tailor() {
	e := &d.state
	switch d.size {
	case 256:
		return
	case 224:
		e[0] += (e[7] >> 27) & 0x1f
		e[1] += (e[7] >> 22) & 0x1f
		e[2] += (e[7] >> 18) & 0x0f
		e[3] += (e[7] >> 13) & 0x1f
		e[4] += (e[7] >> 9) & 0x0f
		e[5] += (e[7] >> 4) & 0x1f
		e[6] += e[7] & 0x0f
	case 192:
		temp := (e[7] & 0x1f) | (e[6] & (0x3f << 26))
		e[0] += bits.RotateLeft32(temp, -26)
		temp = (e[7] & (0x1f << 5)) | (e[6] & 0x1f)
		e[1] += temp
		temp = (e[7] & (0x3f << 10)) | (e[6] & (0x1f << 5))
		e[2] += temp >> 5
		temp = (e[7] & (0x1f << 16)) | (e[6] & (0x3f << 10))
		e[3] += temp >> 10
		temp = (e[7] & (0x1f << 21)) | (e[6] & (0x1f << 16))
		e[4] += temp >> 16
		temp = (e[7] & (0x3f << 26)) | (e[6] & (0x1f << 21))
		e[5] += temp >> 21
	case 160:
		temp := (e[7] & 0x3f) | (e[6] & (0x7f << 25)) | (e[5] & (0x3f << 19))
		e[0] += bits.RotateLeft32(temp, -19)
		temp = (e[7] & (0x3f << 6)) | (e[6] & 0x3f) | (e[5] & (0x7f << 25))
		e[1] += bits.RotateLeft32(temp, -25)
		temp = (e[7] & (0x7f << 12)) | (e[6] & (0x3f << 6)) | (e[5] & 0x3f)
		e[2] += temp
		temp = (e[7] & (0x3f << 19)) | (e[6] & (0x7f << 12)) | (e[5] & (0x3f << 6))
		e[3] += temp >> 6
		temp = (e[7] & (0x7f << 25)) | (e[6] & (0x3f << 19)) | (e[5] & (0x7f << 12))
		e[4] += temp >> 12
	case 128:
		temp := (e[7] & 0x000000ff) | (e[6] & 0xff000000) | (e[5] & 0x00ff0000) | (e[4] & 0x0000ff00)
		e[0] += bits.RotateLeft32(temp, -8)
		temp = (e[7] & 0x0000ff00) | (e[6] & 0x000000ff) | (e[5] & 0xff000000) | (e[4] & 0x00ff0000)
		e[1] += bits.RotateLeft32(temp, -16)
		temp = (e[7] & 0x00ff0000) | (e[6] & 0x0000ff00) | (e[5] & 0x000000ff) | (e[4] & 0xff000000)
		e[2] += bits.RotateLeft32(temp, -24)
		temp = (e[7] & 0xff000000) | (e[6] & 0x00ff0000) | (e[5] & 0x0000ff00) | (e[4] & 0x000000ff)
		e[3] += temp
	}
}

// havalParams reads a name of the form "haval<size>_<passes>", which is how
// John's table spells the fifteen variants.
func havalParams(name string) (size, passes int, ok bool) {
	const prefix = "haval"
	if !strings.HasPrefix(name, prefix) {
		return 0, 0, false
	}
	sizeText, passText, found := strings.Cut(name[len(prefix):], "_")
	if !found {
		return 0, 0, false
	}
	size, err := strconv.Atoi(sizeText)
	if err != nil {
		return 0, 0, false
	}
	passes, err = strconv.Atoi(passText)
	if err != nil {
		return 0, 0, false
	}
	switch size {
	case 128, 160, 192, 224, 256:
	default:
		return 0, 0, false
	}
	if passes < 3 || passes > 5 {
		return 0, 0, false
	}
	return size, passes, true
}
