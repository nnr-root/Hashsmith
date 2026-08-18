package main

// Whirlpool (ISO/IEC 10118-3:2004) — a 512-bit hash used as a KDF in some
// VeraCrypt/TrueCrypt and LUKS volumes. Implemented from the specification; the
// circulant tables and round constants are generated at init from the S-box, and
// the whole thing is pinned to the published test vectors in the tests.

import "hash"

// whirlpoolSBox is the 256-entry Whirlpool substitution box.
var whirlpoolSBox = [256]byte{
	0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
	0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
	0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
	0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
	0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
	0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
	0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
	0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
	0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
	0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
	0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
	0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
	0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
	0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
	0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
	0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
}

var (
	whirlpoolC  [8][256]uint64
	whirlpoolRC [11]uint64
)

// gfMul multiplies two bytes in GF(2^8) modulo x^8+x^4+x^3+x^2+1 (0x11d).
func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return p
}

func init() {
	for x := 0; x < 256; x++ {
		s := whirlpoolSBox[x]
		// MixRows circulant first row: [1, 1, 4, 1, 8, 5, 2, 9].
		b := [8]byte{
			gfMul(s, 1), gfMul(s, 1), gfMul(s, 4), gfMul(s, 1),
			gfMul(s, 8), gfMul(s, 5), gfMul(s, 2), gfMul(s, 9),
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v = v<<8 | uint64(b[i])
		}
		whirlpoolC[0][x] = v
		for t := 1; t < 8; t++ {
			whirlpoolC[t][x] = v>>uint(8*t) | v<<uint(64-8*t) // rotate right by t bytes
		}
	}
	for r := 1; r <= 10; r++ {
		var v uint64
		for j := 0; j < 8; j++ {
			v = v<<8 | uint64(whirlpoolSBox[8*(r-1)+j])
		}
		whirlpoolRC[r] = v
	}
}

// whirlpoolTransform is the Miyaguchi-Preneel compression over one 64-byte block.
func whirlpoolTransform(hashState, block *[8]uint64) {
	var K, state, L [8]uint64
	for i := 0; i < 8; i++ {
		K[i] = hashState[i]
		state[i] = block[i] ^ K[i]
	}
	for r := 1; r <= 10; r++ {
		for i := 0; i < 8; i++ {
			L[i] = whirlpoolC[0][byte(K[i]>>56)] ^
				whirlpoolC[1][byte(K[(i+7)&7]>>48)] ^
				whirlpoolC[2][byte(K[(i+6)&7]>>40)] ^
				whirlpoolC[3][byte(K[(i+5)&7]>>32)] ^
				whirlpoolC[4][byte(K[(i+4)&7]>>24)] ^
				whirlpoolC[5][byte(K[(i+3)&7]>>16)] ^
				whirlpoolC[6][byte(K[(i+2)&7]>>8)] ^
				whirlpoolC[7][byte(K[(i+1)&7])]
		}
		L[0] ^= whirlpoolRC[r]
		K = L
		for i := 0; i < 8; i++ {
			L[i] = whirlpoolC[0][byte(state[i]>>56)] ^
				whirlpoolC[1][byte(state[(i+7)&7]>>48)] ^
				whirlpoolC[2][byte(state[(i+6)&7]>>40)] ^
				whirlpoolC[3][byte(state[(i+5)&7]>>32)] ^
				whirlpoolC[4][byte(state[(i+4)&7]>>24)] ^
				whirlpoolC[5][byte(state[(i+3)&7]>>16)] ^
				whirlpoolC[6][byte(state[(i+2)&7]>>8)] ^
				whirlpoolC[7][byte(state[(i+1)&7])] ^ K[i]
		}
		state = L
	}
	for i := 0; i < 8; i++ {
		hashState[i] ^= state[i] ^ block[i]
	}
}

// whirlpoolDigest implements hash.Hash.
type whirlpoolDigest struct {
	state  [8]uint64
	buf    [64]byte
	nx     int
	length [32]byte // 256-bit bit-length counter (big-endian)
}

func newWhirlpool() hash.Hash { return &whirlpoolDigest{} }

func (d *whirlpoolDigest) Size() int      { return 64 }
func (d *whirlpoolDigest) BlockSize() int { return 64 }

func (d *whirlpoolDigest) Reset() { *d = whirlpoolDigest{} }

func (d *whirlpoolDigest) Write(p []byte) (int, error) {
	n := len(p)
	addBits(&d.length, uint64(n)*8)
	for len(p) > 0 {
		c := copy(d.buf[d.nx:], p)
		d.nx += c
		p = p[c:]
		if d.nx == 64 {
			d.processBuf()
			d.nx = 0
		}
	}
	return n, nil
}

func (d *whirlpoolDigest) processBuf() {
	var block [8]uint64
	for i := 0; i < 8; i++ {
		var v uint64
		for j := 0; j < 8; j++ {
			v = v<<8 | uint64(d.buf[i*8+j])
		}
		block[i] = v
	}
	whirlpoolTransform(&d.state, &block)
}

func (d *whirlpoolDigest) Sum(in []byte) []byte {
	e := *d // copy so Sum doesn't mutate
	length := e.length

	// Pad: 0x80, zeros, then 32-byte length. Reserve 32 bytes for length.
	e.buf[e.nx] = 0x80
	e.nx++
	if e.nx > 32 {
		for i := e.nx; i < 64; i++ {
			e.buf[i] = 0
		}
		e.processBuf()
		e.nx = 0
	}
	for i := e.nx; i < 32; i++ {
		e.buf[i] = 0
	}
	copy(e.buf[32:64], length[:])
	e.processBuf()

	var out [64]byte
	for i := 0; i < 8; i++ {
		v := e.state[i]
		for j := 0; j < 8; j++ {
			out[i*8+j] = byte(v >> uint(56-8*j))
		}
	}
	return append(in, out[:]...)
}

// addBits adds a bit count to a 256-bit big-endian counter.
func addBits(counter *[32]byte, bits uint64) {
	var carry uint64 = bits
	for i := 31; i >= 0 && carry > 0; i-- {
		carry += uint64(counter[i])
		counter[i] = byte(carry)
		carry >>= 8
	}
}
