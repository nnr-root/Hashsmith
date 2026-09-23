package smith

// Whirlpool (ISO/IEC 10118-3:2004) — a 512-bit hash used as a KDF in some
// VeraCrypt/TrueCrypt and LUKS volumes. Implemented from the specification; the
// circulant tables and round constants are generated at init from the S-box, and
// the whole thing is pinned to the published test vectors in the tests.

import (
	"encoding/binary"
	"errors"
	"hash"
)

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
// whirlpoolTransform is the Miyaguchi-Preneel compression.
//
// Written out rather than looped for the same reason as Streebog's LPS: the
// row index into whirlpoolC and the (i+k)&7 state rotations are constants once
// unrolled, so the modular arithmetic disappears and the eight round-state
// words stay in registers instead of being reloaded from an array eight times
// per round. The eight table rows are hoisted to locals so each lookup is a
// single index rather than two.
func whirlpoolTransform(hashState, block *[8]uint64) {
	c0 := &whirlpoolC[0]
	c1 := &whirlpoolC[1]
	c2 := &whirlpoolC[2]
	c3 := &whirlpoolC[3]
	c4 := &whirlpoolC[4]
	c5 := &whirlpoolC[5]
	c6 := &whirlpoolC[6]
	c7 := &whirlpoolC[7]

	k0 := hashState[0]
	k1 := hashState[1]
	k2 := hashState[2]
	k3 := hashState[3]
	k4 := hashState[4]
	k5 := hashState[5]
	k6 := hashState[6]
	k7 := hashState[7]
	s0 := block[0] ^ k0
	s1 := block[1] ^ k1
	s2 := block[2] ^ k2
	s3 := block[3] ^ k3
	s4 := block[4] ^ k4
	s5 := block[5] ^ k5
	s6 := block[6] ^ k6
	s7 := block[7] ^ k7

	for r := 1; r <= 10; r++ {
		l0 := c0[byte(k0>>56)] ^
			c1[byte(k7>>48)] ^
			c2[byte(k6>>40)] ^
			c3[byte(k5>>32)] ^
			c4[byte(k4>>24)] ^
			c5[byte(k3>>16)] ^
			c6[byte(k2>>8)] ^
			c7[byte(k1)]
		l1 := c0[byte(k1>>56)] ^
			c1[byte(k0>>48)] ^
			c2[byte(k7>>40)] ^
			c3[byte(k6>>32)] ^
			c4[byte(k5>>24)] ^
			c5[byte(k4>>16)] ^
			c6[byte(k3>>8)] ^
			c7[byte(k2)]
		l2 := c0[byte(k2>>56)] ^
			c1[byte(k1>>48)] ^
			c2[byte(k0>>40)] ^
			c3[byte(k7>>32)] ^
			c4[byte(k6>>24)] ^
			c5[byte(k5>>16)] ^
			c6[byte(k4>>8)] ^
			c7[byte(k3)]
		l3 := c0[byte(k3>>56)] ^
			c1[byte(k2>>48)] ^
			c2[byte(k1>>40)] ^
			c3[byte(k0>>32)] ^
			c4[byte(k7>>24)] ^
			c5[byte(k6>>16)] ^
			c6[byte(k5>>8)] ^
			c7[byte(k4)]
		l4 := c0[byte(k4>>56)] ^
			c1[byte(k3>>48)] ^
			c2[byte(k2>>40)] ^
			c3[byte(k1>>32)] ^
			c4[byte(k0>>24)] ^
			c5[byte(k7>>16)] ^
			c6[byte(k6>>8)] ^
			c7[byte(k5)]
		l5 := c0[byte(k5>>56)] ^
			c1[byte(k4>>48)] ^
			c2[byte(k3>>40)] ^
			c3[byte(k2>>32)] ^
			c4[byte(k1>>24)] ^
			c5[byte(k0>>16)] ^
			c6[byte(k7>>8)] ^
			c7[byte(k6)]
		l6 := c0[byte(k6>>56)] ^
			c1[byte(k5>>48)] ^
			c2[byte(k4>>40)] ^
			c3[byte(k3>>32)] ^
			c4[byte(k2>>24)] ^
			c5[byte(k1>>16)] ^
			c6[byte(k0>>8)] ^
			c7[byte(k7)]
		l7 := c0[byte(k7>>56)] ^
			c1[byte(k6>>48)] ^
			c2[byte(k5>>40)] ^
			c3[byte(k4>>32)] ^
			c4[byte(k3>>24)] ^
			c5[byte(k2>>16)] ^
			c6[byte(k1>>8)] ^
			c7[byte(k0)]
		l0 ^= whirlpoolRC[r]
		k0 = l0
		k1 = l1
		k2 = l2
		k3 = l3
		k4 = l4
		k5 = l5
		k6 = l6
		k7 = l7
		l0 = c0[byte(s0>>56)] ^
			c1[byte(s7>>48)] ^
			c2[byte(s6>>40)] ^
			c3[byte(s5>>32)] ^
			c4[byte(s4>>24)] ^
			c5[byte(s3>>16)] ^
			c6[byte(s2>>8)] ^
			c7[byte(s1)] ^ k0
		l1 = c0[byte(s1>>56)] ^
			c1[byte(s0>>48)] ^
			c2[byte(s7>>40)] ^
			c3[byte(s6>>32)] ^
			c4[byte(s5>>24)] ^
			c5[byte(s4>>16)] ^
			c6[byte(s3>>8)] ^
			c7[byte(s2)] ^ k1
		l2 = c0[byte(s2>>56)] ^
			c1[byte(s1>>48)] ^
			c2[byte(s0>>40)] ^
			c3[byte(s7>>32)] ^
			c4[byte(s6>>24)] ^
			c5[byte(s5>>16)] ^
			c6[byte(s4>>8)] ^
			c7[byte(s3)] ^ k2
		l3 = c0[byte(s3>>56)] ^
			c1[byte(s2>>48)] ^
			c2[byte(s1>>40)] ^
			c3[byte(s0>>32)] ^
			c4[byte(s7>>24)] ^
			c5[byte(s6>>16)] ^
			c6[byte(s5>>8)] ^
			c7[byte(s4)] ^ k3
		l4 = c0[byte(s4>>56)] ^
			c1[byte(s3>>48)] ^
			c2[byte(s2>>40)] ^
			c3[byte(s1>>32)] ^
			c4[byte(s0>>24)] ^
			c5[byte(s7>>16)] ^
			c6[byte(s6>>8)] ^
			c7[byte(s5)] ^ k4
		l5 = c0[byte(s5>>56)] ^
			c1[byte(s4>>48)] ^
			c2[byte(s3>>40)] ^
			c3[byte(s2>>32)] ^
			c4[byte(s1>>24)] ^
			c5[byte(s0>>16)] ^
			c6[byte(s7>>8)] ^
			c7[byte(s6)] ^ k5
		l6 = c0[byte(s6>>56)] ^
			c1[byte(s5>>48)] ^
			c2[byte(s4>>40)] ^
			c3[byte(s3>>32)] ^
			c4[byte(s2>>24)] ^
			c5[byte(s1>>16)] ^
			c6[byte(s0>>8)] ^
			c7[byte(s7)] ^ k6
		l7 = c0[byte(s7>>56)] ^
			c1[byte(s6>>48)] ^
			c2[byte(s5>>40)] ^
			c3[byte(s4>>32)] ^
			c4[byte(s3>>24)] ^
			c5[byte(s2>>16)] ^
			c6[byte(s1>>8)] ^
			c7[byte(s0)] ^ k7
		s0 = l0
		s1 = l1
		s2 = l2
		s3 = l3
		s4 = l4
		s5 = l5
		s6 = l6
		s7 = l7
	}

	hashState[0] ^= s0 ^ block[0]
	hashState[1] ^= s1 ^ block[1]
	hashState[2] ^= s2 ^ block[2]
	hashState[3] ^= s3 ^ block[3]
	hashState[4] ^= s4 ^ block[4]
	hashState[5] ^= s5 ^ block[5]
	hashState[6] ^= s6 ^ block[6]
	hashState[7] ^= s7 ^ block[7]
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

// whirlpoolMarshalMagic tags a serialised digest.
const whirlpoolMarshalMagic = "hashsmith\x01whirlpool\x01"

// MarshalBinary, AppendBinary and UnmarshalBinary exist for crypto/hmac, which
// caches a key's inner and outer states only when the hash can serialise
// itself and otherwise re-compresses the ipad and opad blocks on every
// message. VeraCrypt's Whirlpool KDF is 500,000 PBKDF2 iterations per derived
// block, so that is 500,000 avoidable pairs of compressions. See the same
// methods on ripemdDigest for the measurement.
func (d *whirlpoolDigest) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, len(whirlpoolMarshalMagic)+64+64+1+32))
}

func (d *whirlpoolDigest) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, whirlpoolMarshalMagic...)
	for _, v := range d.state {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	b = append(b, d.buf[:]...)
	b = append(b, byte(d.nx))
	return append(b, d.length[:]...), nil
}

func (d *whirlpoolDigest) UnmarshalBinary(b []byte) error {
	if len(b) < len(whirlpoolMarshalMagic) || string(b[:len(whirlpoolMarshalMagic)]) != whirlpoolMarshalMagic {
		return errors.New("whirlpool: invalid hash state identifier")
	}
	b = b[len(whirlpoolMarshalMagic):]
	if len(b) != 64+64+1+32 {
		return errors.New("whirlpool: invalid hash state size")
	}
	for i := range d.state {
		d.state[i] = binary.BigEndian.Uint64(b[i*8:])
	}
	b = b[64:]
	copy(d.buf[:], b[:64])
	b = b[64:]
	d.nx = int(b[0])
	if d.nx >= 64 {
		return errors.New("whirlpool: invalid buffered length in hash state")
	}
	copy(d.length[:], b[1:])
	return nil
}
