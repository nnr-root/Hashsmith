package main

// FEAL-8, the cipher Sybase's PROP password hash is built out of.
//
// FEAL was proposed in 1987 as a faster alternative to DES — four rounds, then
// eight, then N — and it is the cipher that taught cryptography how to do
// differential and linear cryptanalysis. FEAL-4 fell to a handful of chosen
// plaintexts, FEAL-8 to a few thousand, and by 1994 the whole family was
// understood to be broken. Nothing has used it since except software written
// before that was known, which is why it appears here at all.
//
// The round function is arithmetic rather than table-driven: two bytes are
// added and the sum rotated left two places, which is the entire nonlinearity.
// That is what made it fast in 1987 and what made it breakable.

import "encoding/binary"

// fealRot2 rotates a byte left two places.
func fealRot2(x byte) byte { return x<<2 | x>>6 }

func fealS0(a, b byte) byte { return fealRot2(a + b) }
func fealS1(a, b byte) byte { return fealRot2(a + b + 1) }

type feal8 struct {
	k                        [16]uint16
	k89, k1011, k1213, k1415 uint32
}

// fealF is the round function. Every byte index here counts from the LOW end
// of the word, because the reference implementation reads its words through a
// byte array on a little-endian machine and the order is part of the cipher.
func fealF(a uint32, bb uint16) uint32 {
	ab := [4]byte{byte(a), byte(a >> 8), byte(a >> 16), byte(a >> 24)}
	bbb := [2]byte{byte(bb), byte(bb >> 8)}
	f1 := ab[1] ^ bbb[0] ^ ab[0]
	f2 := ab[2] ^ bbb[1] ^ ab[3]
	f1 = fealS1(f1, f2)
	f2 = fealS0(f2, f1)
	var out [4]byte
	out[1] = f1
	out[2] = f2
	out[0] = fealS0(ab[0], f1)
	out[3] = fealS1(ab[3], f2)
	return binary.LittleEndian.Uint32(out[:])
}

// fealFK is the key-schedule round function.
func fealFK(aa, bb uint32) uint32 {
	a := [4]byte{byte(aa), byte(aa >> 8), byte(aa >> 16), byte(aa >> 24)}
	b := [4]byte{byte(bb), byte(bb >> 8), byte(bb >> 16), byte(bb >> 24)}
	fk1 := a[1] ^ a[0]
	fk2 := a[2] ^ a[3]
	fk1 = fealS1(fk1, fk2^b[0])
	fk2 = fealS0(fk2, fk1^b[1])
	var out [4]byte
	out[1] = fk1
	out[2] = fk2
	out[0] = fealS0(a[0], fk1^b[2])
	out[3] = fealS1(a[3], fk2^b[3])
	return binary.LittleEndian.Uint32(out[:])
}

// newFEAL8 runs the key schedule over an eight-byte key.
func newFEAL8(key []byte) *feal8 {
	c := &feal8{}
	a := binary.LittleEndian.Uint32(key[0:4])
	b := binary.LittleEndian.Uint32(key[4:8])
	var d uint32
	for i := 0; i < 8; i++ {
		newB := fealFK(a, b^d)
		a, b = b, newB
		c.k[2*i] = uint16(b & 0xFFFF)
		c.k[2*i+1] = uint16(b >> 16)
	}
	pair := func(i int) uint32 {
		return uint32(c.k[i]) | uint32(c.k[i+1])<<16
	}
	c.k89, c.k1011, c.k1213, c.k1415 = pair(8), pair(10), pair(12), pair(14)
	return c
}

// encrypt transforms one eight-byte block.
func (c *feal8) encrypt(dst, src []byte) {
	l := binary.LittleEndian.Uint32(src[0:4])
	r := binary.LittleEndian.Uint32(src[4:8])
	l ^= c.k89
	r ^= c.k1011
	r ^= l
	for i := 0; i < 8; i++ {
		l, r = r, l^fealF(r, c.k[i])
	}
	l ^= r
	r ^= c.k1213
	l ^= c.k1415
	binary.LittleEndian.PutUint32(dst[0:4], r)
	binary.LittleEndian.PutUint32(dst[4:8], l)
}
