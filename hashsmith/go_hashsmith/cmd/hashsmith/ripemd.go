package main

// RIPEMD-128 / RIPEMD-160 / RIPEMD-256 / RIPEMD-320.
//
// All four members of the family share one compression structure: two parallel
// lines of 4 or 5 rounds over the same message block, differing only in the
// message-word order, the rotate amounts, the round constants, and how the two
// lines are recombined.  This file implements that shared structure once and
// parameterises it, so the family is one body of code pinned to the published
// test vectors rather than four transcriptions.
//
// The wide variants (256/320) are not stronger than their narrow counterparts —
// they exist to provide a longer digest, and the two lines are kept separate
// instead of being folded together at the end.

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

// Message-word order and rotate amounts for the left and right lines.  The
// first 64 entries serve the 4-round variants (128/256); all 80 serve the
// 5-round variants (160/320).
var (
	ripemdOrderLeft = [80]uint8{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
	}
	ripemdOrderRight = [80]uint8{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
	}
	ripemdRotLeft = [80]uint8{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
	}
	ripemdRotRight = [80]uint8{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
	}
)

// Round constants.  The 4-round variants use the first four left constants and
// a right-hand set that ends in zero one round earlier than the 5-round set.
var (
	ripemdKLeft5  = [5]uint32{0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e}
	ripemdKRight5 = [5]uint32{0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000}
	ripemdKLeft4  = [4]uint32{0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc}
	ripemdKRight4 = [4]uint32{0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x00000000}
)

// ripemdDigest is the shared state for every width in the family.  h holds 4,
// 5, 8 or 10 words depending on the variant; wide reports whether the two
// lines stay separate (256/320) or are folded together (128/160).
//
// h is a fixed array rather than a slice on purpose: it makes the whole digest
// copyable by assignment, which is what lets Sum work on a copy and Reset
// restore an initial value without allocating.  Both sit in PBKDF2's inner
// loop, where VeraCrypt runs them 655,331 times per derived block.
type ripemdDigest struct {
	h      [10]uint32
	hn     int // words of h this variant uses
	x      [64]byte
	nx     int
	length uint64
	rounds int  // 4 or 5
	wide   bool // true for RIPEMD-256/320
	size   int  // digest length in bytes
}

var (
	ripemd128Init = ripemdDigest{
		h:  [10]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476},
		hn: 4, rounds: 4, size: 16,
	}
	ripemd160Init = ripemdDigest{
		h:  [10]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0},
		hn: 5, rounds: 5, size: 20,
	}
	ripemd256Init = ripemdDigest{
		h: [10]uint32{
			0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
			0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567,
		},
		hn: 8, rounds: 4, wide: true, size: 32,
	}
	ripemd320Init = ripemdDigest{
		h: [10]uint32{
			0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
			0x76543210, 0xfedcba98, 0x89abcdef, 0x01234567, 0x3c2d1e0f,
		},
		hn: 10, rounds: 5, wide: true, size: 40,
	}
)

func newRIPEMD128() hash.Hash { d := ripemd128Init; return &d }

// newRIPEMD160 completes the family in this file.  The narrow 5-round path in
// block5 already WAS RIPEMD-160 — only the constructor was missing, and
// x/crypto/ripemd160 was used instead.  That package is deprecated and, more
// to the point here, its digest implements no encoding.BinaryMarshaler, so
// crypto/hmac cannot cache the ipad/opad states and re-compresses both on
// every single PBKDF2 iteration.
func newRIPEMD160() hash.Hash { d := ripemd160Init; return &d }

func newRIPEMD256() hash.Hash { d := ripemd256Init; return &d }

func newRIPEMD320() hash.Hash { d := ripemd320Init; return &d }

func (d *ripemdDigest) Size() int      { return d.size }
func (d *ripemdDigest) BlockSize() int { return 64 }

func (d *ripemdDigest) Reset() {
	switch d.size {
	case 16:
		*d = ripemd128Init
	case 20:
		*d = ripemd160Init
	case 32:
		*d = ripemd256Init
	default:
		*d = ripemd320Init
	}
}

func (d *ripemdDigest) Write(p []byte) (int, error) {
	n := len(p)
	d.length += uint64(n)
	if d.nx > 0 {
		c := copy(d.x[d.nx:], p)
		d.nx += c
		if d.nx == 64 {
			d.block(d.x[:])
			d.nx = 0
		}
		p = p[c:]
	}
	for len(p) >= 64 {
		d.block(p[:64])
		p = p[64:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return n, nil
}

func (d *ripemdDigest) Sum(in []byte) []byte {
	// Work on a copy so Sum does not disturb a digest that is still being fed.
	c := *d

	length := c.length
	var pad [64]byte
	pad[0] = 0x80
	padLen := 56 - int(length%64)
	if padLen <= 0 {
		padLen += 64
	}
	_, _ = c.Write(pad[:padLen])
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], length<<3)
	_, _ = c.Write(lenBytes[:])

	out := make([]byte, c.size)
	for i := 0; i < c.size/4; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], c.h[i])
	}
	return append(in, out...)
}

func (d *ripemdDigest) block(p []byte) {
	var x [16]uint32
	for i := range x {
		x[i] = binary.LittleEndian.Uint32(p[i*4:])
	}
	if d.rounds == 5 {
		d.block5(&x)
		return
	}
	d.block4(&x)
}

// block4 runs the 4-round structure shared by RIPEMD-128 and RIPEMD-256.
func (d *ripemdDigest) block4(x *[16]uint32) {
	a, b, c, e := d.h[0], d.h[1], d.h[2], d.h[3]
	var aa, bb, cc, dd uint32
	if d.wide {
		aa, bb, cc, dd = d.h[4], d.h[5], d.h[6], d.h[7]
	} else {
		aa, bb, cc, dd = a, b, c, e
	}
	dLeft := e

	for j := 0; j < 4; j++ {
		kl := ripemdKLeft4[j]
		kr := ripemdKRight4[j]
		lo := j * 16
		// The round function is selected per round, not per step. It used to be
		// a call — already inlined, but the five-way switch stayed inside the
		// inner loop and ran 16 times per round on a value that cannot change
		// there. Hoisting it into a switch over specialised loops makes each
		// round's function a constant expression, worth about a quarter of the
		// time; VeraCrypt's RIPEMD-160 KDF runs 655,331 iterations for each of
		// ten derived blocks, so that is seconds per candidate.
		//
		// The five functions, in order, are:
		//
		//	0  x ^ y ^ z
		//	1  (x & y) | (~x & z)
		//	2  (x | ~y) ^ z
		//	3  (x & z) | (y & ~z)
		//	4  x ^ (y | ~z)
		//
		// The left line walks them forwards and the right line backwards, so
		// round j pairs function j with function (rounds-1-j).
		switch j {
		case 0:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+(b^c^dLeft)+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i]))
				a, dLeft, c, b = dLeft, c, b, t
				t = bits.RotateLeft32(aa+((bb&dd)|(cc & ^dd))+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i]))
				aa, dd, cc, bb = dd, cc, bb, t
			}
		case 1:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+((b&c)|(^b&dLeft))+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i]))
				a, dLeft, c, b = dLeft, c, b, t
				t = bits.RotateLeft32(aa+((bb|^cc)^dd)+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i]))
				aa, dd, cc, bb = dd, cc, bb, t
			}
		case 2:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+((b|^c)^dLeft)+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i]))
				a, dLeft, c, b = dLeft, c, b, t
				t = bits.RotateLeft32(aa+((bb&cc)|(^bb&dd))+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i]))
				aa, dd, cc, bb = dd, cc, bb, t
			}
		case 3:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+((b&dLeft)|(c & ^dLeft))+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i]))
				a, dLeft, c, b = dLeft, c, b, t
				t = bits.RotateLeft32(aa+(bb^cc^dd)+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i]))
				aa, dd, cc, bb = dd, cc, bb, t
			}
		}
		if d.wide {
			// RIPEMD-256 keeps the lines separate but swaps one word between
			// them after every round, which is what stops the two halves of the
			// digest from being computable independently.
			switch j {
			case 0:
				a, aa = aa, a
			case 1:
				b, bb = bb, b
			case 2:
				c, cc = cc, c
			case 3:
				dLeft, dd = dd, dLeft
			}
		}
	}
	if d.wide {
		d.h[0] += a
		d.h[1] += b
		d.h[2] += c
		d.h[3] += dLeft
		d.h[4] += aa
		d.h[5] += bb
		d.h[6] += cc
		d.h[7] += dd
		return
	}
	t := d.h[1] + c + dd
	d.h[1] = d.h[2] + dLeft + aa
	d.h[2] = d.h[3] + a + bb
	d.h[3] = d.h[0] + b + cc
	d.h[0] = t
}

// block5 runs the 5-round structure shared by RIPEMD-160 and RIPEMD-320.
func (d *ripemdDigest) block5(x *[16]uint32) {
	a, b, c, dl, e := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4]
	var aa, bb, cc, dd, ee uint32
	if d.wide {
		aa, bb, cc, dd, ee = d.h[5], d.h[6], d.h[7], d.h[8], d.h[9]
	} else {
		aa, bb, cc, dd, ee = a, b, c, dl, e
	}

	for j := 0; j < 5; j++ {
		kl := ripemdKLeft5[j]
		kr := ripemdKRight5[j]
		lo := j * 16
		// The round function is selected per round, not per step. It used to be
		// a call — already inlined, but the five-way switch stayed inside the
		// inner loop and ran 16 times per round on a value that cannot change
		// there. Hoisting it into a switch over specialised loops makes each
		// round's function a constant expression, worth about a quarter of the
		// time; VeraCrypt's RIPEMD-160 KDF runs 655,331 iterations for each of
		// ten derived blocks, so that is seconds per candidate.
		//
		// The five functions, in order, are:
		//
		//	0  x ^ y ^ z
		//	1  (x & y) | (~x & z)
		//	2  (x | ~y) ^ z
		//	3  (x & z) | (y & ~z)
		//	4  x ^ (y | ~z)
		//
		// The left line walks them forwards and the right line backwards, so
		// round j pairs function j with function (rounds-1-j).
		switch j {
		case 0:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+(b^c^dl)+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i])) + e
				a, e, dl, c, b = e, dl, bits.RotateLeft32(c, 10), b, t
				t = bits.RotateLeft32(aa+(bb^(cc|^dd))+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i])) + ee
				aa, ee, dd, cc, bb = ee, dd, bits.RotateLeft32(cc, 10), bb, t
			}
		case 1:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+((b&c)|(^b&dl))+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i])) + e
				a, e, dl, c, b = e, dl, bits.RotateLeft32(c, 10), b, t
				t = bits.RotateLeft32(aa+((bb&dd)|(cc & ^dd))+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i])) + ee
				aa, ee, dd, cc, bb = ee, dd, bits.RotateLeft32(cc, 10), bb, t
			}
		case 2:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+((b|^c)^dl)+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i])) + e
				a, e, dl, c, b = e, dl, bits.RotateLeft32(c, 10), b, t
				t = bits.RotateLeft32(aa+((bb|^cc)^dd)+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i])) + ee
				aa, ee, dd, cc, bb = ee, dd, bits.RotateLeft32(cc, 10), bb, t
			}
		case 3:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+((b&dl)|(c & ^dl))+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i])) + e
				a, e, dl, c, b = e, dl, bits.RotateLeft32(c, 10), b, t
				t = bits.RotateLeft32(aa+((bb&cc)|(^bb&dd))+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i])) + ee
				aa, ee, dd, cc, bb = ee, dd, bits.RotateLeft32(cc, 10), bb, t
			}
		case 4:
			for i := lo; i < lo+16; i++ {
				t := bits.RotateLeft32(a+(b^(c|^dl))+x[ripemdOrderLeft[i]]+kl, int(ripemdRotLeft[i])) + e
				a, e, dl, c, b = e, dl, bits.RotateLeft32(c, 10), b, t
				t = bits.RotateLeft32(aa+(bb^cc^dd)+x[ripemdOrderRight[i]]+kr, int(ripemdRotRight[i])) + ee
				aa, ee, dd, cc, bb = ee, dd, bits.RotateLeft32(cc, 10), bb, t
			}
		}
		if d.wide {
			switch j {
			case 0:
				b, bb = bb, b
			case 1:
				dl, dd = dd, dl
			case 2:
				a, aa = aa, a
			case 3:
				c, cc = cc, c
			case 4:
				e, ee = ee, e
			}
		}
	}
	if d.wide {
		d.h[0] += a
		d.h[1] += b
		d.h[2] += c
		d.h[3] += dl
		d.h[4] += e
		d.h[5] += aa
		d.h[6] += bb
		d.h[7] += cc
		d.h[8] += dd
		d.h[9] += ee
		return
	}
	t := d.h[1] + c + dd
	d.h[1] = d.h[2] + dl + ee
	d.h[2] = d.h[3] + e + aa
	d.h[3] = d.h[4] + a + bb
	d.h[4] = d.h[0] + b + cc
	d.h[0] = t
}

// ripemdMarshalMagic tags a serialised digest.  The trailing byte is the
// digest size, so a state saved from one width can never be restored into
// another — the two would otherwise be indistinguishable byte strings of
// different lengths.
const ripemdMarshalMagic = "hashsmith\x01ripemd\x01"

// MarshalBinary, AppendBinary and UnmarshalBinary exist for crypto/hmac.
//
// hmac keeps the key's inner and outer states and restores them for every
// message, but only when the hash can serialise itself; otherwise it
// re-compresses the 64-byte ipad and opad blocks each time.  In PBKDF2 that is
// the difference between two and four compressions per iteration, and
// VeraCrypt's RIPEMD-160 KDF runs 655,331 iterations for each of ten derived
// blocks.  Measured with x/crypto/sha512, which does implement this, hiding
// the marshaler behind a wrapper costs 1.66x.
func (d *ripemdDigest) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, len(ripemdMarshalMagic)+1+40+64+8+1))
}

func (d *ripemdDigest) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, ripemdMarshalMagic...)
	b = append(b, byte(d.size))
	for i := 0; i < d.hn; i++ {
		b = binary.BigEndian.AppendUint32(b, d.h[i])
	}
	b = append(b, d.x[:]...)
	b = append(b, byte(d.nx))
	return binary.BigEndian.AppendUint64(b, d.length), nil
}

func (d *ripemdDigest) UnmarshalBinary(b []byte) error {
	if len(b) < len(ripemdMarshalMagic)+1 || string(b[:len(ripemdMarshalMagic)]) != ripemdMarshalMagic {
		return errors.New("ripemd: invalid hash state identifier")
	}
	b = b[len(ripemdMarshalMagic):]
	if int(b[0]) != d.size {
		return errors.New("ripemd: hash state is for a different digest size")
	}
	b = b[1:]
	if len(b) != d.hn*4+64+1+8 {
		return errors.New("ripemd: invalid hash state size")
	}
	for i := 0; i < d.hn; i++ {
		d.h[i] = binary.BigEndian.Uint32(b[i*4:])
	}
	b = b[d.hn*4:]
	copy(d.x[:], b[:64])
	b = b[64:]
	d.nx = int(b[0])
	if d.nx >= 64 {
		return errors.New("ripemd: invalid buffered length in hash state")
	}
	d.length = binary.BigEndian.Uint64(b[1:])
	return nil
}
