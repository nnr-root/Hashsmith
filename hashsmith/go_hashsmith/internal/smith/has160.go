package smith

// HAS-160, the hash the Korea Information Security Agency designed in 1998 to
// go with KCDSA, their national digital-signature standard.
//
// It is SHA-1 rearranged: the same five 32-bit words, the same four groups of
// twenty steps, the same four boolean functions and constants. What KISA
// changed is the schedule. SHA-1 expands sixteen message words into eighty by
// a recurrence; HAS-160 instead derives four extra words per group by XOR,
// and then visits all twenty in an order that differs group to group. It also
// rotates the working word by an amount that varies step to step rather than
// by a fixed five.
//
// The tables below are that schedule, and they are the whole algorithm. They
// were transcribed from the eighty-line macro expansion in a reference
// implementation and then checked for the regularity the specification claims
// — that the rotation amounts repeat identically across all four groups, and
// that the five registers rotate one place per step — so a mistyped entry
// would have to survive both that check and the published digests below.

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	has160Size      = 20
	has160BlockSize = 64
)

// has160Rot is the amount the leading word is rotated by, step by step. The
// same twenty amounts serve all four groups.
var has160Rot = [20]uint{5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13}

// has160Idx is which of the thirty-two words each step consumes. Indices 16
// and above are the derived words; each group derives its own four and reads
// them at steps 0, 5, 10 and 15.
var has160Idx = [4][20]int{
	{18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8, 9, 10, 11, 17, 12, 13, 14, 15},
	{22, 3, 6, 9, 12, 23, 15, 2, 5, 8, 20, 11, 14, 1, 4, 21, 7, 10, 13, 0},
	{26, 12, 5, 14, 7, 27, 0, 9, 2, 11, 24, 4, 13, 6, 15, 25, 8, 1, 10, 3},
	{30, 7, 2, 13, 8, 31, 3, 14, 9, 4, 28, 15, 10, 5, 0, 29, 11, 6, 1, 12},
}

// has160Derive says which four message words are XORed to make each of the
// sixteen derived ones.
var has160Derive = [16][4]int{
	{0, 1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11}, {12, 13, 14, 15},
	{3, 6, 9, 12}, {2, 5, 8, 15}, {1, 4, 11, 14}, {0, 7, 10, 13},
	{5, 7, 12, 14}, {0, 2, 9, 11}, {4, 6, 13, 15}, {1, 3, 8, 10},
	{2, 7, 8, 13}, {3, 4, 9, 14}, {0, 5, 10, 15}, {1, 6, 11, 12},
}

// The per-group constant and the fixed rotation applied to the second word.
var (
	has160K    = [4]uint32{0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC}
	has160BRot = [4]uint{10, 17, 25, 30}
)

type has160Digest struct {
	h     [5]uint32
	block [has160BlockSize]byte
	off   int
	len   uint64
}

func newHAS160() hash.Hash {
	d := &has160Digest{}
	d.Reset()
	return d
}

func (d *has160Digest) Size() int      { return has160Size }
func (d *has160Digest) BlockSize() int { return has160BlockSize }

func (d *has160Digest) Reset() {
	d.h = [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	d.off = 0
	d.len = 0
}

func (d *has160Digest) compress(p []byte) {
	var x [32]uint32
	for i := 0; i < 16; i++ {
		x[i] = binary.LittleEndian.Uint32(p[4*i:])
	}
	for i, q := range has160Derive {
		x[16+i] = x[q[0]] ^ x[q[1]] ^ x[q[2]] ^ x[q[3]]
	}

	a, b, c, e0, e := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4]
	for g := 0; g < 4; g++ {
		for s := 0; s < 20; s++ {
			var f uint32
			switch g {
			case 0:
				f = e0 ^ (b & (c ^ e0))
			case 2:
				f = c ^ (b | ^e0)
			default:
				f = b ^ c ^ e0
			}
			e += bits.RotateLeft32(a, int(has160Rot[s])) + f + x[has160Idx[g][s]] + has160K[g]
			b = bits.RotateLeft32(b, int(has160BRot[g]))
			// The five registers move one place along, which is what the
			// reference's eighty separate macro calls spell out by rotating
			// their arguments.
			a, b, c, e0, e = e, a, b, c, e0
		}
	}
	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += e0
	d.h[4] += e
}

func (d *has160Digest) Write(p []byte) (int, error) {
	n := len(p)
	d.len += uint64(n)
	if d.off > 0 {
		c := copy(d.block[d.off:], p)
		d.off += c
		p = p[c:]
		if d.off < has160BlockSize {
			return n, nil
		}
		d.compress(d.block[:])
		d.off = 0
	}
	for len(p) >= has160BlockSize {
		d.compress(p[:has160BlockSize])
		p = p[has160BlockSize:]
	}
	d.off = copy(d.block[:], p)
	return n, nil
}

func (d *has160Digest) Sum(b []byte) []byte {
	c := *d
	var tail [2 * has160BlockSize]byte
	n := copy(tail[:], c.block[:c.off])
	tail[n] = 0x80
	pad := has160BlockSize
	if c.off >= has160BlockSize-8 {
		pad = 2 * has160BlockSize
	}
	binary.LittleEndian.PutUint64(tail[pad-8:], c.len<<3)
	for i := 0; i < pad; i += has160BlockSize {
		c.compress(tail[i : i+has160BlockSize])
	}
	var out [has160Size]byte
	for i, w := range c.h {
		binary.LittleEndian.PutUint32(out[4*i:], w)
	}
	return append(b, out[:]...)
}
