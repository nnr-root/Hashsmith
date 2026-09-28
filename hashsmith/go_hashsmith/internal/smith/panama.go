package smith

// PANAMA, by Joan Daemen and Craig Clapp (1998).
//
// Panama is not a Merkle-Damgård hash at all. It is a cryptographic state
// machine — the same construction Daemen later reworked into Keccak's sponge
// — with a 17-word state and a 32-stage buffer of eight words each, arranged
// as a shift register. Absorbing a block ("push") stirs it in; producing a
// digest ("pull") runs 32 more blank rounds and then reads eight words out of
// the state. Its collision resistance as a hash was broken in 2001 and again
// in 2007, which is why nothing has used it since; the stream cipher of the
// same design is a separate matter.
//
// John keeps it because data outlives algorithms, and this is the last of the
// nineteen hash names in John's dynamic expression table that Hashsmith did
// not have.
//
// The buffer is addressed by a moving pointer rather than shifted, so the
// three offsets in each step — eight back, one back, and sixteen away — are
// all relative to it, and the pointer then moves one stage back. That, and
// the fact that "one" is XORed into the first state word on every single
// round, are the two details that a reimplementation gets wrong.

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const panamaBlockSize = 32

// panamaPi is the permutation-and-rotation stage: output word i takes word
// panamaPi[i].from and rotates it left by panamaPi[i].rot.
var panamaPi = [17]struct {
	from int
	rot  int
}{
	{0, 0}, {7, 1}, {14, 3}, {4, 6}, {11, 10}, {1, 15}, {8, 21}, {15, 28},
	{5, 4}, {12, 13}, {2, 23}, {9, 2}, {16, 14}, {6, 27}, {13, 9}, {3, 24},
	{10, 8},
}

type panamaDigest struct {
	state  [17]uint32
	buffer [32][8]uint32
	bufPtr int
	data   [panamaBlockSize]byte
	off    int
}

func newPanama() hash.Hash { return &panamaDigest{} }

func (d *panamaDigest) Size() int      { return 32 }
func (d *panamaDigest) BlockSize() int { return panamaBlockSize }

func (d *panamaDigest) Reset() { *d = panamaDigest{} }

// step is one round of the state machine. in1 feeds the buffer, in2 feeds the
// state; pushing a message block passes the same eight words as both, while
// pulling passes the state's own words as in1 and a buffer stage as in2.
func (d *panamaDigest) step(in1, in2 *[8]uint32) {
	ptr24 := (d.bufPtr - 8) & 31
	ptr31 := (d.bufPtr - 1) & 31

	for k := 0; k < 8; k++ {
		n2 := (k + 2) & 7
		d.buffer[ptr24][k] ^= d.buffer[ptr31][n2]
		d.buffer[ptr31][n2] ^= in1[n2]
	}

	a := &d.state
	var g, p, t [17]uint32
	for i := 0; i < 17; i++ {
		g[i] = a[i] ^ (a[(i+1)%17] | ^a[(i+2)%17])
	}
	for i := 0; i < 17; i++ {
		p[i] = bits.RotateLeft32(g[panamaPi[i].from], panamaPi[i].rot)
	}
	for i := 0; i < 17; i++ {
		t[i] = p[i] ^ p[(i+1)%17] ^ p[(i+4)%17]
	}

	ptr16 := d.bufPtr ^ 16
	// The lone constant in the whole design: a 1 into the first word, every
	// round, which is what stops an all-zero state being a fixed point.
	a[0] = t[0] ^ 1
	for i := 0; i < 8; i++ {
		a[1+i] = t[1+i] ^ in2[i]
		a[9+i] = t[9+i] ^ d.buffer[ptr16][i]
	}
	d.bufPtr = ptr31
}

func (d *panamaDigest) push(block []byte) {
	var w [8]uint32
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(block[4*i:])
	}
	d.step(&w, &w)
}

func (d *panamaDigest) pull() {
	ptr4 := (d.bufPtr + 4) & 31
	// The buffer stage read here is taken before the step moves the pointer,
	// and the state words fed back in are the ones from before this round.
	var in1, in2 [8]uint32
	copy(in1[:], d.state[1:9])
	in2 = d.buffer[ptr4]
	d.step(&in1, &in2)
}

func (d *panamaDigest) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		c := copy(d.data[d.off:], p)
		d.off += c
		p = p[c:]
		if d.off == panamaBlockSize {
			d.push(d.data[:])
			d.off = 0
		}
	}
	return n, nil
}

// Sum pads with a single 0x01 byte and no length at all — Panama carries no
// message-length field, because the pull phase and not the padding is what
// separates one message from another.
func (d *panamaDigest) Sum(b []byte) []byte {
	c := *d
	var last [panamaBlockSize]byte
	copy(last[:], c.data[:c.off])
	last[c.off] = 0x01
	c.push(last[:])
	for i := 0; i < 32; i++ {
		c.pull()
	}
	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], c.state[9+i])
	}
	return append(b, out[:]...)
}
