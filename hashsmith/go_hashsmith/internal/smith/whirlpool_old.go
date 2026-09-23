package smith

// Whirlpool-0 and Whirlpool-T: the two revisions the final Whirlpool replaced.
//
// The three differ only in constants — Whirlpool-0's S-box was replaced in
// 2001 (giving Whirlpool-T) and the diffusion matrix in 2003 (giving the ISO
// version) — so one round function serves all three, taking its table and its
// round constants as an argument. whirlpool.go keeps its own copy for the
// final version because that one generates its tables from the S-box; these
// two carry theirs, in whirlpool_old_tables.go.
//
// The convention here is sphlib's, which is what John uses: words are read
// and written little-endian, a byte index counts from the low end, and the
// seven tables beyond the first are the first rotated LEFT one byte at a
// time. The final Whirlpool in this package reads bytes from the high end
// and rotates right, which computes the same thing and would have been a
// confusing thing to force these two into.
//
// The message length is a 256-bit big-endian count of BITS, in the last
// thirty-two bytes of the final block — four times wider than the usual
// 64-bit tail, which is the one place a Whirlpool implementation written from
// an MD5 habit goes wrong.

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

type whirlpoolOld struct {
	t0    *[256]uint64
	rc    *[10]uint64
	state [8]uint64
	buf   [64]byte
	nx    int
	// The bit count, big-endian across 32 bytes.
	length [32]byte
}

func newWhirlpool0() hash.Hash {
	return &whirlpoolOld{t0: &whirlpool0T0, rc: &whirlpool0RC}
}

func newWhirlpoolT() hash.Hash {
	return &whirlpoolOld{t0: &whirlpool1T0, rc: &whirlpool1RC}
}

func (d *whirlpoolOld) Size() int      { return 64 }
func (d *whirlpoolOld) BlockSize() int { return 64 }

func (d *whirlpoolOld) Reset() {
	d.state = [8]uint64{}
	d.buf = [64]byte{}
	d.nx = 0
	d.length = [32]byte{}
}

// mix is one application of the round transformation to eight words: each
// output word gathers one byte from each input word, taken along a diagonal,
// through the table.
func (d *whirlpoolOld) mix(in, c *[8]uint64) [8]uint64 {
	var out [8]uint64
	for j := 0; j < 8; j++ {
		var v uint64
		for k := 0; k < 8; k++ {
			b := byte(in[(j-k)&7] >> (8 * k))
			v ^= bits.RotateLeft64(d.t0[b], 8*k)
		}
		out[j] = v ^ c[j]
	}
	return out
}

func (d *whirlpoolOld) compress(src []byte) {
	var n, h, sn [8]uint64
	for i := range n {
		sn[i] = binary.LittleEndian.Uint64(src[8*i:])
		n[i] = sn[i]
		h[i] = d.state[i]
		n[i] ^= h[i]
	}
	for r := 0; r < 10; r++ {
		// The key schedule is the same transformation with only the first
		// word taking a constant.
		kc := [8]uint64{d.rc[r]}
		h = d.mix(&h, &kc)
		n = d.mix(&n, &h)
	}
	for i := range d.state {
		d.state[i] ^= n[i] ^ sn[i]
	}
}

func (d *whirlpoolOld) Write(p []byte) (int, error) {
	n := len(p)
	addBits(&d.length, uint64(n)*8)
	for len(p) > 0 {
		c := copy(d.buf[d.nx:], p)
		d.nx += c
		p = p[c:]
		if d.nx == 64 {
			d.compress(d.buf[:])
			d.nx = 0
		}
	}
	return n, nil
}

func (d *whirlpoolOld) Sum(b []byte) []byte {
	c := *d
	var tail [128]byte
	n := copy(tail[:], c.buf[:c.nx])
	tail[n] = 0x80
	pad := 64
	if n+1 > 32 {
		pad = 128
	}
	copy(tail[pad-32:pad], c.length[:])
	for i := 0; i < pad; i += 64 {
		c.compress(tail[i : i+64])
	}
	var out [64]byte
	for i, w := range c.state {
		binary.LittleEndian.PutUint64(out[8*i:], w)
	}
	return append(b, out[:]...)
}
