package smith

// Tiger, by Ross Anderson and Eli Biham (1995).
//
// Tiger is the hash the 1990s reached for when it wanted something faster
// than SHA-1 on 64-bit machines, and it survives in file-sharing checksums,
// in Merkle tree hashes, and — the reason it is here — in sixteen of John's
// dynamic expressions and in its own `tiger` format.
//
// The structure is unremarkable Merkle-Damgård over a 192-bit state. What is
// unusual is where the S-boxes come from. Tiger needs four tables of 256
// 64-bit words, and the specification does not print them: it prints a
// PROGRAM that produces them. The tables start as the trivial one, and are
// then shuffled by five passes of Tiger's own compression function keyed on a
// sentence from the paper. Transcribing four thousand constants invites four
// thousand chances to mistype one; running the generator is forty lines and
// is checked in full by the published digests below.
//
// The generator is self-referential — it compresses with the table it is in
// the middle of rewriting — so the order of the two nested loops is part of
// the definition and not an implementation detail.
//
// Two conventions catch people out and both are settled by the test vectors:
// the padding byte is 0x01, not 0x80 (0x80 is Tiger2, a later revision that
// is a different hash), and the digest is the three state words written
// LITTLE-endian, which is why the canonical hex for the empty message begins
// 3293AC63 while the reference implementation's own test program prints
// 24F0130C for the same word.

import (
	"encoding/binary"
	"hash"
	"sync"
)

const (
	tigerSize      = 24
	tigerBlockSize = 64
	// The sentence the specification keys the table generator on. It is
	// exactly one compression block long, which is not a coincidence.
	tigerSeed = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham"
)

var (
	tigerOnce  sync.Once
	tigerTable [1024]uint64
)

// tigerSBoxes runs the specification's generator once, on first use.
func tigerSBoxes() *[1024]uint64 {
	tigerOnce.Do(func() {
		t := &tigerTable
		// Every entry starts as its own index repeated in all eight bytes.
		for i := range t {
			b := byte(i)
			t[i] = 0x0101010101010101 * uint64(b)
		}

		state := [3]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187}
		var seed [8]uint64
		for i := range seed {
			seed[i] = binary.LittleEndian.Uint64([]byte(tigerSeed)[8*i:])
		}

		// byteOf and setByte read and write byte `col` of a word as the
		// generator's pointer arithmetic does: little-endian, so byte 0 is
		// the least significant.
		byteOf := func(w uint64, col uint) byte { return byte(w >> (8 * col)) }
		setByte := func(w *uint64, col uint, v byte) {
			*w = (*w &^ (0xFF << (8 * col))) | uint64(v)<<(8*col)
		}

		abc := 2
		for cnt := 0; cnt < 5; cnt++ {
			for i := 0; i < 256; i++ {
				for sb := 0; sb < 1024; sb += 256 {
					abc++
					if abc == 3 {
						abc = 0
						tigerCompress(&seed, &state, t)
					}
					for col := uint(0); col < 8; col++ {
						j := sb + int(byteOf(state[abc], col))
						a, b := byteOf(t[sb+i], col), byteOf(t[j], col)
						setByte(&t[sb+i], col, b)
						setByte(&t[j], col, a)
					}
				}
			}
		}
	})
	return &tigerTable
}

// tigerCompress runs Tiger's three passes over one block. The table is passed
// in rather than read from the package variable because the generator above
// has to compress with a table it is still rewriting.
func tigerCompress(x *[8]uint64, state *[3]uint64, t *[1024]uint64) {
	a, b, c := state[0], state[1], state[2]
	aa, bb, cc := a, b, c
	w := *x

	t1, t2, t3, t4 := t[0:256], t[256:512], t[512:768], t[768:1024]

	round := func(a, b *uint64, c *uint64, x uint64, mul uint64) {
		*c ^= x
		*a -= t1[byte(*c)] ^ t2[byte(*c>>16)] ^ t3[byte(*c>>32)] ^ t4[byte(*c>>48)]
		*b += t4[byte(*c>>8)] ^ t3[byte(*c>>24)] ^ t2[byte(*c>>40)] ^ t1[byte(*c>>56)]
		*b *= mul
	}
	pass := func(a, b, c *uint64, mul uint64) {
		round(a, b, c, w[0], mul)
		round(b, c, a, w[1], mul)
		round(c, a, b, w[2], mul)
		round(a, b, c, w[3], mul)
		round(b, c, a, w[4], mul)
		round(c, a, b, w[5], mul)
		round(a, b, c, w[6], mul)
		round(b, c, a, w[7], mul)
	}
	schedule := func() {
		w[0] -= w[7] ^ 0xA5A5A5A5A5A5A5A5
		w[1] ^= w[0]
		w[2] += w[1]
		w[3] -= w[2] ^ ((^w[1]) << 19)
		w[4] ^= w[3]
		w[5] += w[4]
		w[6] -= w[5] ^ ((^w[4]) >> 23)
		w[7] ^= w[6]
		w[0] += w[7]
		w[1] -= w[0] ^ ((^w[7]) << 19)
		w[2] ^= w[1]
		w[3] += w[2]
		w[4] -= w[3] ^ ((^w[2]) >> 23)
		w[5] ^= w[4]
		w[6] += w[5]
		w[7] -= w[6] ^ 0x0123456789ABCDEF
	}

	pass(&a, &b, &c, 5)
	schedule()
	pass(&c, &a, &b, 7)
	schedule()
	pass(&b, &c, &a, 9)

	state[0] = a ^ aa
	state[1] = b - bb
	state[2] = c + cc
}

type tigerDigest struct {
	state [3]uint64
	block [tigerBlockSize]byte
	off   int
	len   uint64
}

func newTiger() hash.Hash {
	d := &tigerDigest{}
	d.Reset()
	return d
}

func (d *tigerDigest) Size() int      { return tigerSize }
func (d *tigerDigest) BlockSize() int { return tigerBlockSize }

func (d *tigerDigest) Reset() {
	d.state = [3]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187}
	d.off = 0
	d.len = 0
}

func (d *tigerDigest) compressBlock(p []byte) {
	var x [8]uint64
	for i := range x {
		x[i] = binary.LittleEndian.Uint64(p[8*i:])
	}
	tigerCompress(&x, &d.state, tigerSBoxes())
}

func (d *tigerDigest) Write(p []byte) (int, error) {
	n := len(p)
	d.len += uint64(n)
	if d.off > 0 {
		c := copy(d.block[d.off:], p)
		d.off += c
		p = p[c:]
		if d.off < tigerBlockSize {
			return n, nil
		}
		d.compressBlock(d.block[:])
		d.off = 0
	}
	for len(p) >= tigerBlockSize {
		d.compressBlock(p[:tigerBlockSize])
		p = p[tigerBlockSize:]
	}
	d.off = copy(d.block[:], p)
	return n, nil
}

// Sum pads with 0x01 — Tiger's marker, where almost every other
// Merkle-Damgård hash writes 0x80 — and appends the bit length little-endian.
func (d *tigerDigest) Sum(b []byte) []byte {
	c := *d
	var tail [2 * tigerBlockSize]byte
	n := copy(tail[:], c.block[:c.off])
	tail[n] = 0x01
	pad := tigerBlockSize
	if c.off < tigerBlockSize-8 {
		pad = tigerBlockSize
	} else {
		pad = 2 * tigerBlockSize
	}
	binary.LittleEndian.PutUint64(tail[pad-8:], c.len<<3)
	for i := 0; i < pad; i += tigerBlockSize {
		c.compressBlock(tail[i : i+tigerBlockSize])
	}
	var out [tigerSize]byte
	for i, w := range c.state {
		binary.LittleEndian.PutUint64(out[8*i:], w)
	}
	return append(b, out[:]...)
}
