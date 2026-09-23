package smith

// Snefru, by Ralph Merkle (1990), in its 128- and 256-bit widths.
//
// Snefru is the hash that gave differential cryptanalysis its first scalp:
// Biham and Shamir broke the two-pass version, Merkle raised it to eight
// passes, and that eight-pass version — the one here, and the one everything
// that still mentions Snefru means — has stood since.
//
// Its shape is unlike the MD/SHA line. There is no separate compression
// function over a fixed block: the chaining value and the message block are
// laid side by side into one sixteen-word array, stirred by eight rounds of
// S-box lookups, and the far half of the result is XORed back into the
// chaining value. The digest width therefore changes the BLOCK size — a
// 128-bit digest leaves 48 bytes of room for message per block, a 256-bit
// digest only 32 — which is the one thing about Snefru that catches an
// implementation out, and the reason both widths are exercised below.
//
// The trailing length is written big-endian into the last eight bytes of a
// final block, and that block is always processed, even when the message
// happened to end exactly on a boundary.

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

type snefruDigest struct {
	h      [8]uint32
	size   int // digest length in bytes: 16 or 32
	block  [48]byte
	off    int
	length uint64
}

// newSnefru returns Snefru with a 16- or 32-byte digest.
func newSnefru(size int) hash.Hash {
	d := &snefruDigest{size: size}
	d.Reset()
	return d
}

func (d *snefruDigest) Size() int { return d.size }

// BlockSize is what is left of sixteen words once the chaining value has
// taken its share.
func (d *snefruDigest) BlockSize() int { return 64 - d.size }

func (d *snefruDigest) Reset() {
	d.h = [8]uint32{}
	d.off = 0
	d.length = 0
}

func (d *snefruDigest) compress(p []byte) {
	var w [16]uint32
	n := d.size / 4 // chaining words
	copy(w[:n], d.h[:n])
	for i := n; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(p[4*(i-n):])
	}

	for r := 0; r < 8; r++ {
		sbox := snefruSBox[512*r : 512*(r+1)]
		for _, rot := range [4]uint{16, 8, 16, 24} {
			for i := 0; i < 16; i++ {
				x := sbox[(i<<7&0x100)+int(w[i]&0xff)]
				w[(i-1)&15] ^= x
				if i >= 2 {
					w[(i-1)&15] = bits.RotateLeft32(w[(i-1)&15], -int(rot))
				}
				w[(i+1)&15] ^= x
			}
			w[0] = bits.RotateLeft32(w[0], -int(rot))
			w[15] = bits.RotateLeft32(w[15], -int(rot))
		}
	}

	// The far end of the stirred array folds back into the chaining value,
	// in reverse: word 15 into word 0.
	for i := 0; i < n; i++ {
		d.h[i] ^= w[15-i]
	}
}

func (d *snefruDigest) Write(p []byte) (int, error) {
	n := len(p)
	d.length += uint64(n)
	bs := d.BlockSize()
	if d.off > 0 {
		c := copy(d.block[d.off:bs], p)
		d.off += c
		p = p[c:]
		if d.off < bs {
			return n, nil
		}
		d.compress(d.block[:bs])
		d.off = 0
	}
	for len(p) >= bs {
		d.compress(p[:bs])
		p = p[bs:]
	}
	d.off = copy(d.block[:bs], p)
	return n, nil
}

func (d *snefruDigest) Sum(b []byte) []byte {
	c := *d
	bs := c.BlockSize()
	if c.off > 0 {
		var last [48]byte
		copy(last[:], c.block[:c.off])
		c.compress(last[:bs])
	}
	// The length always gets a block of its own, zero-filled ahead of it.
	var tail [48]byte
	binary.BigEndian.PutUint32(tail[bs-8:], uint32(c.length>>29))
	binary.BigEndian.PutUint32(tail[bs-4:], uint32(c.length<<3))
	c.compress(tail[:bs])

	var out [32]byte
	for i := 0; i < c.size/4; i++ {
		binary.BigEndian.PutUint32(out[4*i:], c.h[i])
	}
	return append(b, out[:c.size]...)
}
