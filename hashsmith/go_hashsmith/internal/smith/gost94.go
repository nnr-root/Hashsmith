package smith

import (
	"encoding/binary"
	"hash"
)

// GOST R 34.11-94, the Russian hash standard that Streebog (GOST R 34.11-2012,
// already here as streebog.go) replaced. Hashcat calls it mode 6900 and John
// calls it "gost".
//
// It is a 256-bit hash built on the GOST 28147-89 block cipher, and the cipher
// is parameterised by an S-box that the standard does NOT fix. Two sets are in
// circulation: the "test parameters" from the standard's own examples, and
// CryptoPro's (RFC 4357), which is what real deployments use. They produce
// completely different digests from the same input, so the choice is not a
// detail — it is which of two different hash functions this is.
//
// Both are here, and both are checked against their own published vectors:
//
//	""     test parameters  ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d
//	""     CryptoPro        981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0
//
// Hashcat's mode 6900 is the TEST-PARAMETER one, which its own example record
// settles: "hashcat" hashes to df226c2c… under those and to 256f021a… under
// CryptoPro.

// gost94CryptoProSbox is the CryptoPro parameter set (RFC 4357 id-GostR3411-94-
// CryptoProParamSet), stored as eight rows of sixteen 4-bit values.
var gost94CryptoProSbox = [8][16]byte{
	{10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
	{5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
	{7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
	{4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
	{7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
	{7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
	{13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
	{1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12},
}

// gost94Tables flattens the S-box into four 8-bit-indexed tables with the
// 11-bit rotation already applied, which is the usual way to run GOST 28147-89
// at a sensible speed: one table lookup and an OR per byte pair instead of
// eight nibble lookups and a shift.
type gost94Tables [4][256]uint32

func newGOST94Tables(sbox [8][16]byte) *gost94Tables {
	var t gost94Tables
	for i := 0; i < 4; i++ {
		for j := 0; j < 256; j++ {
			lo := uint32(sbox[2*i][j&0x0f])
			hi := uint32(sbox[2*i+1][j>>4])
			v := lo | hi<<4
			// Rotate left by 11 + 8*i, the cipher's fixed rotation folded into
			// the table. The modulo is not cosmetic: for the top table the
			// raw shift is 35, and in Go a uint32 shifted by 35 is zero, so
			// without it a quarter of the substitution silently vanishes.
			shift := uint(11+8*i) % 32
			t[i][j] = v<<shift | v>>(32-shift)
		}
	}
	return &t
}

// gost94TestSbox is the parameter set from the standard's own worked examples
// (RFC 4357 id-GostR3411-94-TestParamSet). Hashcat mode 6900 uses it.
var gost94TestSbox = [8][16]byte{
	{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
	{14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
	{5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
	{7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
	{6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
	{4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
	{13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
	{1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12},
}

var (
	gost94CryptoProTables = newGOST94Tables(gost94CryptoProSbox)
	gost94TestTables      = newGOST94Tables(gost94TestSbox)
)

// encrypt runs GOST 28147-89 over one 64-bit block with the eight-word key.
func (t *gost94Tables) encrypt(key *[8]uint32, n1, n2 uint32) (uint32, uint32) {
	f := func(x uint32) uint32 {
		return t[0][byte(x)] | t[1][byte(x>>8)] | t[2][byte(x>>16)] | t[3][byte(x>>24)]
	}
	// Three forward passes over the key, then one in reverse.
	for round := 0; round < 3; round++ {
		for i := 0; i < 8; i += 2 {
			n2 ^= f(n1 + key[i])
			n1 ^= f(n2 + key[i+1])
		}
	}
	for i := 7; i > 0; i -= 2 {
		n2 ^= f(n1 + key[i])
		n1 ^= f(n2 + key[i-1])
	}
	return n2, n1
}

// gost94Digest is the streaming state.
type gost94Digest struct {
	tables *gost94Tables
	h      [32]byte // the chaining value
	sum    [32]byte // the running checksum, added modulo 2^256
	length uint64
	buf    [32]byte
	n      int
}

// newGOST94 is the test-parameter variant, which is what hashcat -m 6900 means
// by "GOST R 34.11-94".
func newGOST94() hash.Hash {
	return &gost94Digest{tables: gost94TestTables}
}

// newGOST94CryptoPro is the CryptoPro variant, which is what a Russian PKI
// deployment means by the same name.
func newGOST94CryptoPro() hash.Hash {
	return &gost94Digest{tables: gost94CryptoProTables}
}

func (d *gost94Digest) Size() int      { return 32 }
func (d *gost94Digest) BlockSize() int { return 32 }

func (d *gost94Digest) Reset() {
	d.h = [32]byte{}
	d.sum = [32]byte{}
	d.length = 0
	d.n = 0
}

func (d *gost94Digest) Write(p []byte) (int, error) {
	total := len(p)
	d.length += uint64(len(p)) * 8
	for len(p) > 0 {
		k := copy(d.buf[d.n:], p)
		d.n += k
		p = p[k:]
		if d.n == 32 {
			d.block(d.buf[:])
			d.addChecksum(d.buf[:])
			d.n = 0
		}
	}
	return total, nil
}

func (d *gost94Digest) Sum(in []byte) []byte {
	c := *d
	if c.n > 0 {
		// The final partial block is zero-padded on the RIGHT, and the length
		// counted is the real message length, not the padded one.
		var last [32]byte
		copy(last[:], c.buf[:c.n])
		c.block(last[:])
		c.addChecksum(last[:])
	}
	var lenBlock [32]byte
	binary.LittleEndian.PutUint64(lenBlock[:8], c.length)
	c.block(lenBlock[:])
	c.block(c.sum[:])
	return append(in, c.h[:]...)
}

// addChecksum adds a block to the running 256-bit checksum, little-endian with
// carry across the whole width.
func (d *gost94Digest) addChecksum(block []byte) {
	carry := 0
	for i := 0; i < 32; i++ {
		v := int(d.sum[i]) + int(block[i]) + carry
		d.sum[i] = byte(v)
		carry = v >> 8
	}
}

// block is the compression function: it folds one 32-byte message block into
// the chaining value h.
//
// The structure is fixed by the standard. Four keys are generated from h and
// the message by a sequence of linear mixes, each key encrypts one 64-bit
// quarter of h, and the four ciphertext quarters are then run through a
// 61-round shift-register mixing that also draws on h and the message. It is
// long, it is not reducible, and every step is load-bearing.
func (d *gost94Digest) block(m []byte) {
	var h, mm [8]uint32
	for i := 0; i < 8; i++ {
		h[i] = binary.LittleEndian.Uint32(d.h[i*4:])
		mm[i] = binary.LittleEndian.Uint32(m[i*4:])
	}

	// u = h, v = m, w = u xor v; the first key is P(w).
	var u, v, w, key [8]uint32
	u = h
	v = mm
	for i := 0; i < 8; i++ {
		w[i] = u[i] ^ v[i]
	}
	gost94P(&key, &w)

	var s [8]uint32
	for i := 0; i < 4; i++ {
		if i > 0 {
			// u = A(u) xor C_i, v = A(A(v)), w = u xor v, key = P(w).
			gost94A(&u)
			if i == 2 {
				// C3 is the only non-zero constant: RFC 5831 gives C2 = C4 = 0
				// and spells C3 out as a bit pattern, which expands to these
				// words once it is read little-endian the way the state is.
				u[0] ^= 0xff00ff00
				u[1] ^= 0xff00ff00
				u[2] ^= 0x00ff00ff
				u[3] ^= 0x00ff00ff
				u[4] ^= 0x00ffff00
				u[5] ^= 0xff0000ff
				u[6] ^= 0x000000ff
				u[7] ^= 0xff00ffff
			}
			gost94A(&v)
			gost94A(&v)
			for j := 0; j < 8; j++ {
				w[j] = u[j] ^ v[j]
			}
			gost94P(&key, &w)
		}
		var k [8]uint32
		copy(k[:], key[:])
		a, b := d.tables.encrypt(&k, h[i*2], h[i*2+1])
		s[i*2], s[i*2+1] = a, b
	}

	// psi-mixing: 12 rounds on s, then xor in m, one round, xor in h, 61 rounds.
	for i := 0; i < 12; i++ {
		gost94Psi(&s)
	}
	for i := 0; i < 8; i++ {
		s[i] ^= mm[i]
	}
	gost94Psi(&s)
	for i := 0; i < 8; i++ {
		s[i] ^= h[i]
	}
	for i := 0; i < 61; i++ {
		gost94Psi(&s)
	}
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(d.h[i*4:], s[i])
	}
}

// gost94P is the standard's byte-transposition P, which spreads the 32 bytes
// of w into the key.
func gost94P(key *[8]uint32, w *[8]uint32) {
	var wb, kb [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(wb[i*4:], w[i])
	}
	for i := 0; i < 4; i++ {
		for k := 0; k < 8; k++ {
			kb[i+4*k] = wb[8*i+k]
		}
	}
	for i := 0; i < 8; i++ {
		key[i] = binary.LittleEndian.Uint32(kb[i*4:])
	}
}

// gost94A is the standard's A: shift the 256-bit value down by 64 bits and put
// the xor of the two lowest 64-bit words on top.
func gost94A(x *[8]uint32) {
	a0, a1 := x[0]^x[2], x[1]^x[3]
	copy(x[0:6], x[2:8])
	x[6], x[7] = a0, a1
}

// gost94Psi is the 16-bit linear-feedback step the mixing rounds use.
func gost94Psi(x *[8]uint32) {
	var b [16]uint16
	for i := 0; i < 8; i++ {
		b[i*2] = uint16(x[i])
		b[i*2+1] = uint16(x[i] >> 16)
	}
	next := b[0] ^ b[1] ^ b[2] ^ b[3] ^ b[12] ^ b[15]
	copy(b[0:15], b[1:16])
	b[15] = next
	for i := 0; i < 8; i++ {
		x[i] = uint32(b[i*2]) | uint32(b[i*2+1])<<16
	}
}
