package main

// Streebog (GOST R 34.11-2012), 256- and 512-bit — a KDF option in some
// VeraCrypt volumes. The L∘P∘S transform is applied through the precomputed
// streebogTR table (see streebog_tables.go); the compression g_N follows the
// standard. Pinned to the GOST test vectors in the tests.

import (
	"encoding/hex"
	"hash"
)

// streebogDigest implements hash.Hash for Streebog-512 (size=64) or -256 (=32).
type streebogDigest struct {
	h    [8]uint64
	n    [8]uint64
	s    [8]uint64
	buf  [64]byte
	nx   int
	size int // 64 or 32
}

func newStreebog512() hash.Hash { return &streebogDigest{size: 64} }
func newStreebog256() hash.Hash { d := &streebogDigest{size: 32}; d.initH(); return d }

func (d *streebogDigest) initH() {
	// 256-bit variant initialises h to all-0x01 bytes.
	for i := range d.h {
		d.h[i] = 0x0101010101010101
	}
}

func (d *streebogDigest) Size() int      { return d.size }
func (d *streebogDigest) BlockSize() int { return 64 }

func (d *streebogDigest) Reset() {
	*d = streebogDigest{size: d.size}
	if d.size == 32 {
		d.initH()
	}
}

// lpsx computes result = LPS(a XOR b) via the precomputed table.
func streebogLPSX(a, b *[8]uint64, result *[8]uint64) {
	var r [8]uint64
	for j := 0; j < 8; j++ {
		r[j] = a[j] ^ b[j]
	}
	for i := 0; i < 8; i++ {
		result[i] = streebogTR[0][(r[0]>>(uint(i)*8))&0xff] ^
			streebogTR[1][(r[1]>>(uint(i)*8))&0xff] ^
			streebogTR[2][(r[2]>>(uint(i)*8))&0xff] ^
			streebogTR[3][(r[3]>>(uint(i)*8))&0xff] ^
			streebogTR[4][(r[4]>>(uint(i)*8))&0xff] ^
			streebogTR[5][(r[5]>>(uint(i)*8))&0xff] ^
			streebogTR[6][(r[6]>>(uint(i)*8))&0xff] ^
			streebogTR[7][(r[7]>>(uint(i)*8))&0xff]
	}
}

// gN is the compression g_N(h, m) = E(LPS(h⊕N), m) ⊕ h ⊕ m.
func streebogGN(n, h, m *[8]uint64) {
	var k, state [8]uint64
	streebogLPSX(h, n, &k)
	streebogLPSX(&k, m, &state)
	for i := 0; i < 11; i++ {
		var ci [8]uint64 = streebogC[i]
		streebogLPSX(&k, &ci, &k)
		streebogLPSX(&k, &state, &state)
	}
	var c11 [8]uint64 = streebogC[11]
	streebogLPSX(&k, &c11, &k)
	for i := 0; i < 8; i++ {
		state[i] ^= k[i]
		state[i] ^= h[i]
		h[i] = state[i] ^ m[i]
	}
}

// add512 adds x into sum as little-endian 512-bit integers.
func streebogAdd512(sum, x *[8]uint64) {
	var carry uint64
	for i := 0; i < 8; i++ {
		old := sum[i]
		sum[i] = old + x[i] + carry
		if sum[i] < old || (carry == 1 && sum[i] == old) {
			carry = 1
		} else {
			carry = 0
		}
	}
}

func loadBlockLE(b []byte) [8]uint64 {
	var m [8]uint64
	for i := 0; i < 8; i++ {
		var v uint64
		for j := 0; j < 8; j++ {
			v |= uint64(b[i*8+j]) << (uint(j) * 8)
		}
		m[i] = v
	}
	return m
}

func (d *streebogDigest) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		c := copy(d.buf[d.nx:], p)
		d.nx += c
		p = p[c:]
		if d.nx == 64 {
			m := loadBlockLE(d.buf[:])
			streebogGN(&d.n, &d.h, &m)
			block512 := [8]uint64{512}
			streebogAdd512(&d.n, &block512)
			streebogAdd512(&d.s, &m)
			d.nx = 0
		}
	}
	return n, nil
}

func (d *streebogDigest) Sum(in []byte) []byte {
	e := *d // copy

	// Pad the final (partial) block: 0x01 right after the data, rest zero.
	var block [64]byte
	copy(block[:], e.buf[:e.nx])
	block[e.nx] = 0x01
	m := loadBlockLE(block[:])

	bitLen := [8]uint64{uint64(e.nx) * 8}
	streebogGN(&e.n, &e.h, &m)
	streebogAdd512(&e.n, &bitLen)
	streebogAdd512(&e.s, &m)
	var zero [8]uint64
	streebogGN(&zero, &e.h, &e.n)
	streebogGN(&zero, &e.h, &e.s)

	// The digest is the top `size` bytes of h in big-endian (standard) order:
	// output word h[7] down to h[8-size/8], each big-endian.
	out := make([]byte, e.size)
	start := 8 - e.size/8
	pos := 0
	for i := 7; i >= start; i-- {
		v := e.h[i]
		for j := 7; j >= 0; j-- {
			out[pos] = byte(v >> (uint(j) * 8))
			pos++
		}
	}
	return append(in, out...)
}

// HMAC-Streebog is defined over the little-endian byte string returned by the
// GOST primitive. Hashsmith displays raw Streebog digests in the conventional
// big-endian order, so the inner digest must be reversed before the outer hash.
func hmacStreebogHex(newHash func() hash.Hash, key, message string) string {
	const blockSize = 64
	k := []byte(key)
	if len(k) > blockSize {
		h := newHash()
		_, _ = h.Write(k)
		k = h.Sum(nil)
		reverseBytes(k)
	}
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		var b byte
		if i < len(k) {
			b = k[i]
		}
		ipad[i] = b ^ 0x36
		opad[i] = b ^ 0x5c
	}
	inner := newHash()
	_, _ = inner.Write(ipad)
	_, _ = inner.Write([]byte(message))
	innerRaw := inner.Sum(nil)
	reverseBytes(innerRaw)
	outer := newHash()
	_, _ = outer.Write(opad)
	_, _ = outer.Write(innerRaw)
	return hex.EncodeToString(outer.Sum(nil))
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
