package main

// Streebog (GOST R 34.11-2012), 256- and 512-bit — a KDF option in some
// VeraCrypt volumes. The L∘P∘S transform is applied through the precomputed
// streebogTR table (see streebog_tables.go); the compression g_N follows the
// standard. Pinned to the GOST test vectors in the tests.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
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

// newStreebog512Native returns the byte order used internally by VeraCrypt's
// HMAC/PBKDF2 construction. The public Streebog hash emits the conventional
// big-endian display form; VeraCrypt feeds the primitive's little-endian byte
// string into the next HMAC round instead.
func newStreebog512Native() hash.Hash {
	return &streebogNativeDigest{Hash: newStreebog512()}
}

type streebogNativeDigest struct {
	hash.Hash
}

func (d *streebogNativeDigest) Sum(in []byte) []byte {
	out := d.Hash.Sum(nil)
	reverseBytes(out)
	return append(in, out...)
}

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
//
// The XOR operands are held in locals rather than an array so the compiler can
// keep all eight in registers across the output loop; each is read eight times,
// once per output word, and an array forces a reload every time. The eight
// table rows are likewise hoisted into slice-typed locals, which turns
// streebogTR[j][k] from a two-level index with two bounds checks into one.
// Together these are worth about a fifth of the time in the compression
// function, which is the whole cost of PBKDF2-HMAC-Streebog.
func streebogLPSX(a, b *[8]uint64, result *[8]uint64) {
	r0 := a[0] ^ b[0]
	r1 := a[1] ^ b[1]
	r2 := a[2] ^ b[2]
	r3 := a[3] ^ b[3]
	r4 := a[4] ^ b[4]
	r5 := a[5] ^ b[5]
	r6 := a[6] ^ b[6]
	r7 := a[7] ^ b[7]

	t0 := &streebogTR[0]
	t1 := &streebogTR[1]
	t2 := &streebogTR[2]
	t3 := &streebogTR[3]
	t4 := &streebogTR[4]
	t5 := &streebogTR[5]
	t6 := &streebogTR[6]
	t7 := &streebogTR[7]

	// Fully unrolled: the byte offset is a constant in each line, so the
	// shift folds into the addressing and the loop counter disappears.
	result[0] = t0[(r0)&0xff] ^
		t1[(r1)&0xff] ^
		t2[(r2)&0xff] ^
		t3[(r3)&0xff] ^
		t4[(r4)&0xff] ^
		t5[(r5)&0xff] ^
		t6[(r6)&0xff] ^
		t7[(r7)&0xff]
	result[1] = t0[(r0>>8)&0xff] ^
		t1[(r1>>8)&0xff] ^
		t2[(r2>>8)&0xff] ^
		t3[(r3>>8)&0xff] ^
		t4[(r4>>8)&0xff] ^
		t5[(r5>>8)&0xff] ^
		t6[(r6>>8)&0xff] ^
		t7[(r7>>8)&0xff]
	result[2] = t0[(r0>>16)&0xff] ^
		t1[(r1>>16)&0xff] ^
		t2[(r2>>16)&0xff] ^
		t3[(r3>>16)&0xff] ^
		t4[(r4>>16)&0xff] ^
		t5[(r5>>16)&0xff] ^
		t6[(r6>>16)&0xff] ^
		t7[(r7>>16)&0xff]
	result[3] = t0[(r0>>24)&0xff] ^
		t1[(r1>>24)&0xff] ^
		t2[(r2>>24)&0xff] ^
		t3[(r3>>24)&0xff] ^
		t4[(r4>>24)&0xff] ^
		t5[(r5>>24)&0xff] ^
		t6[(r6>>24)&0xff] ^
		t7[(r7>>24)&0xff]
	result[4] = t0[(r0>>32)&0xff] ^
		t1[(r1>>32)&0xff] ^
		t2[(r2>>32)&0xff] ^
		t3[(r3>>32)&0xff] ^
		t4[(r4>>32)&0xff] ^
		t5[(r5>>32)&0xff] ^
		t6[(r6>>32)&0xff] ^
		t7[(r7>>32)&0xff]
	result[5] = t0[(r0>>40)&0xff] ^
		t1[(r1>>40)&0xff] ^
		t2[(r2>>40)&0xff] ^
		t3[(r3>>40)&0xff] ^
		t4[(r4>>40)&0xff] ^
		t5[(r5>>40)&0xff] ^
		t6[(r6>>40)&0xff] ^
		t7[(r7>>40)&0xff]
	result[6] = t0[(r0>>48)&0xff] ^
		t1[(r1>>48)&0xff] ^
		t2[(r2>>48)&0xff] ^
		t3[(r3>>48)&0xff] ^
		t4[(r4>>48)&0xff] ^
		t5[(r5>>48)&0xff] ^
		t6[(r6>>48)&0xff] ^
		t7[(r7>>48)&0xff]
	result[7] = t0[(r0>>56)&0xff] ^
		t1[(r1>>56)&0xff] ^
		t2[(r2>>56)&0xff] ^
		t3[(r3>>56)&0xff] ^
		t4[(r4>>56)&0xff] ^
		t5[(r5>>56)&0xff] ^
		t6[(r6>>56)&0xff] ^
		t7[(r7>>56)&0xff]
}

// gN is the compression g_N(h, m) = E(LPS(h⊕N), m) ⊕ h ⊕ m.
func streebogGN(n, h, m *[8]uint64) {
	var k, state [8]uint64
	streebogLPSX(h, n, &k)
	streebogLPSX(&k, m, &state)
	// The round constants are taken by pointer; copying each 64-byte constant
	// into a local, as this used to, cost twelve array copies per compression
	// for nothing.
	for i := 0; i < 11; i++ {
		streebogLPSX(&k, &streebogC[i], &k)
		streebogLPSX(&k, &state, &state)
	}
	streebogLPSX(&k, &streebogC[11], &k)
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

// streebogMarshalMagic tags a serialised digest. The trailing size byte keeps
// a 256-bit state from being restored into a 512-bit digest, whose only other
// difference is the initial h.
const streebogMarshalMagic = "hashsmith\x01streebog\x01"

// MarshalBinary, AppendBinary and UnmarshalBinary exist for crypto/hmac, which
// caches a key's inner and outer states only when the hash can serialise
// itself and otherwise re-compresses the ipad and opad blocks on every
// message. VeraCrypt's Streebog-512 KDF is 500,000 PBKDF2 iterations per
// derived block. See the same methods on ripemdDigest for the measurement.
func (d *streebogDigest) MarshalBinary() ([]byte, error) {
	return d.AppendBinary(make([]byte, 0, len(streebogMarshalMagic)+1+3*64+64+1))
}

func (d *streebogDigest) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, streebogMarshalMagic...)
	b = append(b, byte(d.size))
	for _, w := range [][8]uint64{d.h, d.n, d.s} {
		for _, v := range w {
			b = binary.BigEndian.AppendUint64(b, v)
		}
	}
	b = append(b, d.buf[:]...)
	return append(b, byte(d.nx)), nil
}

func (d *streebogDigest) UnmarshalBinary(b []byte) error {
	if len(b) < len(streebogMarshalMagic)+1 || string(b[:len(streebogMarshalMagic)]) != streebogMarshalMagic {
		return errors.New("streebog: invalid hash state identifier")
	}
	b = b[len(streebogMarshalMagic):]
	if int(b[0]) != d.size {
		return errors.New("streebog: hash state is for a different digest size")
	}
	b = b[1:]
	if len(b) != 3*64+64+1 {
		return errors.New("streebog: invalid hash state size")
	}
	for i, w := range []*[8]uint64{&d.h, &d.n, &d.s} {
		for j := range w {
			w[j] = binary.BigEndian.Uint64(b[i*64+j*8:])
		}
	}
	b = b[3*64:]
	copy(d.buf[:], b[:64])
	d.nx = int(b[64])
	if d.nx >= 64 {
		return errors.New("streebog: invalid buffered length in hash state")
	}
	return nil
}

// streebogNativeDigest embeds hash.Hash, an interface, so the marshaler above
// is NOT promoted through it — and crypto/hmac asks the outermost value. These
// forwarders are what actually puts VeraCrypt's Streebog KDF on the fast path;
// without them the methods exist and are never reached.
func (d *streebogNativeDigest) MarshalBinary() ([]byte, error) {
	return d.Hash.(*streebogDigest).MarshalBinary()
}

func (d *streebogNativeDigest) AppendBinary(b []byte) ([]byte, error) {
	return d.Hash.(*streebogDigest).AppendBinary(b)
}

func (d *streebogNativeDigest) UnmarshalBinary(b []byte) error {
	return d.Hash.(*streebogDigest).UnmarshalBinary(b)
}
