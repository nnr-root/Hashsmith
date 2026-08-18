package main

// Serpent block cipher (128-bit block, 128/192/256-bit keys) — one of the AES
// finalists, used as a cipher option in VeraCrypt/TrueCrypt and LUKS volumes.
// Bitslice implementation; validated end-to-end against real Serpent LUKS images
// (and standard ECB test vectors) in the tests.

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/bits"
)

const serpentPhi = 0x9e3779b9

type serpentCipher struct {
	k [33][4]uint32
}

// newSerpentCipher returns a Serpent cipher.Block for a 16/24/32-byte key.
func newSerpentCipher(key []byte) (cipher.Block, error) {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, errors.New("serpent: invalid key size")
	}
	c := &serpentCipher{}
	c.expandKey(key)
	return c, nil
}

func (c *serpentCipher) BlockSize() int { return 16 }

func (c *serpentCipher) expandKey(key []byte) {
	// Pad to 256 bits: append a 1 bit then zeros.
	var padded [32]byte
	copy(padded[:], key)
	if len(key) < 32 {
		padded[len(key)] = 0x01
	}
	var w [140]uint32
	for i := 0; i < 8; i++ {
		w[i] = binary.LittleEndian.Uint32(padded[i*4:])
	}
	// Prekey expansion (indices offset by 8: w[8..139] hold the real prekeys).
	for i := 8; i < 140; i++ {
		w[i] = bits.RotateLeft32(w[i-8]^w[i-5]^w[i-3]^w[i-1]^serpentPhi^uint32(i-8), 11)
	}
	// Derive the 33 round keys by applying S-boxes to prekey groups.
	for i := 0; i <= 32; i++ {
		a := w[8+4*i]
		b := w[8+4*i+1]
		cc := w[8+4*i+2]
		d := w[8+4*i+3]
		serpentKeySBox((32+3-i)%8, &a, &b, &cc, &d)
		c.k[i] = [4]uint32{a, b, cc, d}
	}
}

func (c *serpentCipher) Encrypt(dst, src []byte) {
	x0 := binary.LittleEndian.Uint32(src[0:])
	x1 := binary.LittleEndian.Uint32(src[4:])
	x2 := binary.LittleEndian.Uint32(src[8:])
	x3 := binary.LittleEndian.Uint32(src[12:])

	for i := 0; i < 31; i++ {
		x0 ^= c.k[i][0]
		x1 ^= c.k[i][1]
		x2 ^= c.k[i][2]
		x3 ^= c.k[i][3]
		serpentSBox(i%8, &x0, &x1, &x2, &x3)
		serpentLT(&x0, &x1, &x2, &x3)
	}
	x0 ^= c.k[31][0]
	x1 ^= c.k[31][1]
	x2 ^= c.k[31][2]
	x3 ^= c.k[31][3]
	serpentSBox(7, &x0, &x1, &x2, &x3)
	x0 ^= c.k[32][0]
	x1 ^= c.k[32][1]
	x2 ^= c.k[32][2]
	x3 ^= c.k[32][3]

	binary.LittleEndian.PutUint32(dst[0:], x0)
	binary.LittleEndian.PutUint32(dst[4:], x1)
	binary.LittleEndian.PutUint32(dst[8:], x2)
	binary.LittleEndian.PutUint32(dst[12:], x3)
}

func (c *serpentCipher) Decrypt(dst, src []byte) {
	x0 := binary.LittleEndian.Uint32(src[0:])
	x1 := binary.LittleEndian.Uint32(src[4:])
	x2 := binary.LittleEndian.Uint32(src[8:])
	x3 := binary.LittleEndian.Uint32(src[12:])

	x0 ^= c.k[32][0]
	x1 ^= c.k[32][1]
	x2 ^= c.k[32][2]
	x3 ^= c.k[32][3]
	serpentSBoxInv(7, &x0, &x1, &x2, &x3)
	x0 ^= c.k[31][0]
	x1 ^= c.k[31][1]
	x2 ^= c.k[31][2]
	x3 ^= c.k[31][3]

	for i := 30; i >= 0; i-- {
		serpentLTInv(&x0, &x1, &x2, &x3)
		serpentSBoxInv(i%8, &x0, &x1, &x2, &x3)
		x0 ^= c.k[i][0]
		x1 ^= c.k[i][1]
		x2 ^= c.k[i][2]
		x3 ^= c.k[i][3]
	}

	binary.LittleEndian.PutUint32(dst[0:], x0)
	binary.LittleEndian.PutUint32(dst[4:], x1)
	binary.LittleEndian.PutUint32(dst[8:], x2)
	binary.LittleEndian.PutUint32(dst[12:], x3)
}

// serpentLT is the Serpent linear transformation.
func serpentLT(x0, x1, x2, x3 *uint32) {
	*x0 = bits.RotateLeft32(*x0, 13)
	*x2 = bits.RotateLeft32(*x2, 3)
	*x1 ^= *x0 ^ *x2
	*x3 ^= *x2 ^ (*x0 << 3)
	*x1 = bits.RotateLeft32(*x1, 1)
	*x3 = bits.RotateLeft32(*x3, 7)
	*x0 ^= *x1 ^ *x3
	*x2 ^= *x3 ^ (*x1 << 7)
	*x0 = bits.RotateLeft32(*x0, 5)
	*x2 = bits.RotateLeft32(*x2, 22)
}

// serpentLTInv is the inverse linear transformation.
func serpentLTInv(x0, x1, x2, x3 *uint32) {
	*x2 = bits.RotateLeft32(*x2, 32-22)
	*x0 = bits.RotateLeft32(*x0, 32-5)
	*x2 ^= *x3 ^ (*x1 << 7)
	*x0 ^= *x1 ^ *x3
	*x3 = bits.RotateLeft32(*x3, 32-7)
	*x1 = bits.RotateLeft32(*x1, 32-1)
	*x3 ^= *x2 ^ (*x0 << 3)
	*x1 ^= *x0 ^ *x2
	*x2 = bits.RotateLeft32(*x2, 32-3)
	*x0 = bits.RotateLeft32(*x0, 32-13)
}

// serpentKeySBox applies S-box `n` in place during the key schedule.
func serpentKeySBox(n int, a, b, c, d *uint32) {
	serpentSBox(n, a, b, c, d)
}
