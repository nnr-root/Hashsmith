package main

// MDC-2, the hash you build out of a block cipher when you have no hash.
//
// ISO/IEC 10118-2 defines it over any block cipher; with DES, which is what
// everything that ships it uses, it produces 128 bits from two interleaved
// Davies-Meyer chains whose halves are swapped after every block. That swap
// is the whole construction: without it the two chains would be independent
// 64-bit hashes, and a collision in either would be a collision in the pair.
//
// The key bits are not decoration either. Each chain forces two bits of its
// key byte — 0x40 for one chain and 0x20 for the other — which is what keeps
// the two chains from ever meeting on the same key and collapsing into one.
//
// It is obsolete, slow and patented until 2002, so nothing new uses it. It
// appears here because John ships it and because a DES-based hash is a
// reasonable thing for this tool to be able to read.

import (
	"crypto/des"
	"encoding/hex"
)

// mdc2Sum returns the 16-byte MDC-2 digest of msg.
func mdc2Sum(msg []byte) []byte {
	h1 := []byte{0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52}
	h2 := []byte{0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25}

	// The message is padded with zeros to a whole number of blocks and its
	// length is not encoded, which is one of several reasons this is not a
	// hash to choose today.
	m := append([]byte(nil), msg...)
	for len(m)%des.BlockSize != 0 {
		m = append(m, 0)
	}

	t1 := make([]byte, des.BlockSize)
	t2 := make([]byte, des.BlockSize)
	for off := 0; off < len(m); off += des.BlockSize {
		block := m[off : off+des.BlockSize]

		k1 := append([]byte(nil), h1...)
		k1[0] = (k1[0] & 0x9f) | 0x40
		k2 := append([]byte(nil), h2...)
		k2[0] = (k2[0] & 0x9f) | 0x20

		c1, err := des.NewCipher(k1)
		if err != nil {
			return nil
		}
		c2, err := des.NewCipher(k2)
		if err != nil {
			return nil
		}
		c1.Encrypt(t1, block)
		c2.Encrypt(t2, block)
		for i := range block {
			t1[i] ^= block[i]
			t2[i] ^= block[i]
		}
		// The halves cross over: each chain keeps its own first half and
		// takes the other's second.
		h1 = append(append([]byte(nil), t1[:4]...), t2[4:]...)
		h2 = append(append([]byte(nil), t2[:4]...), t1[4:]...)
	}
	return append(h1, h2...)
}

// mdc2Hex returns the digest as lower-case hex.
func mdc2Hex(msg []byte) string { return hex.EncodeToString(mdc2Sum(msg)) }
