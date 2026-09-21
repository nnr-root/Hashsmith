package main

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// pbkdf2Range derives the PBKDF2 output blocks numbered [from, to) and returns
// them concatenated, where block 1 is the first hLen bytes of the key.
//
// PBKDF2 defines DK = T_1 || T_2 || ... and T_i = F(P, S, c, i), where F
// depends on the block index and on nothing else in the output (RFC 8018 §5.2).
// The blocks are therefore independent, and a longer derivation is a strict
// extension of a shorter one: the first 64 bytes of a 192-byte key are exactly
// the 64-byte key.
//
// VeraCrypt has a use for that. A header may be single-cipher (64 bytes of key)
// or a two- or three-cipher cascade (192 bytes), and the single-cipher case is
// far more common, so it is worth testing first. Deriving 64 bytes and then
// separately deriving 192 does the first four blocks twice — and when cracking,
// every candidate but the last one takes exactly that path. Extending instead
// costs ten RIPEMD-160 blocks per candidate where deriving twice costs
// fourteen, with no loss on the single-cipher hit, which still stops after four.
//
// x/crypto/pbkdf2 cannot express this: its API derives a prefix from block 1
// every time. The loop below is that package's, restricted to a block range.
func pbkdf2Range(password, salt []byte, iter, from, to int, newHash func() hash.Hash) []byte {
	prf := hmac.New(newHash, password)
	hLen := prf.Size()
	out := make([]byte, 0, (to-from)*hLen)

	var buf [4]byte
	dk := make([]byte, 0, hLen)
	u := make([]byte, hLen)
	for block := from; block < to; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		dk = prf.Sum(dk[:0])
		copy(u, dk)

		for n := 1; n < iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range dk {
				dk[i] ^= u[i]
			}
		}
		out = append(out, dk...)
	}
	return out
}

// pbkdf2BlocksFor reports how many output blocks a dkLen-byte key spans for a
// PRF of the given hash.
func pbkdf2BlocksFor(dkLen int, newHash func() hash.Hash) int {
	hLen := newHash().Size()
	return (dkLen + hLen - 1) / hLen
}
