package smith

// MD6, Rivest's SHA-3 candidate — Hashcat 34600 uses the 256-bit variant.
//
// MD6's compression function is unusual: no Feistel network, no S-boxes, just
// a shift register 89 words long fed by a recurrence with two AND terms. Each
// step reads five earlier words at fixed taps, mixes in a round constant, and
// writes one new word. 104 rounds of 16 steps produce 1664 new words, and the
// last sixteen are the output. That is why the working array is 1753 words:
// the algorithm never overwrites, it only extends.
//
// The mode of operation is a tree. Each 512-byte block is compressed
// independently, the 128-byte results are concatenated, and the level repeats
// until one block remains — that last compression is marked final (z = 1) and
// its trailing bytes are the digest. For any password this is a single block
// and the tree never forms, but the tree is implemented here because MD6 is
// also offered as a general hash, and a hash that is only correct for short
// inputs is a trap rather than a feature.
//
// Verified against two independent vectors: MD6-256("hashcat"), which is
// hashcat's published example for mode 34600, and MD6-256(""), which matches
// Rivest's reference implementation.

import (
	"encoding/binary"
	"errors"
)

const (
	md6Words      = 89 // compression input size, in words
	md6Chunk      = 16 // compression output size, in words
	md6DataWords  = 64 // data words per compression block
	md6KeyWords   = 8  // key words per block; Hashsmith always uses an empty key
	md6BlockBytes = md6DataWords * 8
	md6Rounds256  = 104 // 40 + d/4 for d = 256 with no key
	md6DigestBits = 256
	md6TreeHeight = 64 // L: large enough that MD6 is fully hierarchical
	md6MaxLevels  = 64
	md6S0         = 0x0123456789abcdef
	md6SMask      = 0x7311c2812425cfa0
)

// md6Q is the fractional-part constant Q from the MD6 specification.
var md6Q = [15]uint64{
	0x7311c2812425cfa0, 0x6432286434aac8e7, 0xb60450e9ef68b7c1, 0xe8fb23908d9f06f1,
	0xdd2e76cba691e5bf, 0x0cd0d63b2c30bc41, 0x1f8ccf6823058f8a, 0x54e5ed5b88e3775d,
	0x4ad12aae0a6d6031, 0x3e7f16bb88222e0d, 0x8af8671d3fb50c2c, 0x995ad1178bd25c31,
	0xc878c1dd04c4b633, 0x3b72066c7a1552ac, 0x0d6f3522631effcb,
}

// The per-step shift amounts, right then left.
var (
	md6RightShift = [16]uint{10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12}
	md6LeftShift  = [16]uint{11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9}
)

// md6Compress runs one compression. block is exactly md6DataWords words;
// level, index, padBits and final describe where the block sits in the tree.
func md6Compress(block []uint64, level, index uint64, padBits uint64, final bool) []uint64 {
	rounds := md6Rounds256
	a := make([]uint64, md6Words+rounds*md6Chunk)
	copy(a[0:15], md6Q[:])
	// a[15:23] is the key, left zero.
	a[23] = level<<56 | index
	z := uint64(0)
	if final {
		z = 1
	}
	a[24] = uint64(rounds)<<48 |
		uint64(md6TreeHeight)<<40 |
		z<<36 |
		padBits<<20 |
		md6DigestBits
	copy(a[25:25+md6DataWords], block)

	s := uint64(md6S0)
	i := md6Words
	for j := 0; j < rounds*md6Chunk; j += md6Chunk {
		for step := 0; step < md6Chunk; step++ {
			n := i + step
			x := s
			x ^= a[n-89] // end-around feedback
			x ^= a[n-17] // linear feedback
			x ^= a[n-18] & a[n-21]
			x ^= a[n-31] & a[n-67]
			x ^= x >> md6RightShift[step]
			a[n] = x ^ (x << md6LeftShift[step])
		}
		s = (s << 1) ^ (s >> 63) ^ (s & md6SMask)
		i += md6Chunk
	}
	return a[len(a)-md6Chunk:]
}

// md6Sum256 hashes a message of any length.
func md6Sum256(msg []byte) ([]byte, error) {
	data := msg
	for level := uint64(1); ; level++ {
		if level > md6MaxLevels {
			// Unreachable for any input that fits in memory: each level
			// divides the length by four.
			return nil, errors.New("MD6 tree exceeded its maximum height")
		}
		blocks := (len(data) + md6BlockBytes - 1) / md6BlockBytes
		if blocks == 0 {
			blocks = 1 // The empty message is still one (all-zero) block.
		}
		final := blocks == 1

		padded := make([]byte, blocks*md6BlockBytes)
		copy(padded, data)

		out := make([]byte, 0, blocks*md6Chunk*8)
		words := make([]uint64, md6DataWords)
		for b := 0; b < blocks; b++ {
			chunk := padded[b*md6BlockBytes : (b+1)*md6BlockBytes]
			for w := 0; w < md6DataWords; w++ {
				words[w] = binary.BigEndian.Uint64(chunk[w*8:])
			}
			// Only the final block of a level can carry padding.
			padBits := uint64(0)
			if b == blocks-1 {
				padBits = uint64(len(padded)-len(data)) * 8
			}
			res := md6Compress(words, level, uint64(b), padBits, final)
			for _, v := range res {
				var tmp [8]byte
				binary.BigEndian.PutUint64(tmp[:], v)
				out = append(out, tmp[:]...)
			}
		}
		if final {
			// The digest is the trailing d bits of the last compression.
			return out[len(out)-md6DigestBits/8:], nil
		}
		data = out
	}
}
