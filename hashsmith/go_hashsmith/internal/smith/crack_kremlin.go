package smith

// Kremlin Encrypt 3.0 with NewDES — Hashcat 32700.
//
//	$kgb$<8-byte salt>$<20-byte SHA-1>
//
// Kremlin derives a NewDES key from SHA-1 of the password, runs the file's
// eight-byte check value through 1000 NewDES encryptions, and stores SHA-1 of
// (check value || password). Verifying is the same work: there is no shortcut
// and no early exit, but 1000 NewDES blocks is cheap, so this is a fast format
// despite the iteration count.
//
// The SHA-1 here is not SHA-1. Kremlin lays the message out as little-endian
// 32-bit words and then runs the standard big-endian compression function over
// them, so every four-byte group is transposed — and, crucially, so are the
// 0x80 terminator and the length field. hashcat encodes this by passing `pos`
// where its own sha1_final passes `pos ^ 3`, and by byte-swapping the bit
// length. Reversing the message but appending the padding in natural order
// produces a digest that is wrong for every input, which is the shape of the
// bug worth naming: the transposition applies to the padded buffer, not to
// the message.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
	"strings"
)

const (
	kremlinPrefix    = "$kgb$"
	kremlinSaltLen   = 8
	kremlinDigestLen = 20
	kremlinRounds    = 1000
	kremlinKeyLen    = 60
)

// kremlinSHA1 is SHA-1 over a buffer whose four-byte groups — padding and
// length included — are laid out little-endian.
func kremlinSHA1(msg []byte) [kremlinDigestLen]byte {
	buf := append(append(make([]byte, 0, len(msg)+72), msg...), 0x80)
	for len(buf)%64 != 56 {
		buf = append(buf, 0)
	}
	for i := 0; i+4 <= len(buf); i += 4 {
		buf[i], buf[i+1], buf[i+2], buf[i+3] = buf[i+3], buf[i+2], buf[i+1], buf[i]
	}
	var tail [8]byte
	binary.LittleEndian.PutUint32(tail[4:], uint32(len(msg))*8)
	buf = append(buf, tail[:]...)

	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	var w [80]uint32
	for off := 0; off < len(buf); off += 64 {
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(buf[off+i*4:])
		}
		for i := 16; i < 80; i++ {
			w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}
		a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
		for i := 0; i < 80; i++ {
			var f, k uint32
			switch {
			case i < 20:
				f, k = (b&c)|(^b&d), 0x5A827999
			case i < 40:
				f, k = b^c^d, 0x6ED9EBA1
			case i < 60:
				f, k = (b&c)|(b&d)|(c&d), 0x8F1BBCDC
			default:
				f, k = b^c^d, 0xCA62C1D6
			}
			t := bits.RotateLeft32(a, 5) + f + e + k + w[i]
			e, d, c, b, a = d, c, bits.RotateLeft32(b, 30), a, t
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}
	var out [kremlinDigestLen]byte
	for i, v := range h {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return out
}

// kremlinExpandKey turns the first fifteen digest bytes into NewDES's sixty
// key bytes. Bytes 24, 29 and 34 of the result are always zero, because the
// expansion XORs each source byte with digest bytes 7, 8 and 9 and those
// collide with the source byte at three positions — a wart of the original
// design, not of this transcription.
func kremlinExpandKey(sum [kremlinDigestLen]byte) [kremlinKeyLen]byte {
	var key [kremlinKeyLen]byte
	for i := 0; i < 15; i++ {
		b := sum[i]
		key[i*4+0] = b
		key[i*4+1] = b ^ sum[7]
		key[i*4+2] = b ^ sum[8]
		key[i*4+3] = b ^ sum[9]
	}
	return key
}

// newDESEncrypt is Robert Scott's NewDES: eight rounds over an eight-byte
// block plus a four-byte final half-round, consuming sixty key bytes.
func newDESEncrypt(b *[kremlinSaltLen]byte, key *[kremlinKeyLen]byte) {
	k := 0
	next := func() byte { v := key[k]; k++; return v }
	for round := 0; round < 8; round++ {
		b[4] ^= kremlinRotor[b[0]^next()]
		b[5] ^= kremlinRotor[b[1]^next()]
		b[6] ^= kremlinRotor[b[2]^next()]
		b[7] ^= kremlinRotor[b[3]^next()]
		b[1] ^= kremlinRotor[b[4]^next()]
		b[2] ^= kremlinRotor[b[4]^b[5]] // consumes no key byte
		b[3] ^= kremlinRotor[b[6]^next()]
		b[0] ^= kremlinRotor[b[7]^next()]
	}
	b[4] ^= kremlinRotor[b[0]^next()]
	b[5] ^= kremlinRotor[b[1]^next()]
	b[6] ^= kremlinRotor[b[2]^next()]
	b[7] ^= kremlinRotor[b[3]^next()]
}

func verifyKremlin(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, kremlinPrefix) {
		return false, errors.New("not a Kremlin record")
	}
	p := strings.Split(strings.TrimPrefix(t, kremlinPrefix), "$")
	if len(p) != 2 {
		return false, errors.New("Kremlin record must be $kgb$<salt>$<digest>")
	}
	salt, err := hex.DecodeString(p[0])
	if err != nil || len(salt) != kremlinSaltLen {
		return false, errors.New("Kremlin salt must be 8 hex-encoded bytes")
	}
	want, err := hex.DecodeString(p[1])
	if err != nil || len(want) != kremlinDigestLen {
		return false, errors.New("Kremlin digest must be 20 hex-encoded bytes")
	}

	key := kremlinExpandKey(kremlinSHA1([]byte(candidate)))
	var block [kremlinSaltLen]byte
	copy(block[:], salt)
	for i := 0; i < kremlinRounds; i++ {
		newDESEncrypt(&block, &key)
	}
	got := kremlinSHA1(append(append(make([]byte, 0, kremlinSaltLen+len(candidate)), block[:]...), candidate...))
	return string(got[:]) == string(want), nil
}
