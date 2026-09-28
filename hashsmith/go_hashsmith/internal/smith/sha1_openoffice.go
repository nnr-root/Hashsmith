package smith

// OpenOffice's own SHA-1, which is wrong, and the files that carry its output.
//
// Its padding unconditionally fills to sixty bytes into the block and, when
// the message ends 52 to 55 bytes into one, adds a WHOLE EXTRA BLOCK of zeros
// before the length — where the specification would have fitted the padding
// into the space already there. It also writes a thirty-two-bit length where
// the specification writes sixty-four, which changes nothing for any real
// message.
//
// For every other length the two agree exactly, which is why the bug went
// unnoticed: it shows on one message length in sixteen. A document written by
// an affected version stores the buggy digest, so a reader that computes only
// the correct one fails on those files and on no others.

import "encoding/binary"

// ── OpenOffice's SHA-1 ────────────────────────────────────────────────────────

// sha1OpenOfficeBuggy is SHA-1 with OpenOffice's padding: fill to sixty bytes
// into the block, add a whole further block when the message ended 52 to 55
// bytes in, then a THIRTY-TWO-bit length where the specification writes
// sixty-four.
//
// The compression function is written out here rather than borrowed because
// no standard library exposes one — the padding is the only thing that
// differs, and it happens after the last place a Hash interface lets anything
// in.
func sha1OpenOfficeBuggy(data []byte) []byte {
	msg := make([]byte, 0, len(data)+140)
	msg = append(msg, data...)

	i := len(data) & 63
	pad := func(n int) {
		msg = append(msg, make([]byte, n)...)
	}
	if i < 56 {
		msg = append(msg, 0x80)
		pad(60 - i - 1)
		if i>>2 == 13 {
			pad(64)
		}
	} else {
		msg = append(msg, 0x80)
		pad(64 - i - 1)
		pad(60)
	}
	var bits [4]byte
	binary.BigEndian.PutUint32(bits[:], uint32(len(data))*8)
	msg = append(msg, bits[:]...)

	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	for off := 0; off+64 <= len(msg); off += 64 {
		sha1Compress(&h, msg[off:off+64])
	}
	out := make([]byte, 20)
	for k, v := range h {
		binary.BigEndian.PutUint32(out[4*k:], v)
	}
	return out
}

// sha1Compress is one block of SHA-1, straight from FIPS 180.
func sha1Compress(h *[5]uint32, block []byte) {
	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[4*i:])
	}
	for i := 16; i < 80; i++ {
		v := w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		w[i] = v<<1 | v>>31
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
		t := (a<<5 | a>>27) + f + e + k + w[i]
		e, d, c, b, a = d, c, b<<30|b>>2, a, t
	}
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
	h[4] += e
}
