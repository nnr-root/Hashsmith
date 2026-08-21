package main

// Legacy and regional raw hashes that are useful in password-audit imports but
// are not provided by Go's standard hash packages.

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
)

var md2Substitution = [256]byte{
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
	98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
	30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
	190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
	169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
	128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
	255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
	79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
	69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
	27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
	44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
	106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
	120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
	242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
	49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
}

func md2Hex(data []byte) string {
	padLen := 16 - len(data)%16
	msg := make([]byte, len(data)+padLen+16)
	copy(msg, data)
	for i := len(data); i < len(data)+padLen; i++ {
		msg[i] = byte(padLen)
	}

	var checksum [16]byte
	var last byte
	for off := 0; off < len(data)+padLen; off += 16 {
		for i := 0; i < 16; i++ {
			checksum[i] ^= md2Substitution[msg[off+i]^last]
			last = checksum[i]
		}
	}
	copy(msg[len(data)+padLen:], checksum[:])

	var state [48]byte
	for off := 0; off < len(msg); off += 16 {
		for i := 0; i < 16; i++ {
			state[16+i] = msg[off+i]
			state[32+i] = state[16+i] ^ state[i]
		}
		var t byte
		for round := 0; round < 18; round++ {
			for i := 0; i < 48; i++ {
				state[i] ^= md2Substitution[t]
				t = state[i]
			}
			t += byte(round)
		}
	}
	return hex.EncodeToString(state[:16])
}

func padHashBlocks(data []byte) []byte {
	bitLen := uint64(len(data)) * 8
	paddedLen := ((len(data) + 9 + 63) / 64) * 64
	msg := make([]byte, paddedLen)
	copy(msg, data)
	msg[len(data)] = 0x80
	binary.BigEndian.PutUint64(msg[len(msg)-8:], bitLen)
	return msg
}

func sha0Hex(data []byte) string {
	h := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	msg := padHashBlocks(data)
	for off := 0; off < len(msg); off += 64 {
		var w [80]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[off+i*4:])
		}
		for i := 16; i < 80; i++ {
			w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
		}
		a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
		for i := 0; i < 80; i++ {
			var f, k uint32
			switch {
			case i < 20:
				f, k = (b&c)|(^b&d), 0x5a827999
			case i < 40:
				f, k = b^c^d, 0x6ed9eba1
			case i < 60:
				f, k = (b&c)|(b&d)|(c&d), 0x8f1bbcdc
			default:
				f, k = b^c^d, 0xca62c1d6
			}
			temp := bits.RotateLeft32(a, 5) + f + e + k + w[i]
			e, d, c, b, a = d, c, bits.RotateLeft32(b, 30), a, temp
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}
	out := make([]byte, 20)
	for i, word := range h {
		binary.BigEndian.PutUint32(out[i*4:], word)
	}
	return hex.EncodeToString(out)
}

func sm3P0(x uint32) uint32 { return x ^ bits.RotateLeft32(x, 9) ^ bits.RotateLeft32(x, 17) }
func sm3P1(x uint32) uint32 { return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23) }

func sm3Hex(data []byte) string {
	v := [8]uint32{0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e}
	msg := padHashBlocks(data)
	for off := 0; off < len(msg); off += 64 {
		var w [68]uint32
		var wp [64]uint32
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[off+i*4:])
		}
		for i := 16; i < 68; i++ {
			w[i] = sm3P1(w[i-16]^w[i-9]^bits.RotateLeft32(w[i-3], 15)) ^
				bits.RotateLeft32(w[i-13], 7) ^ w[i-6]
		}
		for i := 0; i < 64; i++ {
			wp[i] = w[i] ^ w[i+4]
		}

		a, b, c, d := v[0], v[1], v[2], v[3]
		e, f, g, h := v[4], v[5], v[6], v[7]
		for i := 0; i < 64; i++ {
			t := uint32(0x79cc4519)
			if i >= 16 {
				t = 0x7a879d8a
			}
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(t, i%32), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			var ff, gg uint32
			if i < 16 {
				ff = a ^ b ^ c
				gg = e ^ f ^ g
			} else {
				ff = (a & b) | (a & c) | (b & c)
				gg = (e & f) | (^e & g)
			}
			tt1 := ff + d + ss2 + wp[i]
			tt2 := gg + h + ss1 + w[i]
			d, c, b, a = c, bits.RotateLeft32(b, 9), a, tt1
			h, g, f, e = g, bits.RotateLeft32(f, 19), e, sm3P0(tt2)
		}
		v[0] ^= a
		v[1] ^= b
		v[2] ^= c
		v[3] ^= d
		v[4] ^= e
		v[5] ^= f
		v[6] ^= g
		v[7] ^= h
	}
	out := make([]byte, 32)
	for i, word := range v {
		binary.BigEndian.PutUint32(out[i*4:], word)
	}
	return hex.EncodeToString(out)
}

func xxhash32(data []byte) uint32 {
	const p1, p2, p3, p4, p5 uint32 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
	round := func(acc, input uint32) uint32 {
		return bits.RotateLeft32(acc+input*p2, 13) * p1
	}
	var h uint32
	i := 0
	if len(data) >= 16 {
		v1, v2, v3, v4 := p1, p2, uint32(0), uint32(0)
		v1 += p2
		v4 -= p1
		for i <= len(data)-16 {
			v1 = round(v1, binary.LittleEndian.Uint32(data[i:]))
			v2 = round(v2, binary.LittleEndian.Uint32(data[i+4:]))
			v3 = round(v3, binary.LittleEndian.Uint32(data[i+8:]))
			v4 = round(v4, binary.LittleEndian.Uint32(data[i+12:]))
			i += 16
		}
		h = bits.RotateLeft32(v1, 1) + bits.RotateLeft32(v2, 7) + bits.RotateLeft32(v3, 12) + bits.RotateLeft32(v4, 18)
	} else {
		h = p5
	}
	h += uint32(len(data))
	for i <= len(data)-4 {
		h = bits.RotateLeft32(h+binary.LittleEndian.Uint32(data[i:])*p3, 17) * p4
		i += 4
	}
	for i < len(data) {
		h = bits.RotateLeft32(h+uint32(data[i])*p5, 11) * p1
		i++
	}
	h ^= h >> 15
	h *= p2
	h ^= h >> 13
	h *= p3
	h ^= h >> 16
	return h
}

func xxhash64(data []byte) uint64 {
	const p1, p2, p3, p4, p5 uint64 = 11400714785074694791, 14029467366897019727, 1609587929392839161, 9650029242287828579, 2870177450012600261
	round := func(acc, input uint64) uint64 {
		return bits.RotateLeft64(acc+input*p2, 31) * p1
	}
	merge := func(acc, value uint64) uint64 {
		return (acc^round(0, value))*p1 + p4
	}
	var h uint64
	i := 0
	if len(data) >= 32 {
		v1, v2, v3, v4 := p1, p2, uint64(0), uint64(0)
		v1 += p2
		v4 -= p1
		for i <= len(data)-32 {
			v1 = round(v1, binary.LittleEndian.Uint64(data[i:]))
			v2 = round(v2, binary.LittleEndian.Uint64(data[i+8:]))
			v3 = round(v3, binary.LittleEndian.Uint64(data[i+16:]))
			v4 = round(v4, binary.LittleEndian.Uint64(data[i+24:]))
			i += 32
		}
		h = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) + bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		h = merge(merge(merge(merge(h, v1), v2), v3), v4)
	} else {
		h = p5
	}
	h += uint64(len(data))
	for i <= len(data)-8 {
		k := round(0, binary.LittleEndian.Uint64(data[i:]))
		h = bits.RotateLeft64(h^k, 27)*p1 + p4
		i += 8
	}
	if i <= len(data)-4 {
		h = bits.RotateLeft64(h^uint64(binary.LittleEndian.Uint32(data[i:]))*p1, 23)*p2 + p3
		i += 4
	}
	for i < len(data) {
		h = bits.RotateLeft64(h^uint64(data[i])*p5, 11) * p1
		i++
	}
	h ^= h >> 33
	h *= p2
	h ^= h >> 29
	h *= p3
	h ^= h >> 32
	return h
}

func murmur3_32(data []byte) uint32 {
	const c1, c2 uint32 = 0xcc9e2d51, 0x1b873593
	var h uint32
	i := 0
	for i <= len(data)-4 {
		k := binary.LittleEndian.Uint32(data[i:])
		k = bits.RotateLeft32(k*c1, 15) * c2
		h ^= k
		h = bits.RotateLeft32(h, 13)*5 + 0xe6546b64
		i += 4
	}
	var tail uint32
	switch len(data) - i {
	case 3:
		tail ^= uint32(data[i+2]) << 16
		fallthrough
	case 2:
		tail ^= uint32(data[i+1]) << 8
		fallthrough
	case 1:
		tail ^= uint32(data[i])
		tail = bits.RotateLeft32(tail*c1, 15) * c2
		h ^= tail
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
