package smith

// The DES core shared by the RACF family (Hashcat 8500, 8501).
//
// This is DES with the initial and final permutations removed. RACF feeds the
// EBCDIC profile name straight into the Feistel network and reads the two
// halves straight out again, so the result is not interchangeable with a
// standard DES block — crypto/des cannot stand in for it without conjugating
// the input and output by IP and FP, which costs more care than porting the
// sixteen rounds outright.
//
// The key schedule is the libdes one, kept in hashcat's Kc/Kd packing so the
// round function can index desSPtrans directly.

import "encoding/binary"

func desPermOp(a, b uint32, n uint, m uint32) (uint32, uint32) {
	t := ((a >> n) ^ b) & m
	return a ^ (t << n), b ^ t
}

func desHPermOp(a uint32, n uint, m uint32) uint32 {
	t := ((a << (16 + n)) ^ a) & m
	a ^= t
	return a ^ (t >> (16 + n))
}

// desKeySetup expands the two key words into the sixteen round-key pairs.
func desKeySetup(c, d uint32) (kc, kd [16]uint32) {
	d, c = desPermOp(d, c, 4, 0x0f0f0f0f)
	c = desHPermOp(c, 2, 0xcccc0000)
	d = desHPermOp(d, 2, 0xcccc0000)
	d, c = desPermOp(d, c, 1, 0x55555555)
	c, d = desPermOp(c, d, 8, 0x00ff00ff)
	d, c = desPermOp(d, c, 1, 0x55555555)

	d = ((d & 0x000000ff) << 16) |
		(d & 0x0000ff00) |
		((d & 0x00ff0000) >> 16) |
		((c & 0xf0000000) >> 4)
	c &= 0x0fffffff

	for i := 0; i < 16; i++ {
		if i < 2 || i == 8 || i == 15 {
			c = (c >> 1) | (c << 27)
			d = (d >> 1) | (d << 27)
		} else {
			c = (c >> 2) | (c << 26)
			d = (d >> 2) | (d << 26)
		}
		c &= 0x0fffffff
		d &= 0x0fffffff

		c00 := c & 0x0000003f
		c06 := (c >> 6) & 0x00383003
		c07 := (c >> 7) & 0x0000003c
		c13 := (c >> 13) & 0x0000060f
		c20 := (c >> 20) & 0x00000001

		s := desSKB[0][c00&0xff] |
			desSKB[1][(c06&0xff)|(c07&0xff)] |
			desSKB[2][(c13&0xff)|((c06>>8)&0xff)] |
			desSKB[3][(c20&0xff)|((c13>>8)&0xff)|((c06>>16)&0xff)]

		d00 := d & 0x00003c3f
		d07 := (d >> 7) & 0x00003f03
		d21 := (d >> 21) & 0x0000000f
		d22 := (d >> 22) & 0x00000030

		t := desSKB[4][d00&0xff] |
			desSKB[5][(d07&0xff)|((d00>>8)&0xff)] |
			desSKB[6][(d07>>8)&0xff] |
			desSKB[7][(d21&0xff)|(d22&0xff)]

		kc[i] = rotl32((t<<16)|(s&0x0000ffff), 2)
		kd[i] = rotl32((s>>16)|(t&0xffff0000), 2)
	}
	return kc, kd
}

func rotl32(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

func desRound(u, t uint32) uint32 {
	return desSPtrans[0][(u>>2)&0x3f] |
		desSPtrans[2][(u>>10)&0x3f] |
		desSPtrans[4][(u>>18)&0x3f] |
		desSPtrans[6][(u>>26)&0x3f] |
		desSPtrans[1][(t>>2)&0x3f] |
		desSPtrans[3][(t>>10)&0x3f] |
		desSPtrans[5][(t>>18)&0x3f] |
		desSPtrans[7][(t>>26)&0x3f]
}

// desEncryptRACF runs the sixteen rounds with neither IP nor FP.
func desEncryptRACF(data [2]uint32, kc, kd [16]uint32) [2]uint32 {
	r, l := data[0], data[1]
	for i := 0; i < 16; i += 2 {
		l ^= desRound(kc[i]^r, kd[i]^rotl32(r, 28))
		r ^= desRound(kc[i+1]^l, kd[i+1]^rotl32(l, 28))
	}
	return [2]uint32{l, r}
}

// racfDigest is the whole construction: EBCDIC-map the password into key
// material, then push the eight-byte block through the rounds.
func racfDigest(password string, block [8]byte) [2]uint32 {
	var key [8]byte
	for i := 0; i < 8; i++ {
		var ch byte
		if i < len(password) {
			ch = password[i]
		}
		key[i] = racfASCIIToEBCDIC[ch]
	}
	c := binary.LittleEndian.Uint32(key[0:4])
	d := binary.LittleEndian.Uint32(key[4:8])
	kc, kd := desKeySetup(c, d)
	return desEncryptRACF([2]uint32{
		binary.LittleEndian.Uint32(block[0:4]),
		binary.LittleEndian.Uint32(block[4:8]),
	}, kc, kd)
}

// racfDigestWords is racfDigest with the block already in hashcat's two-word,
// initially-permuted form.
func racfDigestWords(w0, w1 uint32, password string) [2]uint32 {
	var key [8]byte
	for i := 0; i < 8; i++ {
		var ch byte
		if i < len(password) {
			ch = password[i]
		}
		key[i] = racfASCIIToEBCDIC[ch]
	}
	kc, kd := desKeySetup(binary.LittleEndian.Uint32(key[0:4]), binary.LittleEndian.Uint32(key[4:8]))
	return desEncryptRACF([2]uint32{w0, w1}, kc, kd)
}
