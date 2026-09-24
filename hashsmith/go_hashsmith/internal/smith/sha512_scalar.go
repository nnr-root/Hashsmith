package smith

// sha512ScalarCompress and sha512ExpandSchedule mirror sha256_scalar.go's
// role for SHA-512: a from-scratch, portable-Go core supporting compression
// from an ARBITRARY starting state, for the same three reasons given
// there. SHA-512's round function has the identical shape to SHA-256's
// (same T1=h+Sigma1(e)+Ch(e,f,g)+K+W / T2=Sigma0(a)+Maj(a,b,c) structure —
// SHA-512 is not a distinct algorithm design, just SHA-256's family
// generalized to 64-bit words) — what differs is word size, rotation
// amounts, round count (80, not 64), and block size (128 bytes, not 64,
// with a 128-bit rather than 64-bit length field in padding).

var sha512K = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

var sha512IV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

func sha512Rotr(x uint64, n uint) uint64 { return (x >> n) | (x << (64 - n)) }

// sha512ExpandSchedule expands one 128-byte block into the full 80-word
// (64-bit word) message schedule per FIPS 180-4 Sec 6.4.2 step 1 — the
// same sigma-based expansion as SHA-256's, widened to 64-bit words and
// SHA-512's own rotation amounts.
func sha512ExpandSchedule(block *[128]byte, w *[80]uint64) {
	for i := 0; i < 16; i++ {
		var v uint64
		for b := 0; b < 8; b++ {
			v = v<<8 | uint64(block[i*8+b])
		}
		w[i] = v
	}
	for i := 16; i < 80; i++ {
		s0 := sha512Rotr(w[i-15], 1) ^ sha512Rotr(w[i-15], 8) ^ (w[i-15] >> 7)
		s1 := sha512Rotr(w[i-2], 19) ^ sha512Rotr(w[i-2], 61) ^ (w[i-2] >> 6)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
}

// sha512ScalarCompress runs SHA-512's compression function on one already-
// expanded 80-word schedule, updating state in place. state may be any
// value, not only sha512IV — see sha256ScalarCompress's comment for why
// that generalization is exact.
func sha512ScalarCompress(state *[8]uint64, w *[80]uint64) {
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
	for i := 0; i < 80; i++ {
		s1 := sha512Rotr(e, 14) ^ sha512Rotr(e, 18) ^ sha512Rotr(e, 41)
		ch := (e & f) ^ (^e & g)
		t1 := h + s1 + ch + sha512K[i] + w[i]
		s0 := sha512Rotr(a, 28) ^ sha512Rotr(a, 34) ^ sha512Rotr(a, 39)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := s0 + maj
		h, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
	state[4] += e
	state[5] += f
	state[6] += g
	state[7] += h
}
