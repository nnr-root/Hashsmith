package smith

// sha256ScalarCompress and sha256ExpandSchedule are a from-scratch,
// portable-Go SHA-256 compression core. They exist for three reasons, all
// needing the same primitive crypto/sha256's public API does not expose:
// compressing a single 64-byte block starting from an ARBITRARY state, not
// only the standard IV via a full Sum256 call.
//
//  1. The correctness oracle for sha256avx2_amd64.s (sha256avx2_test.go):
//     the AVX2 core and this scalar one must agree on every lane, for many
//     random starting states and blocks, not just state=IV.
//  2. The generic (non-amd64) fallback for the AVX2 wrapper — see
//     sha256avx2_generic.go — so the package behaves identically on every
//     architecture, only the implementation underneath differs, exactly
//     like md5avx2_generic.go's role for the MD5 core.
//  3. The PBKDF2 lane hasher's one-time, non-hot-path pieces (U1's
//     variable-length salt||counter absorption): see the design's own
//     note that this is deliberately not vectorized, since the hot loop
//     (fixed one-block-per-iteration U_n, n>=2) dominates any realistic
//     iteration count by orders of magnitude.
//
// Verified against crypto/sha256 in sha256_scalar_test.go — not merely
// trusted because it "looks like FIPS 180-4."

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// sha256IV is the standard SHA-256 initial state, in the [8]uint32 layout
// sha256ScalarCompress and the AVX2 core both take (index 0=a .. 7=h).
var sha256IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

func sha256Rotr(x uint32, n uint) uint32 { return (x >> n) | (x << (32 - n)) }

// sha256ExpandSchedule expands one 64-byte block into the full 64-word
// message schedule, per FIPS 180-4 Sec 6.2.2 step 1. w must have length 64;
// only the first 16 words come from block, the rest are computed.
func sha256ExpandSchedule(block *[64]byte, w *[64]uint32) {
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 | uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}
	for i := 16; i < 64; i++ {
		s0 := sha256Rotr(w[i-15], 7) ^ sha256Rotr(w[i-15], 18) ^ (w[i-15] >> 3)
		s1 := sha256Rotr(w[i-2], 17) ^ sha256Rotr(w[i-2], 19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
}

// sha256ScalarCompress runs SHA-256's compression function on one already-
// expanded 64-word schedule, updating state in place. state may be any
// value, not only sha256IV — continuing from an arbitrary intermediate
// state (as HMAC's inner/outer continuation needs) is exactly the same
// computation as starting fresh, with no special-casing of the IV anywhere
// in the algorithm.
func sha256ScalarCompress(state *[8]uint32, w *[64]uint32) {
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
	for i := 0; i < 64; i++ {
		s1 := sha256Rotr(e, 6) ^ sha256Rotr(e, 11) ^ sha256Rotr(e, 25)
		ch := (e & f) ^ (^e & g)
		t1 := h + s1 + ch + sha256K[i] + w[i]
		s0 := sha256Rotr(a, 2) ^ sha256Rotr(a, 13) ^ sha256Rotr(a, 22)
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
