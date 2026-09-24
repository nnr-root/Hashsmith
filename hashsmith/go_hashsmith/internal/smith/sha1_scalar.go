package smith

// sha1ScalarCompress and sha1ExpandSchedule mirror sha256_scalar.go's role
// for SHA-1: a from-scratch, portable-Go core supporting compression from
// an ARBITRARY starting state (not only the standard IV), for the same
// three reasons given there — the AVX2 core's correctness oracle, the
// generic (non-amd64) fallback, and the PBKDF2 lane hasher's one-time,
// non-hot-path U1 computation.

// sha1IV is the standard SHA-1 initial state, in the [5]uint32 layout
// sha1ScalarCompress and the AVX2 core both take (index 0=a .. 4=e).
var sha1IV = [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}

// sha1K holds the 4 round constants, expanded to one per round (80 entries)
// so the AVX2 core reads K the same memory-operand way sha256AVX2Kvec does
// — no branch on round range needed in the generator or the assembly.
var sha1K [80]uint32

func init() {
	consts := [4]uint32{0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}
	for i := range sha1K {
		sha1K[i] = consts[i/20]
	}
}

// sha1ExpandSchedule expands one 64-byte block into the full 80-word
// message schedule per FIPS 180-4 Sec 6.1.2 step 1: the first 16 words come
// from the block, the rest are ROTL1(w[i-3]^w[i-8]^w[i-14]^w[i-16]) — a
// single rotate-XOR, unlike SHA-256's two-sigma expansion.
func sha1ExpandSchedule(block *[64]byte, w *[80]uint32) {
	for i := 0; i < 16; i++ {
		w[i] = uint32(block[i*4])<<24 | uint32(block[i*4+1])<<16 | uint32(block[i*4+2])<<8 | uint32(block[i*4+3])
	}
	for i := 16; i < 80; i++ {
		w[i] = sha256Rotr(w[i-3]^w[i-8]^w[i-14]^w[i-16], 31) // ROTL1(x) == ROTR(x,31)
	}
}

// sha1ScalarCompress runs SHA-1's compression function on one already-
// expanded 80-word schedule, updating state in place. state may be any
// value, not only sha1IV — see sha256ScalarCompress's own comment for why
// that generalization is exact, not approximate: nothing in the algorithm
// special-cases the IV.
func sha1ScalarCompress(state *[5]uint32, w *[80]uint32) {
	a, b, c, d, e := state[0], state[1], state[2], state[3], state[4]
	for i := 0; i < 80; i++ {
		var f uint32
		switch {
		case i < 20:
			f = d ^ (b & (c ^ d)) // Ch(b,c,d), the same bit-select identity used throughout this project
		case i < 40:
			f = b ^ c ^ d // Parity
		case i < 60:
			f = (b & c) ^ (d & (b ^ c)) // Maj(b,c,d)
		default:
			f = b ^ c ^ d // Parity
		}
		temp := sha256Rotr(a, 27) + f + e + sha1K[i] + w[i] // ROTL5(a) == ROTR(a,27)
		e, d, c, b, a = d, c, sha256Rotr(b, 2), a, temp      // ROTL30(b) == ROTR(b,2)
	}
	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
	state[4] += e
}
