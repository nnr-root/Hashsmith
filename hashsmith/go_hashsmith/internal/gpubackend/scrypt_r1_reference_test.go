package gpubackend

// This file is the verification trail for opencl_scrypt_experimental.cl's
// own doc comment, which asserts that its algorithm (Salsa20/8, BlockMix
// r=1, ROMix/smix, a Davies-Meyer multi-block SHA-256, HMAC-SHA256, and
// PBKDF2 with 1 iteration) was checked against trusted references in plain
// Go before being transcribed into OpenCL C. An assertion of verification
// with no committed evidence is just a claim — this is the evidence, kept
// permanently (not thrown away after one interactive session) so a future
// reader can re-run it, and so any future edit to the .cl file's logic has
// something real to re-verify against by porting the change here first.
//
// Every function below is a 1:1 mirror of its OpenCL counterpart — same
// variable roles, same loop/unroll shape where it matters for the
// translation's faithfulness, same big-endian byte packing. This file
// builds and runs natively (no CGO, no build tag) specifically so it stays
// runnable on any machine, including one (like this project's own dev
// machine) where the CGO toolchain itself is broken.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func rotl32r(x uint32, b uint) uint32 { return (x << b) | (x >> (32 - b)) }
func rotr32r(x uint32, b uint) uint32 { return (x >> b) | (x << (32 - b)) }

// salsa208Ref mirrors salsa20_8_core in opencl_scrypt_experimental.cl.
func salsa208Ref(B *[16]uint32) {
	var x [16]uint32
	copy(x[:], B[:])
	for i := 0; i < 4; i++ {
		x[4] ^= rotl32r(x[0]+x[12], 7)
		x[8] ^= rotl32r(x[4]+x[0], 9)
		x[12] ^= rotl32r(x[8]+x[4], 13)
		x[0] ^= rotl32r(x[12]+x[8], 18)
		x[9] ^= rotl32r(x[5]+x[1], 7)
		x[13] ^= rotl32r(x[9]+x[5], 9)
		x[1] ^= rotl32r(x[13]+x[9], 13)
		x[5] ^= rotl32r(x[1]+x[13], 18)
		x[14] ^= rotl32r(x[10]+x[6], 7)
		x[2] ^= rotl32r(x[14]+x[10], 9)
		x[6] ^= rotl32r(x[2]+x[14], 13)
		x[10] ^= rotl32r(x[6]+x[2], 18)
		x[3] ^= rotl32r(x[15]+x[11], 7)
		x[7] ^= rotl32r(x[3]+x[15], 9)
		x[11] ^= rotl32r(x[7]+x[3], 13)
		x[15] ^= rotl32r(x[11]+x[7], 18)

		x[1] ^= rotl32r(x[0]+x[3], 7)
		x[2] ^= rotl32r(x[1]+x[0], 9)
		x[3] ^= rotl32r(x[2]+x[1], 13)
		x[0] ^= rotl32r(x[3]+x[2], 18)
		x[6] ^= rotl32r(x[5]+x[4], 7)
		x[7] ^= rotl32r(x[6]+x[5], 9)
		x[4] ^= rotl32r(x[7]+x[6], 13)
		x[5] ^= rotl32r(x[4]+x[7], 18)
		x[11] ^= rotl32r(x[10]+x[9], 7)
		x[8] ^= rotl32r(x[11]+x[10], 9)
		x[9] ^= rotl32r(x[8]+x[11], 13)
		x[10] ^= rotl32r(x[9]+x[8], 18)
		x[12] ^= rotl32r(x[15]+x[14], 7)
		x[13] ^= rotl32r(x[12]+x[15], 9)
		x[14] ^= rotl32r(x[13]+x[12], 13)
		x[15] ^= rotl32r(x[14]+x[13], 18)
	}
	for i := range B {
		B[i] += x[i]
	}
}

// blockmixR1Ref mirrors blockmix_salsa8_r1.
func blockmixR1Ref(B *[32]uint32) {
	var X [16]uint32
	copy(X[:], B[16:32])
	var Y0 [16]uint32
	for i := 0; i < 16; i++ {
		X[i] ^= B[i]
	}
	salsa208Ref(&X)
	copy(Y0[:], X[:])
	for i := 0; i < 16; i++ {
		X[i] ^= B[16+i]
	}
	salsa208Ref(&X)
	copy(B[0:16], Y0[:])
	copy(B[16:32], X[:])
}

// smixR1Ref mirrors smix_r1, including the N-must-be-a-power-of-2 shortcut
// (j = B[16] & (N-1) instead of a 64-bit modulo).
func smixR1Ref(B *[32]uint32, N uint32) {
	V := make([][32]uint32, N)
	for i := uint32(0); i < N; i++ {
		V[i] = *B
		blockmixR1Ref(B)
	}
	mask := N - 1
	for i := uint32(0); i < N; i++ {
		j := B[16] & mask
		for w := 0; w < 32; w++ {
			B[w] ^= V[j][w]
		}
		blockmixR1Ref(B)
	}
}

var sha256KRef = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// sha256CompressFromStateRef mirrors sha256_compress_from_state: Davies-
// Meyer, H is both input and output, unlike opencl_kernels.cl's own
// sha256_compress (which always starts from the fixed IV, since every
// caller there hashes exactly one block — HMAC needs real chaining).
func sha256CompressFromStateRef(M *[16]uint32, H *[8]uint32) {
	var W [16]uint32
	copy(W[:], M[:])
	a, b, c, d, e, f, g, h := H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
	for i := 0; i < 64; i++ {
		var w uint32
		if i < 16 {
			w = W[i]
		} else {
			s0 := rotr32r(W[(i+1)&15], 7) ^ rotr32r(W[(i+1)&15], 18) ^ (W[(i+1)&15] >> 3)
			s1 := rotr32r(W[(i+14)&15], 17) ^ rotr32r(W[(i+14)&15], 19) ^ (W[(i+14)&15] >> 10)
			W[i&15] += s1 + W[(i+9)&15] + s0
			w = W[i&15]
		}
		t1 := h + (rotr32r(e, 6) ^ rotr32r(e, 11) ^ rotr32r(e, 25)) + ((e & f) ^ (^e & g)) + sha256KRef[i] + w
		t2 := (rotr32r(a, 2) ^ rotr32r(a, 13) ^ rotr32r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
		h, g, f, e = g, f, e, d+t1
		d, c, b, a = c, b, a, t1+t2
	}
	H[0] += a
	H[1] += b
	H[2] += c
	H[3] += d
	H[4] += e
	H[5] += f
	H[6] += g
	H[7] += h
}

// sha256HashRef mirrors sha256_hash's multi-block MD-padding loop.
func sha256HashRef(msg []byte) [8]uint32 {
	H := [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	totalBits := uint64(len(msg)) * 8
	nBlocks := (len(msg) + 9 + 63) / 64
	for blk := 0; blk < nBlocks; blk++ {
		var m [16]uint32
		base := blk * 64
		for bi := 0; bi < 64; bi++ {
			pos := base + bi
			var byteVal byte
			if pos < len(msg) {
				byteVal = msg[pos]
			} else if pos == len(msg) {
				byteVal = 0x80
			}
			m[bi>>2] |= uint32(byteVal) << (24 - uint((bi&3)*8))
		}
		if blk == nBlocks-1 {
			m[14] = uint32(totalBits >> 32)
			m[15] = uint32(totalBits)
		}
		sha256CompressFromStateRef(&m, &H)
	}
	return H
}

func beBytesRef(H *[8]uint32) []byte {
	out := make([]byte, 32)
	for i, v := range H {
		out[i*4] = byte(v >> 24)
		out[i*4+1] = byte(v >> 16)
		out[i*4+2] = byte(v >> 8)
		out[i*4+3] = byte(v)
	}
	return out
}

// hmacSHA256Ref mirrors hmac_sha256 (key <= 64 bytes, zero-padded).
func hmacSHA256Ref(key, msg []byte) []byte {
	var k [64]byte
	copy(k[:], key)
	var ipad, opad [64]byte
	for i := 0; i < 64; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	inner := sha256HashRef(append(ipad[:], msg...))
	outer := sha256HashRef(append(opad[:], beBytesRef(&inner)...))
	return beBytesRef(&outer)
}

func be32r(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

// pbkdf2Iter1Ref mirrors the kernel's own PBKDF2-HMAC-SHA256 with exactly 1
// iteration (T_i = U_1), used for both B_init (dkLen=128) and the final
// output (dkLen=32).
func pbkdf2Iter1Ref(password, salt []byte, dkLen int) []byte {
	var out []byte
	for i := uint32(1); len(out) < dkLen; i++ {
		out = append(out, hmacSHA256Ref(password, append(append([]byte{}, salt...), be32r(i)...))...)
	}
	return out[:dkLen]
}

// scryptR1Ref mirrors the kernel's full scrypt_r1_probe pipeline end to end.
//
// The PBKDF2 byte string and the Salsa20/BlockMix 32-bit words are two
// INDEPENDENT representations with two INDEPENDENT, unrelated endianness
// conventions, and conflating them is an easy, real mistake (an earlier
// draft of this exact function made it, caught only because this test
// exists): PBKDF2-HMAC-SHA256's output is always a byte STRING, written in
// HMAC's own natural order — that part is fixed by SHA-256 and never in
// question. Separately, RFC 7914 §3 requires that byte string be
// reinterpreted as 32-bit scrypt words using LITTLE-ENDIAN octet-to-integer
// conversion for every Salsa20/BlockMix operation — that convention has
// nothing to do with SHA-256 being big-endian internally; it is scrypt's
// own, independent choice.
func scryptR1Ref(password, salt []byte, N uint32, dkLen int) []byte {
	bInit := pbkdf2Iter1Ref(password, salt, 128)
	var B [32]uint32
	for i := 0; i < 32; i++ {
		B[i] = uint32(bInit[i*4]) | uint32(bInit[i*4+1])<<8 | uint32(bInit[i*4+2])<<16 | uint32(bInit[i*4+3])<<24
	}
	smixR1Ref(&B, N)
	bFinal := make([]byte, 128)
	for i := 0; i < 32; i++ {
		bFinal[i*4] = byte(B[i])
		bFinal[i*4+1] = byte(B[i] >> 8)
		bFinal[i*4+2] = byte(B[i] >> 16)
		bFinal[i*4+3] = byte(B[i] >> 24)
	}
	return pbkdf2Iter1Ref(password, bFinal, dkLen)
}

// TestScryptR1RefMatchesRFC7914Vector is RFC 7914 §12's own published
// vector: scrypt(P="", S="", N=16, r=1, p=1, dkLen=64).
func TestScryptR1RefMatchesRFC7914Vector(t *testing.T) {
	want, err := hex.DecodeString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
	if err != nil {
		t.Fatal(err)
	}
	got := scryptR1Ref(nil, nil, 16, 64)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

// TestScryptR1RefMatchesXCrypto cross-checks against golang.org/x/crypto/scrypt
// (configured for r=1) across varied inputs, including N=16384 — the exact
// parameter Cisco $9$ uses, the format this project's own CPU-side
// scrypt-AVX2 spike measured.
func TestScryptR1RefMatchesXCrypto(t *testing.T) {
	cases := []struct {
		pw, salt string
		n        uint32
		dk       int
	}{
		{"", "", 16, 64},
		{"password", "salt1234", 16, 32},
		{"correcthorsebatterystaple", "deadbeefcafe0000", 64, 32},
		{"a", "b", 1024, 32},
		{"longer password with spaces and punctuation!", "0123456789abcdef", 16384, 32},
	}
	for _, c := range cases {
		got := scryptR1Ref([]byte(c.pw), []byte(c.salt), c.n, c.dk)
		want, err := scrypt.Key([]byte(c.pw), []byte(c.salt), int(c.n), 1, 1, c.dk)
		if err != nil {
			t.Fatalf("pw=%q salt=%q N=%d: x/crypto/scrypt error: %v", c.pw, c.salt, c.n, err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("pw=%q salt=%q N=%d dk=%d: got %x, want %x", c.pw, c.salt, c.n, c.dk, got, want)
		}
	}
}

// TestHMACSHA256RefMatchesStdlib exercises the Davies-Meyer multi-block
// SHA-256 compressor through hmacSHA256Ref, including a deliberately
// 4-SHA-256-block inner message (64+132 bytes) — the exact worst case the
// kernel's own B_final step produces.
func TestHMACSHA256RefMatchesStdlib(t *testing.T) {
	cases := []struct{ key, msg string }{
		{"", ""},
		{"key", "The quick brown fox jumps over the lazy dog"},
		{"password", "salt12341"},
		{repeatByte('x', 55), repeatByte('y', 132)},
	}
	for _, c := range cases {
		got := hmacSHA256Ref([]byte(c.key), []byte(c.msg))
		h := hmac.New(sha256.New, []byte(c.key))
		h.Write([]byte(c.msg))
		want := h.Sum(nil)
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("key=%q msglen=%d: got %x, want %x", c.key, len(c.msg), got, want)
		}
	}
}

func repeatByte(b byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}

// TestPBKDF2Iter1RefMatchesXCrypto exercises multi-block PBKDF2 output
// (dkLen up to 128 bytes = 4 HMAC calls), matching what B_init generation
// needs.
func TestPBKDF2Iter1RefMatchesXCrypto(t *testing.T) {
	for _, dk := range []int{32, 64, 128} {
		got := pbkdf2Iter1Ref([]byte("password"), []byte("salt1234"), dk)
		want := pbkdf2.Key([]byte("password"), []byte("salt1234"), 1, dk, sha256.New)
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("dkLen=%d: got %x, want %x", dk, got, want)
		}
	}
}
