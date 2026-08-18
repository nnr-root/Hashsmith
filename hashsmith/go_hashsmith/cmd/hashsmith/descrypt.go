package main

// Traditional DES-based crypt(3) — the 13-character hashes ("abJnggxhB/yWI")
// that predate the $-tagged shadow schemes. Still occasionally seen on old
// Unix systems and in captured /etc/shadow files, so shadow cracking needs it.
//
// The algorithm is DES with two twists:
//   - the 8-byte key is the password with each 7-bit character shifted left one
//     bit (into the high 7 bits of each key byte);
//   - a 12-bit salt perturbs the E-expansion by swapping bit j with bit j+24
//     whenever salt bit j is set;
// then a 64-bit zero block is encrypted 25 times and the result is packed into
// 11 crypt-base64 characters, prefixed by the two salt characters.

import (
	"errors"
	"strings"
)

// ── DES permutation tables (1-indexed, bit 1 = most-significant) ───────────────

var desIP = [64]int{
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
}

var desFP = [64]int{
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
}

var desE = [48]int{
	32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
	24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
}

var desP = [32]int{
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
}

var desPC1 = [56]int{
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
}

var desPC2 = [48]int{
	14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
}

var desShifts = [16]int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

var desSBox = [8][64]int{
	{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
}

// getBit reads bit `pos` (1-indexed from the MSB) of a `width`-bit value.
func getBit(v uint64, pos, width int) uint64 {
	return (v >> uint(width-pos)) & 1
}

// permute applies a permutation table, mapping an inWidth-bit input to an
// len(table)-bit output.
func permute(v uint64, table []int, inWidth int) uint64 {
	var out uint64
	for _, pos := range table {
		out = (out << 1) | getBit(v, pos, inWidth)
	}
	return out
}

// desSubkeys derives the 16 round subkeys from a 64-bit key value.
func desSubkeys(key uint64) [16]uint64 {
	permuted := permute(key, desPC1[:], 64) // 56 bits
	c := (permuted >> 28) & 0x0fffffff
	d := permuted & 0x0fffffff
	var ks [16]uint64
	for i := 0; i < 16; i++ {
		s := uint(desShifts[i])
		c = ((c << s) | (c >> (28 - s))) & 0x0fffffff
		d = ((d << s) | (d >> (28 - s))) & 0x0fffffff
		cd := (c << 28) | d
		ks[i] = permute(cd, desPC2[:], 56) // 48 bits
	}
	return ks
}

// desFeistel computes the round function f(r, subkey) with the salt-modified
// expansion. salt is a 24-bit mask: when bit j is set, expansion bits j and
// j+24 are swapped before the subkey XOR.
func desFeistel(r uint64, subkey uint64, salt uint32) uint64 {
	e := permute(r, desE[:], 32) // 48 bits, e[0]=MSB … e[47]

	// Apply salt swaps on the 48-bit expansion. Bit index j (0-based from MSB)
	// pairs with j+24.
	for j := 0; j < 24; j++ {
		if salt&(1<<uint(j)) != 0 {
			hi := (e >> uint(47-j)) & 1
			lo := (e >> uint(47-(j+24))) & 1
			if hi != lo {
				e ^= (1 << uint(47-j)) | (1 << uint(47-(j+24)))
			}
		}
	}

	e ^= subkey
	// 8 S-boxes, each 6→4 bits, MSB group first.
	var out uint64
	for i := 0; i < 8; i++ {
		six := (e >> uint(42-6*i)) & 0x3f
		row := ((six >> 5) & 1 << 1) | (six & 1)
		col := (six >> 1) & 0x0f
		out = (out << 4) | uint64(desSBox[i][row*16+col])
	}
	return permute(out, desP[:], 32) // 32 bits
}

// desEncryptBlock runs the 16-round DES encryption of a 64-bit block with the
// salt-modified expansion.
func desEncryptBlock(block uint64, ks [16]uint64, salt uint32) uint64 {
	ip := permute(block, desIP[:], 64)
	l := (ip >> 32) & 0xffffffff
	r := ip & 0xffffffff
	for i := 0; i < 16; i++ {
		nl := r
		nr := l ^ desFeistel(r, ks[i], salt)
		l, r = nl, nr
	}
	// Preoutput is R16||L16 (halves swapped) before the final permutation.
	pre := (r << 32) | l
	return permute(pre, desFP[:], 64)
}

// descryptSaltChar decodes one crypt-base64 salt character to its 6-bit value.
func descryptSaltChar(c byte) (uint32, bool) {
	i := strings.IndexByte(itoa64, c)
	if i < 0 {
		return 0, false
	}
	return uint32(i), true
}

// descryptRaw computes a traditional DES crypt hash and returns the full
// 13-character "<2-char-salt><11-char-hash>" string. Only the first 8 bytes of
// the password are significant.
func descryptRaw(password, salt string) (string, error) {
	if len(salt) < 2 {
		return "", errors.New("descrypt salt must be 2 characters")
	}
	s0, ok0 := descryptSaltChar(salt[0])
	s1, ok1 := descryptSaltChar(salt[1])
	if !ok0 || !ok1 {
		return "", errors.New("descrypt salt has non-crypt-base64 characters")
	}
	saltVal := s0 | (s1 << 6) // 12-bit salt

	// Build the 64-bit key: each password char occupies the high 7 bits of a
	// key byte (char << 1); absent chars are zero.
	var key uint64
	pw := []byte(password)
	for i := 0; i < 8; i++ {
		var b byte
		if i < len(pw) {
			b = pw[i] << 1
		}
		key = (key << 8) | uint64(b)
	}

	ks := desSubkeys(key)

	// Encrypt the all-zero block 25 times.
	var block uint64
	for i := 0; i < 25; i++ {
		block = desEncryptBlock(block, ks, saltVal)
	}

	// Pack the 64-bit result into 11 crypt-base64 chars, MSB-first in 6-bit
	// groups (3 bytes → 4 chars; the trailing 2 bytes → 3 chars).
	var q [8]byte
	for i := 0; i < 8; i++ {
		q[i] = byte(block >> uint(56-8*i))
	}
	out := make([]byte, 0, 11)
	emit := func(l uint32, n int) {
		for i := 0; i < n; i++ {
			shift := uint(18 - 6*i)
			out = append(out, itoa64[(l>>shift)&0x3f])
		}
	}
	emit(uint32(q[0])<<16|uint32(q[1])<<8|uint32(q[2]), 4)
	emit(uint32(q[3])<<16|uint32(q[4])<<8|uint32(q[5]), 4)
	emit(uint32(q[6])<<16|uint32(q[7])<<8, 3)

	return salt[:2] + string(out), nil
}

// looksLikeDescrypt reports whether s has the shape of a traditional DES crypt
// hash: exactly 13 characters, all from the crypt-base64 alphabet.
func looksLikeDescrypt(s string) bool {
	if len(s) != 13 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(itoa64, s[i]) < 0 {
			return false
		}
	}
	return true
}

// verifyDescrypt checks a candidate against a 13-char traditional DES crypt hash.
func verifyDescrypt(targetHash, candidate string) (bool, error) {
	if !looksLikeDescrypt(targetHash) {
		return false, errors.New("invalid descrypt hash (need 13 crypt-base64 chars)")
	}
	got, err := descryptRaw(candidate, targetHash[:2])
	if err != nil {
		return false, err
	}
	return got == targetHash, nil
}
