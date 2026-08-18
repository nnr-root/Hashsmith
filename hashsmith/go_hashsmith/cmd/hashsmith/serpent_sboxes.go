package main

// Serpent S-boxes as 4-bit lookup tables, applied bitsliced across the four
// 32-bit words (bit j of each word forms one S-box nibble, x0 = LSB). Using the
// tables directly — rather than hand-optimised boolean formulas — keeps the
// implementation obviously correct; correctness is pinned by the LUKS/ECB tests.

var serpentSBoxes = [8][16]byte{
	{3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12},
	{15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4},
	{8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2},
	{0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14},
	{1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13},
	{15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1},
	{7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0},
	{1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6},
}

// serpentSBoxInv is the inverse of each S-box, built at init.
var serpentSBoxesInv [8][16]byte

func init() {
	for n := 0; n < 8; n++ {
		for i := 0; i < 16; i++ {
			serpentSBoxesInv[n][serpentSBoxes[n][i]] = byte(i)
		}
	}
}

// applySerpentSBox applies a 4-bit table bitsliced across the four words.
func applySerpentSBox(table *[16]byte, a, b, c, d *uint32) {
	var o0, o1, o2, o3 uint32
	x0, x1, x2, x3 := *a, *b, *c, *d
	for j := uint(0); j < 32; j++ {
		idx := (x0>>j)&1 | ((x1>>j)&1)<<1 | ((x2>>j)&1)<<2 | ((x3>>j)&1)<<3
		v := uint32(table[idx])
		o0 |= (v & 1) << j
		o1 |= ((v >> 1) & 1) << j
		o2 |= ((v >> 2) & 1) << j
		o3 |= ((v >> 3) & 1) << j
	}
	*a, *b, *c, *d = o0, o1, o2, o3
}

func serpentSBox(n int, a, b, c, d *uint32) {
	applySerpentSBox(&serpentSBoxes[n], a, b, c, d)
}

func serpentSBoxInv(n int, a, b, c, d *uint32) {
	applySerpentSBox(&serpentSBoxesInv[n], a, b, c, d)
}
