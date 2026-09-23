package smith

// ── A faster descrypt inner loop ──────────────────────────────────────────────
//
// The implementation next door is textbook DES: every permutation walks its
// table one bit at a time. That is the clearest way to write it and the
// slowest way to run it. Per Feistel round it costs 48 iterations expanding R,
// 24 testing salt bits and 32 permuting the S-box output — and descrypt runs
// 16 rounds twenty-five times, so a single password costs on the order of
// forty thousand loop iterations. Measured: 10.45 kH/s on one core, against
// John's 2,945 kH/s.
//
// Two standard transformations remove almost all of it, and neither changes
// what is computed:
//
//   - The S-box output and the P permutation are composed ONCE, at startup,
//     into eight 64-entry tables of pre-permuted 32-bit words. The round
//     function becomes eight indexed loads and eight XORs instead of eighty
//     bit operations. This is the classic SP-box form.
//
//   - The salt's E-expansion swap becomes mask arithmetic. Swapping bit j with
//     bit j+24 for every set salt bit is three operations on the whole word,
//     not a twenty-four iteration loop with a branch inside it.
//
// Bitslicing — John's DES 128/128 ASIMD, which computes 128 passwords at once
// with the S-boxes as gate networks — is a different and much larger project.
// This is the ordinary optimisation that should exist underneath it either
// way, and it is verified against the bit-at-a-time code it replaces rather
// than against itself: see TestDescryptFastMatchesReference.

// desETab[b][v] is the contribution of byte b of R (b=0 most significant) to
// the 48-bit E expansion when that byte holds v.
//
// A permutation is linear over bit positions: every output bit comes from
// exactly one input bit, so the expansion of a whole word is the OR of the
// expansions of its bytes. That turns a 48-iteration loop into four indexed
// loads and three ORs. The same identity underlies the SP tables below, and
// both are generated from the very tables the reference walks, so neither can
// encode a different permutation than the reference does.
var desETab [4][256]uint64

// desPC1Tab and desPC2Tab are the key schedule's two permutations, driven by
// byte rather than by bit for the same reason desETab is: a permutation is
// linear over bit positions, so the image of a word is the OR of the images of
// its bytes.
//
// The schedule is not the hot loop — it runs once per password against 400
// Feistel calls — but it was still an eighth of descryptRaw's time (583ns of
// 4839ns), because PC1 walks 64 positions and PC2 walks 56 of them sixteen
// times over: 960 bit-loop iterations to produce one key's subkeys.
var (
	desPC1Tab [8][256]uint64
	desPC2Tab [7][256]uint64
)

// desSP[i][v] is S-box i applied to the 6-bit value v, placed in that box's
// nibble of the 32-bit word, and then run through the P permutation. Composing
// the two means the round function never touches P at all.
var desSP [8][64]uint32

// desEMask[j] and the salt mask below operate on the 48-bit expansion with bit
// 0 as the MOST significant, matching desFeistel's own convention.
func init() {
	for b := 0; b < 4; b++ {
		for v := 0; v < 256; v++ {
			word := uint64(v) << uint(8*(3-b))
			desETab[b][v] = permute(word, desE[:], 32)
		}
	}
	for b := 0; b < 8; b++ {
		for v := 0; v < 256; v++ {
			// Byte b of a 64-bit value, in the MSB-first numbering permute
			// uses: byte 0 holds bit positions 1..8.
			desPC1Tab[b][v] = permute(uint64(v)<<uint(56-8*b), desPC1[:], 64)
		}
	}
	for b := 0; b < 7; b++ {
		for v := 0; v < 256; v++ {
			// Byte b of a 56-bit value.
			desPC2Tab[b][v] = permute(uint64(v)<<uint(48-8*b), desPC2[:], 56)
		}
	}
	for box := 0; box < 8; box++ {
		for six := 0; six < 64; six++ {
			row := ((six >> 5) & 1 << 1) | (six & 1)
			col := (six >> 1) & 0x0f
			nibble := uint64(desSBox[box][row*16+col])
			// Box i's nibble sits at bit position 4*(7-i) of the 32-bit
			// pre-P value, exactly where desFeistel's shift-and-or puts it.
			word := nibble << uint(4*(7-box))
			desSP[box][six] = uint32(permute(word, desP[:], 32))
		}
	}
}

// descryptSaltMask turns the 12-bit crypt salt into the 48-bit mask the swap
// uses: salt bit j selects expansion bit j, whose partner is bit j+24. In the
// MSB-first numbering desFeistel uses, expansion bit j is 1<<(47-j).
func descryptSaltMask(salt uint32) uint64 {
	var m uint64
	for j := 0; j < 24; j++ {
		if salt&(1<<uint(j)) != 0 {
			m |= 1 << uint(47-j)
		}
	}
	return m
}

// desFeistelFast is desFeistel with the two transformations applied. saltMask
// is descryptSaltMask(salt), hoisted out of the round loop because it depends
// only on the record.
func desFeistelFast(r uint64, subkey uint64, saltMask uint64) uint64 {
	e := desETab[0][(r>>24)&0xff] |
		desETab[1][(r>>16)&0xff] |
		desETab[2][(r>>8)&0xff] |
		desETab[3][r&0xff] // 48 bits, e[0] = MSB

	// Swap each selected bit j with bit j+24. saltMask marks the HIGH member
	// of each pair, at shift 47-j; its partner at shift 47-(j+24) is 24
	// places lower, so aligning the two means shifting the low one UP. (The
	// first version of this shifted down, which pairs each selected bit with
	// one 24 places above it instead — the tests below caught it on salt bit
	// 0 alone.) Bits pushed past 47 by the shift are removed by the mask.
	//
	// diff then holds, at the high position, the XOR of the two bits; XORing
	// it in at both positions exchanges them and leaves equal pairs alone,
	// which is what the reference version's branch was testing for.
	diff := ((e << 24) ^ e) & saltMask
	e ^= diff | (diff >> 24)

	e ^= subkey
	return uint64(desSP[0][(e>>42)&0x3f] |
		desSP[1][(e>>36)&0x3f] |
		desSP[2][(e>>30)&0x3f] |
		desSP[3][(e>>24)&0x3f] |
		desSP[4][(e>>18)&0x3f] |
		desSP[5][(e>>12)&0x3f] |
		desSP[6][(e>>6)&0x3f] |
		desSP[7][e&0x3f])
}

// desEncryptBlockFast is desEncryptBlock over the faster round function.
//
// descryptIterate25 below supersedes it for descrypt itself, which no longer
// permutes between iterations at all. This stays because it is the rung
// between the two: TestDescryptFastBlockMatchesReference exercises
// desFeistelFast across a whole block, IP and FP included, against the
// bit-at-a-time original. Removing it would leave the fused loop verified only
// end to end, with nothing isolating a round-function fault from a fusion
// fault.
func desEncryptBlockFast(block uint64, ks *[16]uint64, saltMask uint64) uint64 {
	ip := permute(block, desIP[:], 64)
	l := (ip >> 32) & 0xffffffff
	r := ip & 0xffffffff
	for i := 0; i < 16; i++ {
		l, r = r, l^desFeistelFast(r, ks[i], saltMask)
	}
	return permute((r<<32)|l, desFP[:], 64)
}

// desIterateZeroBlock encrypts the all-zero block `rounds` times under a fixed
// key schedule and salt, and returns the final result. descrypt asks for
// twenty-five; BSDi extended crypt asks for whatever its record's count field
// says, up to 2^24.
//
// It exists because the obvious loop — call desEncryptBlock `rounds` times —
// applies IP at the start of every iteration and FP at the end of every
// iteration, and those two are inverses. Iteration n+1 begins by permuting
// back exactly what iteration n just finished permuting: two permutations of
// sixty-four bits per iteration where two IN TOTAL would do.
//
// Writing the state in the IP domain makes that explicit. If Pn is the
// pre-output of iteration n — the value FP is applied to — then
//
//	IP(block_{n+1}) = IP(FP(Pn)) = Pn
//
// so the rounds run back-to-back on Pn with nothing between them, and FP is
// applied once at the end. The initial IP is free as well: both callers start
// from the all-zero block, and permuting zeros gives zeros.
//
// For descrypt that removes forty-eight of fifty permutations. For BSDi, whose
// count field routinely asks for tens of thousands of iterations, it removes
// essentially all of them.
//
// Equivalence with the repeated-call form is asserted against the
// bit-at-a-time desEncryptBlock, not against the faster block function, in
// TestDesIterateZeroBlockMatchesReference.
func desIterateZeroBlock(ks *[16]uint64, saltMask uint64, rounds int) uint64 {
	var state uint64 // IP(0) == 0
	for i := 0; i < rounds; i++ {
		l := (state >> 32) & 0xffffffff
		r := state & 0xffffffff
		for j := 0; j < 16; j++ {
			l, r = r, l^desFeistelFast(r, ks[j], saltMask)
		}
		// The pre-output is R16||L16, halves swapped — the value the final
		// permutation is applied to, and so the next iteration's IP image.
		state = (r << 32) | l
	}
	return permute(state, desFP[:], 64)
}

// desSubkeysFast is desSubkeys over the byte-driven permutations. It must
// produce the identical schedule — TestDesSubkeysFastMatchesReference asserts
// that over random keys, against the bit-at-a-time original which stays as
// the authority.
func desSubkeysFast(key uint64) [16]uint64 {
	permuted := desPC1Tab[0][(key>>56)&0xff] |
		desPC1Tab[1][(key>>48)&0xff] |
		desPC1Tab[2][(key>>40)&0xff] |
		desPC1Tab[3][(key>>32)&0xff] |
		desPC1Tab[4][(key>>24)&0xff] |
		desPC1Tab[5][(key>>16)&0xff] |
		desPC1Tab[6][(key>>8)&0xff] |
		desPC1Tab[7][key&0xff] // 56 bits
	c := (permuted >> 28) & 0x0fffffff
	d := permuted & 0x0fffffff
	var ks [16]uint64
	for i := 0; i < 16; i++ {
		s := uint(desShifts[i])
		c = ((c << s) | (c >> (28 - s))) & 0x0fffffff
		d = ((d << s) | (d >> (28 - s))) & 0x0fffffff
		cd := (c << 28) | d
		ks[i] = desPC2Tab[0][(cd>>48)&0xff] |
			desPC2Tab[1][(cd>>40)&0xff] |
			desPC2Tab[2][(cd>>32)&0xff] |
			desPC2Tab[3][(cd>>24)&0xff] |
			desPC2Tab[4][(cd>>16)&0xff] |
			desPC2Tab[5][(cd>>8)&0xff] |
			desPC2Tab[6][cd&0xff] // 48 bits
	}
	return ks
}
