package smith

import "testing"

// ── Why descrypt is not bitsliced ────────────────────────────────────────────
//
// §4 of the roadmap recorded "descrypt is not bitsliced, costing ~400x against
// John's bitsliced DES". The table-driven work in descrypt_fast.go closed most
// of that — roughly 11x, from bit-at-a-time permutations to SP tables and a
// fused iteration loop — and the question of whether to go further kept coming
// back. This file answers it with a measurement instead of an estimate, so the
// next person does not have to re-derive it.
//
// Bitslicing computes N passwords at once, one per bit of a machine word, with
// the S-boxes written as boolean gate networks and the permutations reduced to
// wire selection (free). Its whole economy rests on those gate networks being
// SMALL: the published ones (Kwan's, Rusakov's) run about 45-60 gates per
// S-box, the product of years of dedicated search.
//
// A gate network cannot be derived cheaply. What CAN be derived mechanically,
// from the S-box table alone, is a multiplexer tree — Shannon decomposition,
// one 64-leaf tree per output bit. bsSBoxMuxTree below is exactly that, and
// TestBitslicedSBoxIsCorrectButSlow proves it computes the right S-box.
//
// It is also about ten times larger than a hand-optimised network, and the
// benchmark shows what that costs: per S-box per 64 candidates it is several
// times SLOWER than the SP-table lookup the scalar path already uses. So a
// mechanically-derived bitslice is not an optimisation at all, and a
// hand-optimised one in pure Go over uint64 would be worth roughly the ratio
// between 500 gates and 50 — a small multiple, not an order of magnitude,
// because the scalar path's table lookup is already close to load-bound.
//
// John's remaining advantage is not the gate networks alone. It is 128-bit
// SIMD (twice the lanes per instruction) on top of them. Matching it here
// would mean hand-written NEON and AVX2 for the full bitsliced round — the
// project has precedent for that in md4/md5, and it is a project rather than
// a change.

// bsSBoxMuxTree computes S-box `box` in bitsliced form for 64 candidates at
// once, derived from desSBox by Shannon decomposition. in[i] holds bit i of
// each candidate's six-bit input (i=0 most significant), one candidate per
// lane; out[j] receives bit j of the four-bit output (j=0 most significant).
func bsSBoxMuxTree(box int, in [6]uint64, out *[4]uint64) {
	for j := 0; j < 4; j++ {
		// The bottom level's leaves are constants — the S-box entries — so
		// each pair collapses to one select rather than a full mux.
		var lvl [32]uint64
		for k := 0; k < 32; k++ {
			lvl[k] = bsConst(box, 2*k, j) ^
				((bsConst(box, 2*k, j) ^ bsConst(box, 2*k+1, j)) & in[5])
		}
		n := 32
		for s := 4; s >= 0; s-- {
			n /= 2
			for k := 0; k < n; k++ {
				a, b := lvl[2*k], lvl[2*k+1]
				lvl[k] = a ^ ((a ^ b) & in[s])
			}
		}
		out[j] = lvl[0]
	}
}

// bsConst is the S-box output bit j for the six-bit input `six`, as an
// all-ones or all-zero word. The row/column indexing is DES's own — the outer
// bits pick the row and the middle four the column — and getting it wrong here
// would make the tree model a different function that still looked plausible.
func bsConst(box, six, j int) uint64 {
	row := ((six >> 5) & 1 << 1) | (six & 1)
	col := (six >> 1) & 0x0f
	if desSBox[box][row*16+col]>>(3-j)&1 == 1 {
		return ^uint64(0)
	}
	return 0
}

// TestBitslicedSBoxIsCorrectButSlow checks all 64 inputs of all 8 S-boxes —
// exhaustive, since one lane can carry each input — so the benchmark below is
// timing a correct implementation rather than a broken one.
func TestBitslicedSBoxIsCorrectButSlow(t *testing.T) {
	var in [6]uint64
	for bit := 0; bit < 6; bit++ {
		var w uint64
		for lane := 0; lane < 64; lane++ {
			if lane>>(5-bit)&1 == 1 {
				w |= 1 << uint(lane)
			}
		}
		in[bit] = w
	}
	for box := 0; box < 8; box++ {
		var out [4]uint64
		bsSBoxMuxTree(box, in, &out)
		for lane := 0; lane < 64; lane++ {
			row := ((lane >> 5) & 1 << 1) | (lane & 1)
			col := (lane >> 1) & 0x0f
			want := desSBox[box][row*16+col]
			got := 0
			for j := 0; j < 4; j++ {
				if out[j]>>uint(lane)&1 == 1 {
					got |= 1 << (3 - j)
				}
			}
			if got != want {
				t.Fatalf("box %d lane %d: bitsliced gave %d, table gives %d", box, lane, got, want)
			}
		}
	}
}

// BenchmarkSBoxForms is the measurement the comment at the top rests on: one
// S-box applied to 64 candidates, bitsliced against the scalar SP-table the
// current implementation uses.
func BenchmarkSBoxForms(b *testing.B) {
	var in [6]uint64
	for i := range in {
		in[i] = uint64(i)*0x9e3779b97f4a7c15 + 1
	}
	var out [4]uint64
	b.Run("bitsliced-muxtree", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bsSBoxMuxTree(0, in, &out)
		}
	})
	b.Run("scalar-SP-table", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var acc uint32
			for lane := 0; lane < 64; lane++ {
				acc ^= desSP[0][(uint64(lane)*0x9e37)&0x3f]
			}
			out[0] = uint64(acc)
		}
	})
}
