package main

// Regression tests for the maskKeyspace int64-overflow bug: a mask whose
// true candidate count exceeds math.MaxInt64 (e.g. a 10-position ?a mask,
// 95^10 = 59,873,693,923,837,890,625) used to wrap silently to a small
// positive number (4,533,461,702,709,235,777 — about 7.57% of the true
// count), so the run "succeeded" having enumerated the wrong, truncated
// keyspace with no error or warning. The fix saturates all keyspace
// arithmetic at math.MaxInt64 instead of wrapping.

import (
	"math"
	"math/big"
	"testing"
)

// ── satMul / satAdd boundary tests ──────────────────────────────────────────

func TestSatMulNormal(t *testing.T) {
	cases := []struct{ a, b, want int64 }{
		{0, 0, 0},
		{0, 5, 0},
		{5, 0, 0},
		{1, 1, 1},
		{3, 7, 21},
		{1000, 1000, 1000000},
		{math.MaxInt64, 1, math.MaxInt64},
		{1, math.MaxInt64, math.MaxInt64},
		{math.MaxInt64 / 2, 2, (math.MaxInt64 / 2) * 2}, // exact, no overflow
	}
	for _, c := range cases {
		if got := satMul(c.a, c.b); got != c.want {
			t.Errorf("satMul(%d,%d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSatMulOverflowSaturates(t *testing.T) {
	cases := []struct{ a, b int64 }{
		{math.MaxInt64, 2},
		{math.MaxInt64, math.MaxInt64},
		{1 << 32, 1 << 32},                               // exactly overflows 63 bits
		{95, 95 * 95 * 95 * 95 * 95 * 95 * 95 * 95 * 95}, // 95^9, still fits; * one more 95 overflows below
	}
	for _, c := range cases {
		if got := satMul(c.a, c.b); got != math.MaxInt64 {
			t.Errorf("satMul(%d,%d) = %d, want MaxInt64 (saturated)", c.a, c.b, got)
		}
	}
}

func TestSatMulNegativeDefensive(t *testing.T) {
	// Keyspace math never produces negative operands, but satMul must not
	// flip sign on them either — it should saturate rather than return a
	// nonsensical (and potentially negative) product.
	if got := satMul(-5, 3); got != math.MaxInt64 {
		t.Errorf("satMul(-5,3) = %d, want MaxInt64", got)
	}
	if got := satMul(5, -3); got != math.MaxInt64 {
		t.Errorf("satMul(5,-3) = %d, want MaxInt64", got)
	}
}

func TestSatAddNormal(t *testing.T) {
	cases := []struct{ a, b, want int64 }{
		{0, 0, 0},
		{0, 5, 5},
		{5, 0, 5},
		{3, 7, 10},
		{math.MaxInt64 - 1, 1, math.MaxInt64}, // exact, lands right on the boundary
		{math.MaxInt64, 0, math.MaxInt64},
	}
	for _, c := range cases {
		if got := satAdd(c.a, c.b); got != c.want {
			t.Errorf("satAdd(%d,%d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSatAddOverflowSaturates(t *testing.T) {
	cases := []struct{ a, b int64 }{
		{math.MaxInt64, 1},
		{math.MaxInt64, math.MaxInt64},
		{math.MaxInt64 - 1, 2},
	}
	for _, c := range cases {
		if got := satAdd(c.a, c.b); got != math.MaxInt64 {
			t.Errorf("satAdd(%d,%d) = %d, want MaxInt64 (saturated)", c.a, c.b, got)
		}
	}
}

func TestSatAddNegativeDefensive(t *testing.T) {
	if got := satAdd(-1, 5); got != math.MaxInt64 {
		t.Errorf("satAdd(-1,5) = %d, want MaxInt64", got)
	}
}

// ── maskKeyspace regression: the bug this whole fix pins ───────────────────

// makeSets builds a set list of `positions` positions, each with `charsetLen`
// distinct bytes — enough to build synthetic masks of any size for testing
// without going through parseMask.
func makeSets(positions, charsetLen int) [][]byte {
	base := make([]byte, charsetLen)
	for i := range base {
		base[i] = byte('a' + (i % 26))
	}
	sets := make([][]byte, positions)
	for i := range sets {
		sets[i] = base
	}
	return sets
}

// TestMaskKeyspaceAOverflowSaturates is the regression test: a ?a-equivalent
// 10-position mask (95 symbols per position) has a true keyspace of
// 95^10 = 59,873,693,923,837,890,625, which does not fit in an int64. The old
// code wrapped this to 4,533,461,702,709,235,777 (still positive, so nothing
// failed loudly) — a silent 7.57%-of-requested-keyspace truncation. The fixed
// maskKeyspace must saturate to math.MaxInt64 and must NEVER return the old
// wrapped value.
func TestMaskKeyspaceAOverflowSaturates(t *testing.T) {
	sets := makeSets(10, 95)

	const wrongWrappedValue = int64(4533461702709235777)

	got := maskKeyspace(sets)

	if got == wrongWrappedValue {
		t.Fatalf("maskKeyspace returned the known-wrong wrapped value %d — overflow bug is back", got)
	}
	if got != math.MaxInt64 {
		t.Fatalf("maskKeyspace(?a x10) = %d, want math.MaxInt64 (%d)", got, int64(math.MaxInt64))
	}

	// Cross-check against the true value computed with math/big, to make sure
	// we're actually testing an overflowing case and not a mistaken setup.
	trueTotal := big.NewInt(1)
	ninetyFive := big.NewInt(95)
	for i := 0; i < 10; i++ {
		trueTotal.Mul(trueTotal, ninetyFive)
	}
	wantTrue, ok := new(big.Int).SetString("59873693923837890625", 10)
	if !ok || trueTotal.Cmp(wantTrue) != 0 {
		t.Fatalf("test setup error: 95^10 computed as %s, want 59873693923837890625", trueTotal.String())
	}
	if trueTotal.Cmp(big.NewInt(math.MaxInt64)) <= 0 {
		t.Fatal("test setup error: 95^10 does not actually exceed MaxInt64")
	}
}

// maskKeyspaceExact must agree: it should report the exact true value and
// flag that it overflowed int64 range.
func TestMaskKeyspaceExactMatchesTrueValue(t *testing.T) {
	sets := makeSets(10, 95)
	exact, overflowed := maskKeyspaceExact(sets)
	if !overflowed {
		t.Fatal("maskKeyspaceExact: want overflowed=true for ?a x10")
	}
	want, _ := new(big.Int).SetString("59873693923837890625", 10)
	if exact.Cmp(want) != 0 {
		t.Fatalf("maskKeyspaceExact = %s, want %s", exact.String(), want.String())
	}
}

// ── Property test: non-negative, non-decreasing as sets are appended ───────

func TestMaskKeyspaceMonotonicNonNegative(t *testing.T) {
	// A sweep of set-list shapes, including several that overflow int64.
	shapes := [][2]int{
		{0, 0},   // no positions
		{1, 1},   // trivial
		{3, 26},  // small, well within range
		{8, 95},  // still fits (95^8 ≈ 6.6e15)
		{10, 95}, // overflows (95^10)
		{20, 95}, // overflows harder
		{40, 2},  // overflows via many small factors
	}
	for _, shape := range shapes {
		positions, charsetLen := shape[0], shape[1]
		var sets [][]byte
		prev := int64(1) // maskKeyspace of the empty set list is 1 (identity product)
		for i := 0; i < positions; i++ {
			base := make([]byte, charsetLen)
			for j := range base {
				base[j] = byte('a' + (j % 26))
			}
			sets = append(sets, base)
			got := maskKeyspace(sets)
			if got < 0 {
				t.Fatalf("maskKeyspace negative at %d positions of %d: %d", i+1, charsetLen, got)
			}
			if got < prev {
				t.Fatalf("maskKeyspace decreased after appending a set: %d -> %d (position %d, charsetLen %d)",
					prev, got, i+1, charsetLen)
			}
			prev = got
		}
	}
}

func TestMaskKeyspaceEmptySetReturnsZero(t *testing.T) {
	sets := [][]byte{[]byte("ab"), {}, []byte("cd")}
	if got := maskKeyspace(sets); got != 0 {
		t.Errorf("maskKeyspace with an empty position set = %d, want 0", got)
	}
}

// ── calcMaskTotal (increment mode) must not wrap ────────────────────────────

func TestCalcMaskTotalIncrementOverflowSaturates(t *testing.T) {
	// Build a custom-set mask "?1?1?1?1?1?1?1?1?1?1" (10 positions, 95 chars
	// each via custom set 1) with increment mode from length 1..10. Summing
	// 95^1 + 95^2 + ... + 95^10 overflows int64 well before reaching the
	// last term, and the old `total += maskKeyspace(...)` would wrap.
	custom := string(makeSets(1, 95)[0])
	cfg := &maskConfig{
		mask:      "?1?1?1?1?1?1?1?1?1?1",
		custom:    [4]string{custom, "", "", ""},
		increment: true,
		incMin:    1,
	}
	got := calcMaskTotal(cfg)
	if got != math.MaxInt64 {
		t.Fatalf("calcMaskTotal(increment ?a x10) = %d, want math.MaxInt64", got)
	}
	if got < 0 {
		t.Fatal("calcMaskTotal must never be negative")
	}

	exact, overflowed := calcMaskTotalExact(cfg)
	if !overflowed {
		t.Fatal("calcMaskTotalExact: want overflowed=true")
	}
	if exact.Sign() <= 0 {
		t.Fatalf("calcMaskTotalExact exact value should be large and positive, got %s", exact.String())
	}
}

// ── calcBruteTotal must not wrap either (same bug shape) ───────────────────

func TestCalcBruteTotalOverflowSaturates(t *testing.T) {
	// 95-character charset, lengths 1..12: 95^12 vastly exceeds int64 range.
	charset := string(makeSets(1, 95)[0])
	got := calcBruteTotal(charset, 1, 12)
	if got != math.MaxInt64 {
		t.Fatalf("calcBruteTotal(95-char, 1..12) = %d, want math.MaxInt64", got)
	}
	exact, overflowed := calcBruteTotalExact(charset, 1, 12)
	if !overflowed {
		t.Fatal("calcBruteTotalExact: want overflowed=true")
	}
	if exact.Cmp(big.NewInt(math.MaxInt64)) <= 0 {
		t.Fatal("calcBruteTotalExact should exceed MaxInt64")
	}
}

// ── End-to-end: setting up a ?a x10 mask reports a saturated/true size,
// never the old wrapped value. Does NOT run the attack — only checks the
// keyspace accounting that happens at setup time. ─────────────────────────

func TestEndToEndMaskAKeyspaceNotWrapped(t *testing.T) {
	// Ten custom-set positions of 95 chars each == a ?a x10 mask's keyspace,
	// built with a real maskConfig through parseMask (custom sets), exactly
	// as buildMaskConfig / doCrack would see it.
	custom := string(makeSets(1, 95)[0])
	cfg := &maskConfig{mask: "?1?1?1?1?1?1?1?1?1?1", custom: [4]string{custom, "", "", ""}}

	sets, err := parseMask(cfg)
	if err != nil {
		t.Fatalf("parseMask: %v", err)
	}
	if len(sets) != 10 {
		t.Fatalf("want 10 positions, got %d", len(sets))
	}

	total := calcMaskTotal(cfg)
	const wrongWrappedValue = int64(4533461702709235777)
	if total == wrongWrappedValue {
		t.Fatal("calcMaskTotal reported the known-wrong wrapped value — regression")
	}
	if total != math.MaxInt64 {
		t.Fatalf("calcMaskTotal(?a x10) = %d, want math.MaxInt64", total)
	}

	// The layout used by the actual runner must agree, and building it must
	// not run any candidates (maskLayout only computes offsets/total).
	layout, err := maskLayout(cfg)
	if err != nil {
		t.Fatalf("maskLayout: %v", err)
	}
	if layout.total != math.MaxInt64 {
		t.Fatalf("maskLayout(?a x10).total = %d, want math.MaxInt64", layout.total)
	}

	// The warning predicate must fire for this mask.
	exact, overflowed := calcMaskTotalExact(cfg)
	if !overflowed {
		t.Fatal("calcMaskTotalExact must flag this mask as exceeding int64 range")
	}
	wantExact, _ := new(big.Int).SetString("59873693923837890625", 10)
	if exact.Cmp(wantExact) != 0 {
		t.Fatalf("calcMaskTotalExact = %s, want %s", exact.String(), wantExact.String())
	}
}

// A small, ordinary mask must still report the exact keyspace, unchanged
// from today's behaviour (no saturation for normal-sized keyspaces).
func TestSmallMaskKeyspaceExactUnchanged(t *testing.T) {
	sets, err := parseMask(&maskConfig{mask: "?u?l?d?s"})
	if err != nil {
		t.Fatal(err)
	}
	want := int64(26 * 26 * 10 * len(maskSymbol))
	if got := maskKeyspace(sets); got != want {
		t.Errorf("maskKeyspace(small mask) = %d, want exact %d", got, want)
	}
	if exact, overflowed := maskKeyspaceExact(sets); overflowed || exact.Int64() != want {
		t.Errorf("maskKeyspaceExact(small mask) = %s overflowed=%v, want exact %d overflowed=false",
			exact.String(), overflowed, want)
	}
}
