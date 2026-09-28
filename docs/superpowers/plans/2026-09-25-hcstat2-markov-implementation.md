# hcstat2-compatible positional Markov Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load real hashcat `.hcstat2` files into a new positional Markov model, add `--hcstat2`/`--markov-threshold` to `-a markov`, closing the last well-scoped gap in Phase 2 (Reach).

**Architecture:** A new pure-decode file (`hcstat2.go`) turns a `.hcstat2` file's bytes into raw count tables. `markov.go`'s existing `markovModel`/`markovLayout` gain a positional sibling path (new fields, new branch in `decode`) built from those tables, alongside the existing live-wordlist-trained path (unchanged in spirit, generalized only where threshold now applies uniformly). `crack.go` wires two new flags through the existing `crackCtx`/`doCrack`/`printKeyspace` seams every other mode already uses.

**Tech Stack:** Go 1.26, `github.com/ulikunitz/xz/lzma` (already a project dependency, used today in `codecs_compression.go`).

**Spec:** `docs/superpowers/specs/2026-09-25-hcstat2-markov-design.md` — read it first. This plan implements it exactly; where a step needs a constant or byte-layout detail, the spec's §2/§5 has the derivation.

## Global Constraints

- Go 1.26, module `hashsmith-go`, package `internal/smith`.
- No new dependencies — `github.com/ulikunitz/xz/lzma` is already used directly in this package (`codecs_compression.go`).
- Every new function gets a table-driven or scenario test in the same task that introduces it; no task ends with the suite red.
- A committed real fixture already exists at `internal/smith/testdata/hcstat2_sample.hcstat2` (built from `internal/smith/testdata/hcstat2_sample_wordlist.txt`, contents `aab`, `aac`, `aad`, `zzz`, via hashcat-utils' own `hcstat2gen.c` compressed with `xz --format=raw --lzma1=preset=9e,lc=1,lp=3,pb=0`) — this plan's tests read it, no task needs to generate it.
- Pre-verified expected values for that fixture (computed by decoding it once during planning, cite these directly in tests rather than re-deriving): `root[0]['a']=3`, `root[0]['z']=1`, `root[1]['a']=3`, `root[2]['b']=1`, `root[2]['c']=1`, `root[2]['d']=1`, `root[2]['z']=1`, `markov[0]['a']['a']=3`, `markov[1]['a']['b']=1`, `markov[1]['a']['c']=1`, `markov[1]['a']['d']=1`, `markov[2]['b']['b']=0` (never observed — position 2 is the last character of every training word, so no position-2→3 transition exists).

---

### Task 1: hcstat2 binary decoder

**Files:**
- Create: `internal/smith/hcstat2.go`
- Create: `internal/smith/hcstat2_test.go`

**Interfaces:**
- Produces: `decodeHCStat2(compressed []byte) (*hcstat2Tables, error)` and `loadHCStat2Tables(path string) (*hcstat2Tables, error)`, plus the exported-within-package constants and `hcstat2Tables` type, for Task 3 to build a `markovModel` from.

- [ ] **Step 1: Write the failing test**

```go
// internal/smith/hcstat2_test.go
package smith

import "testing"

func TestDecodeHCStat2MatchesKnownFixtureCounts(t *testing.T) {
	tbl, err := loadHCStat2Tables("testdata/hcstat2_sample.hcstat2")
	if err != nil {
		t.Fatalf("loadHCStat2Tables: %v", err)
	}
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"root[0]['a']", tbl.root[0]['a'], 3},
		{"root[0]['z']", tbl.root[0]['z'], 1},
		{"root[1]['a']", tbl.root[1]['a'], 3},
		{"root[2]['b']", tbl.root[2]['b'], 1},
		{"root[2]['c']", tbl.root[2]['c'], 1},
		{"root[2]['d']", tbl.root[2]['d'], 1},
		{"root[2]['z']", tbl.root[2]['z'], 1},
		{"markov[0]['a']['a']", tbl.markov[0]['a']['a'], 3},
		{"markov[1]['a']['b']", tbl.markov[1]['a']['b'], 1},
		{"markov[1]['a']['c']", tbl.markov[1]['a']['c'], 1},
		{"markov[1]['a']['d']", tbl.markov[1]['a']['d'], 1},
		{"markov[2]['b']['b']", tbl.markov[2]['b']['b'], 0},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestDecodeHCStat2RejectsGarbage(t *testing.T) {
	if _, err := decodeHCStat2([]byte("not a real hcstat2 file")); err == nil {
		t.Fatal("decodeHCStat2 accepted garbage input")
	}
}

func TestLoadHCStat2TablesRejectsMissingFile(t *testing.T) {
	if _, err := loadHCStat2Tables("testdata/does-not-exist.hcstat2"); err == nil {
		t.Fatal("loadHCStat2Tables accepted a missing path")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/smith/ -run TestDecodeHCStat2 -v`
Expected: FAIL — `loadHCStat2Tables`/`decodeHCStat2`/`hcstat2Tables` undefined.

- [ ] **Step 3: Write the implementation**

```go
// internal/smith/hcstat2.go
package smith

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz/lzma"
)

// hcstat2 is hashcat's positional Markov statistics file format. See
// docs/superpowers/specs/2026-09-25-hcstat2-markov-design.md §2 for the full
// derivation of every constant and the byte layout below — it was validated
// against a real file produced by hashcat-utils' own hcstat2gen.c, not
// assumed from documentation.
const (
	hcstat2CharSize = 256
	hcstat2PWMax    = 256
	hcstat2RootCnt  = hcstat2PWMax * hcstat2CharSize
	hcstat2MarkovCnt = hcstat2PWMax * hcstat2CharSize * hcstat2CharSize
	// hcstat2FileSize is the exact decompressed size: two 8-byte header
	// words (magic + zero padding) plus the root and markov tables, each
	// entry a big-endian uint64.
	hcstat2FileSize = 8 + 8 + hcstat2RootCnt*8 + hcstat2MarkovCnt*8
	// hcstat2Magic is "hcstat" followed by 0x00 0x02 (version 2), read as
	// one big-endian uint64.
	hcstat2Magic = 0x6863737461740002
	// hcstat2LZMAProps is the raw-LZMA1 properties byte (lc=1, lp=3, pb=0)
	// hashcat hardcodes for every .hcstat2 file it reads — any file it can
	// open was necessarily compressed with these exact parameters.
	hcstat2LZMAProps = 0x1c
	// hcstat2LZMADictCap matches the dictionary size xz's -9e preset uses;
	// it only needs to be at least as large as what encoding actually used.
	hcstat2LZMADictCap = 1 << 26
)

// hcstat2Tables holds the decoded root and markov count tables — see the
// design doc's table in §2 for what each index means.
type hcstat2Tables struct {
	root   [hcstat2PWMax][hcstat2CharSize]uint64
	markov [hcstat2PWMax][hcstat2CharSize][hcstat2CharSize]uint64
}

// decodeHCStat2 decompresses and parses a .hcstat2 file's raw on-disk bytes.
// The file is a headerless raw LZMA1 stream, so a synthetic 13-byte
// LZMA_ALONE-style header (properties + dict size + the exact known output
// size) is prepended in memory before handing it to lzma.Reader, which
// expects that header and has no other way to learn these parameters.
func decodeHCStat2(compressed []byte) (*hcstat2Tables, error) {
	header := make([]byte, 13)
	header[0] = hcstat2LZMAProps
	binary.LittleEndian.PutUint32(header[1:5], hcstat2LZMADictCap)
	binary.LittleEndian.PutUint64(header[5:13], uint64(hcstat2FileSize))

	r, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(compressed)))
	if err != nil {
		return nil, fmt.Errorf("hcstat2: %w", err)
	}
	raw := make([]byte, hcstat2FileSize)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, fmt.Errorf("hcstat2: decompression failed (not a valid .hcstat2 file?): %w", err)
	}

	if magic := binary.BigEndian.Uint64(raw[0:8]); magic != hcstat2Magic {
		return nil, errors.New("hcstat2: bad magic — not a version-2 hcstat file")
	}
	if binary.BigEndian.Uint64(raw[8:16]) != 0 {
		return nil, errors.New("hcstat2: bad header padding")
	}

	t := &hcstat2Tables{}
	off := 16
	for pos := 0; pos < hcstat2PWMax; pos++ {
		for b := 0; b < hcstat2CharSize; b++ {
			t.root[pos][b] = binary.BigEndian.Uint64(raw[off : off+8])
			off += 8
		}
	}
	for pos := 0; pos < hcstat2PWMax; pos++ {
		for prev := 0; prev < hcstat2CharSize; prev++ {
			for next := 0; next < hcstat2CharSize; next++ {
				t.markov[pos][prev][next] = binary.BigEndian.Uint64(raw[off : off+8])
				off += 8
			}
		}
	}
	return t, nil
}

// loadHCStat2Tables reads and decodes the .hcstat2 file at path.
func loadHCStat2Tables(path string) (*hcstat2Tables, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeHCStat2(data)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/smith/ -run 'TestDecodeHCStat2|TestLoadHCStat2Tables' -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add internal/smith/hcstat2.go internal/smith/hcstat2_test.go
git commit -m "feat(markov): decode hashcat's .hcstat2 positional statistics format"
```

---

### Task 2: Generalize `rankCharset` to unsigned counts

**Files:**
- Modify: `internal/smith/markov.go` (the `rankCharset` function and `trainMarkov`'s two call sites/local variables)
- Modify: `internal/smith/markov_test.go` only if a test directly constructs an `int64` count array (check first — the existing tests in this file train through `trainMarkov`, which does not expose counts directly, so no test change is expected here)

**Interfaces:**
- Consumes: nothing new.
- Produces: `rankCharset(charset []byte, count *[256]uint64) []byte` (signature changed from `*[256]int64`) — Task 3's positional ranking calls this directly against `hcstat2Tables.root[pos]`/`.markov[pos][prev]`, which are already `[256]uint64`.

- [ ] **Step 1: Run the existing tests to confirm green before touching anything**

Run: `go test ./internal/smith/ -run TestMarkov -v`
Expected: PASS (`TestMarkovBijection`, `TestMarkovOrdersLikelyFirst`).

- [ ] **Step 2: Change `rankCharset`'s signature and `trainMarkov`'s local counters**

In `internal/smith/markov.go`, change:

```go
func rankCharset(charset []byte, count *[256]int64) []byte {
```

to:

```go
func rankCharset(charset []byte, count *[256]uint64) []byte {
```

(the function body is otherwise unchanged — `sort.SliceStable`'s comparator only compares, never arithmetic, so `>` on `uint64` behaves identically to `>` on `int64` for values that are never negative, which counts never are). Then in `trainMarkov`, change:

```go
	var firstCount [256]int64
	var transCount [256][256]int64
```

to:

```go
	var firstCount [256]uint64
	var transCount [256][256]uint64
```

No other line in `trainMarkov` changes — `firstCount[c]++`/`transCount[prev][c]++` compile identically against `uint64`.

- [ ] **Step 3: Run the tests again to verify nothing broke**

Run: `go test ./internal/smith/ -run TestMarkov -v`
Expected: PASS, identical to Step 1 — this step is a pure type generalization with no behavior change.

- [ ] **Step 4: Commit**

```bash
git add internal/smith/markov.go
git commit -m "refactor(markov): generalize rankCharset to unsigned counts

Prep for the hcstat2 positional model, whose count tables are uint64.
Behavior-preserving: markov counts are never negative today either."
```

---

### Task 3: Positional `markovModel`

**Files:**
- Modify: `internal/smith/markov.go` (struct, `decode`, `markovLayout`, `trainMarkov`'s signature)
- Modify: `internal/smith/markov_test.go` (update the two existing `trainMarkov` call sites for the new parameter)
- Create: `internal/smith/markov_positional_test.go`

**Interfaces:**
- Consumes: `hcstat2Tables` (Task 1), `rankCharset(charset []byte, count *[256]uint64) []byte` (Task 2).
- Produces: `markovModel.radix int` and `.positional bool` fields (read by Task 4's CLI wiring only indirectly, through `markovLayout`/`decode`, which callers never need to touch directly); `trainMarkov(charset, wordlistPath string, threshold int) (*markovModel, error)` (signature changed — added `threshold`); `loadHCStat2(path string, threshold int) (*markovModel, error)` (new); `markovRadix(threshold, domainSize int) int` (new, also used directly by Task 4's `printKeyspace` change).

- [ ] **Step 1: Update the two existing call sites for `trainMarkov`'s new parameter**

In `internal/smith/markov_test.go`, change both:

```go
	m, err := trainMarkov("abc", wl)
```

and

```go
	m, err := trainMarkov("abz", wl)
```

to pass `0` (no threshold — preserves today's exact behavior):

```go
	m, err := trainMarkov("abc", wl, 0)
```

```go
	m, err := trainMarkov("abz", wl, 0)
```

- [ ] **Step 2: Write the new failing tests**

```go
// internal/smith/markov_positional_test.go
package smith

import (
	"os"
	"testing"
)

func TestMarkovRadix(t *testing.T) {
	cases := []struct{ threshold, domain, want int }{
		{0, 256, 256},   // unset = unlimited
		{300, 256, 256}, // clamps to the domain
		{8, 256, 8},
		{-1, 256, 256}, // negative treated as unset
	}
	for _, c := range cases {
		if got := markovRadix(c.threshold, c.domain); got != c.want {
			t.Errorf("markovRadix(%d, %d) = %d, want %d", c.threshold, c.domain, got, c.want)
		}
	}
}

func TestLoadHCStat2BuildsExpectedRanking(t *testing.T) {
	// Fixture is trained on "aab", "aac", "aad", "zzz" — 'a' strictly
	// dominates position 0 (3 votes vs 'z' at 1), so it must rank first.
	m, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 0)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	if !m.positional {
		t.Fatal("loadHCStat2 must produce a positional model")
	}
	if m.radix != 256 {
		t.Fatalf("radix = %d, want 256 (no threshold given)", m.radix)
	}
	if got := m.posFirst[0][0]; got != 'a' {
		t.Errorf("posFirst[0][0] = %q, want 'a'", got)
	}
	// position 1, conditioned on 'a' at position 0: 'a' appears in all
	// three "aXY" words, strictly dominating 'z'.
	if got := m.posCond[0]['a'][0]; got != 'a' {
		t.Errorf("posCond[0]['a'][0] = %q, want 'a'", got)
	}

	// A length-3 candidate built greedily from this ranking should spell
	// "aaa" — not necessarily a trained word (position 2 has a 4-way tie
	// among 'b','c','d','z', broken deterministically by byte value), but
	// position 0 and 1 must be 'a'.
	layout := markovLayout(m, 3, 3)
	c := layout.candidate(0)
	if c[0] != 'a' || c[1] != 'a' {
		t.Errorf("most-likely length-3 candidate = %q, want to start \"aa\"", c)
	}
}

func TestLoadHCStat2ThresholdShrinksRadixAndKeyspace(t *testing.T) {
	full, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 0)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	limited, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 4)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	if limited.radix != 4 {
		t.Fatalf("radix = %d, want 4", limited.radix)
	}
	fullLayout := markovLayout(full, 3, 3)
	limitedLayout := markovLayout(limited, 3, 3)
	if limitedLayout.total >= fullLayout.total {
		t.Errorf("thresholded total (%d) should be smaller than unthresholded (%d)",
			limitedLayout.total, fullLayout.total)
	}
	if limitedLayout.total != 4*4*4 {
		t.Errorf("thresholded total = %d, want 4^3 = 64", limitedLayout.total)
	}
}

func TestTrainMarkovThresholdShrinksRadix(t *testing.T) {
	dir := t.TempDir()
	wl := dir + "/t.txt"
	if err := os.WriteFile(wl, []byte("abc\ncab\nbca\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := trainMarkov("abc", wl, 2)
	if err != nil {
		t.Fatal(err)
	}
	if m.radix != 2 {
		t.Fatalf("radix = %d, want 2", m.radix)
	}
	if len(m.first) != 2 || len(m.cond['a']) != 2 {
		t.Fatalf("ranked lists were not truncated to the threshold")
	}
}
```

(this file's import block is `import ("os"; "testing")` — matching `markov_test.go`'s own style, which already writes wordlist fixtures the same way.)

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `go test ./internal/smith/ -run 'TestMarkovRadix|TestLoadHCStat2|TestTrainMarkovThreshold' -v`
Expected: FAIL — `markovRadix`/`loadHCStat2`/`m.positional`/`m.radix`/`m.posFirst`/`m.posCond` undefined, `trainMarkov` wrong arg count.

- [ ] **Step 4: Implement**

In `internal/smith/markov.go`, extend the struct:

```go
type markovModel struct {
	charset    []byte
	positional bool
	// radix is the resolved per-position choice count after threshold
	// truncation — len(first) / len(posFirst[0]), computed once at build
	// time and used directly by decode/markovLayout so both always agree
	// with what was actually built, never re-derived from a separate
	// threshold field.
	radix int

	// live -w-trained path:
	first []byte
	cond  [256][]byte

	// hcstat2-loaded path:
	posFirst [256][]byte
	posCond  [256][256][]byte
}

// markovRadix resolves --markov-threshold against a domain size: threshold
// <= 0 means unlimited (keep the whole domain); otherwise the smaller of
// the two.
func markovRadix(threshold, domainSize int) int {
	if threshold <= 0 || threshold > domainSize {
		return domainSize
	}
	return threshold
}
```

Change `trainMarkov`'s signature and the two `rankCharset` call sites:

```go
func trainMarkov(charset string, wordlistPath string, threshold int) (*markovModel, error) {
```

(body unchanged down to the model construction at the end, then):

```go
	radix := markovRadix(threshold, len(cs))
	m := &markovModel{charset: cs, radix: radix}
	m.first = rankCharset(cs, &firstCount)[:radix]
	for _, c := range cs {
		tc := transCount[c]
		m.cond[c] = rankCharset(cs, &tc)[:radix]
	}
	return m, nil
```

Add `loadHCStat2`:

```go
// loadHCStat2 builds a positional markovModel from a real .hcstat2 file —
// see the design doc's §5 for why every node's ranked list is a uniform
// markovRadix(threshold, 256) long with no padding needed: root/markov are
// already dense over all 256 byte values, so ranking always yields a full
// 256-entry permutation regardless of how sparse the underlying counts are.
func loadHCStat2(path string, threshold int) (*markovModel, error) {
	tables, err := loadHCStat2Tables(path)
	if err != nil {
		return nil, err
	}
	var allBytes [256]byte
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	radix := markovRadix(threshold, 256)
	m := &markovModel{charset: allBytes[:], positional: true, radix: radix}
	for pos := 0; pos < 256; pos++ {
		m.posFirst[pos] = rankCharset(allBytes[:], &tables.root[pos])[:radix]
		for prev := 0; prev < 256; prev++ {
			m.posCond[pos][prev] = rankCharset(allBytes[:], &tables.markov[pos][prev])[:radix]
		}
	}
	return m, nil
}
```

Change `decode` to branch on `positional` and use `m.radix` instead of `len(m.charset)`:

```go
func (m *markovModel) decode(idx int64, L int) string {
	base := int64(m.radix)
	digits := make([]int, L)
	for p := L - 1; p >= 0; p-- {
		digits[p] = int(idx % base)
		idx /= base
	}
	out := make([]byte, L)
	var prev byte
	for p := 0; p < L; p++ {
		var ranked []byte
		switch {
		case m.positional && p == 0:
			ranked = m.posFirst[0]
		case m.positional:
			ranked = m.posCond[p-1][prev]
		case p == 0:
			ranked = m.first
		default:
			ranked = m.cond[prev]
		}
		out[p] = ranked[digits[p]]
		prev = out[p]
	}
	return string(out)
}
```

Change `markovLayout`'s `base` the same way (it independently recomputes the per-length keyspace size, and must agree with `decode`):

```go
func markovLayout(m *markovModel, minLen, maxLen int) *keyspaceLayout {
	base := int64(m.radix)
	// ... rest of the function body is unchanged (it only ever used `base`
	// as a plain int64, never touched m.charset again below this line).
}
```

Finally, update the one production call site in `crack.go` (the `case "markov":` in `doCrack`, which today reads `trainMarkov(charset, wordlist)`) to pass `0` for now — Task 4 replaces this `0` with the real `--markov-threshold` value:

```go
		model, e := trainMarkov(charset, wordlist, 0)
```

- [ ] **Step 5: Run all markov tests to verify they pass**

Run: `go test ./internal/smith/ -run 'TestMarkov|TestLoadHCStat2|TestTrainMarkov' -v`
Expected: PASS — every test from this task and Task 1/2, plus the original `TestMarkovBijection`/`TestMarkovOrdersLikelyFirst` (proving the non-positional path is behavior-preserving: `radix == len(charset)` when `threshold` is `0`, identical to today's `base := int64(len(m.charset))`).

- [ ] **Step 6: Run the full package test suite once, since this touches a shared function (`decode`/`markovLayout`) other tests may exercise indirectly**

Run: `go test ./internal/smith/... 2>&1 | tail -20`
Expected: `ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/smith/markov.go internal/smith/markov_test.go internal/smith/markov_positional_test.go
git commit -m "feat(markov): positional model loadable from a real .hcstat2 file

Adds loadHCStat2 (builds a positional markovModel from the decoded
hcstat2 tables) and markovRadix (--markov-threshold's clamp, shared by
both the live-trained and hcstat2 paths). decode/markovLayout now read
the resolved radix instead of len(charset), which is behavior-preserving
for every existing caller since radix == len(charset) whenever no
threshold is set."
```

---

### Task 4: CLI wiring — `--hcstat2`, `--markov-threshold`

**Files:**
- Modify: `internal/smith/crack.go`

**Interfaces:**
- Consumes: `trainMarkov(charset, wordlistPath string, threshold int)`, `loadHCStat2(path string, threshold int)`, `markovRadix(threshold, domainSize int) int` (Task 3).
- Produces: `crackCtx.hcstat2 string` / `.markovThreshold int` fields, read by nothing outside this file.

- [ ] **Step 1: Add the two new `crackCtx` fields**

Near the existing `princeElems int` field (`crack.go`, `type crackCtx struct`), add:

```go
	// hcstat2 is --hcstat2: a path to a real hashcat-compatible positional
	// Markov statistics file, used by -a markov instead of live-training
	// from -w. "" means unset (today's live-trained behavior).
	hcstat2 string
	// markovThreshold is --markov-threshold: keep only the top-N most
	// likely bytes at each Markov position/node. 0 = unlimited, applies to
	// both the hcstat2 path and the live-trained path.
	markovThreshold int
```

- [ ] **Step 2: Declare the two new flags**

Near `princeElems := fs.Int(...)` (same flag block), add:

```go
	hcstat2Flag := fs.String("hcstat2", "", "path to a hashcat-compatible .hcstat2 file (markov mode; loads real positional statistics instead of training live from -w)")
	markovThreshold := fs.Int("markov-threshold", 0, "markov mode: keep only the top-N most likely bytes at each position (0 = unlimited)")
```

- [ ] **Step 3: Thread the two new fields through `newCrackCtx`, and wire the mutual-exclusion / wordlist-resolution bypass**

Change `newCrackCtx`'s signature and the one line that constructs `cc`:

```go
func newCrackCtx(potPath string, noPot bool, sessName string, showOnly bool, wordlist2 string, useGPU bool, skip, limit int64, hcstat2 string, markovThreshold int) (*crackCtx, error) {
	cc := &crackCtx{sessName: sessName, showOnly: showOnly, wordlist2: wordlist2, useGPU: useGPU, skip: skip, limit: limit, hcstat2: hcstat2, markovThreshold: markovThreshold}
```

Update both existing call sites:

```go
	cc, err := newCrackCtx(*potPath, *noPot, sn, *showOnly, wl2, *useGPU, *skip, *limit, *hcstat2Flag, *markovThreshold)
```

(the real CLI path — `hcstat2Flag`/`markovThreshold` are the flags Step 2 just declared), and:

```go
	cc, _ := newCrackCtx("", false, "", false, "", false, 0, 0, "", 0)
```

(the internal/self-test helper call site — unaffected by this feature, passes the zero values).

Then, at the wordlist-resolution site (where `wlChoice, err := resolveWordlistForMode(...)` is called today), wrap it:

```go
	var wlChoice wordlistChoice
	if strings.EqualFold(*mode, "markov") && *hcstat2Flag != "" {
		if wl != "" {
			return errors.New("markov mode: --hcstat2 and -w are mutually exclusive")
		}
	} else {
		var err error
		wlChoice, err = resolveWordlistForMode(*mode, wl, *noAutoWordlist)
		if err != nil {
			return err
		}
		wl = wlChoice.path

		if warn := distributedWordlistWarning(wlChoice, *skip, *limit, *keyspaceOnly); warn != "" {
			clrYellow.Fprintln(os.Stderr, warn)
		}
	}
```

(this replaces the existing three-line `resolveWordlistForMode` call plus the `distributedWordlistWarning` block immediately after it — both move inside the `else`).

- [ ] **Step 4: Update `printKeyspace`'s call site and signature**

Call site:

```go
		return printKeyspace(*mode, wl, wl2, *charset, *minLen, *maxLen, *princeElems, mc, *hcstat2Flag, *markovThreshold)
```

Signature and the `"brute", "markov"` case (split apart, since markov's total now depends on the threshold/hcstat2 domain rather than always equaling brute's):

```go
func printKeyspace(mode, wordlist, wordlist2, charset string, minLen, maxLen, princeElems int, mc *maskConfig, hcstat2 string, markovThreshold int) error {
	m := strings.ToLower(mode)
	var exact *big.Int
	switch m {
	case "brute":
		if minLen < 1 || maxLen < minLen {
			return errors.New("invalid -n/-x range")
		}
		exact, _ = calcBruteTotalExact(charset, minLen, maxLen)
	case "markov":
		if minLen < 1 || maxLen < minLen {
			return errors.New("invalid -n/-x range")
		}
		domain := len([]rune(charset))
		if hcstat2 != "" {
			domain = 256
		}
		radix := markovRadix(markovThreshold, domain)
		exact, _ = calcBruteTotalExact(strings.Repeat("x", radix), minLen, maxLen)
```

(every other case in the switch — `"mask"`, `"hybrid"`, `"combinator"`, `"prince"`, `"dict"`, `default` — is unchanged).

- [ ] **Step 5: Update `doCrack`'s `"markov"` case to pick the right source**

```go
	case "markov":
		if minLen < 1 || maxLen < minLen {
			tickCancel()
			return false, errors.New("invalid -n/-x range")
		}
		var model *markovModel
		var e error
		threshold := 0
		if cc != nil {
			threshold = cc.markovThreshold
		}
		if cc != nil && cc.hcstat2 != "" {
			model, e = loadHCStat2(cc.hcstat2, threshold)
		} else {
			model, e = trainMarkov(charset, wordlist, threshold)
		}
		if e != nil {
			tickCancel()
			return false, e
		}
		var pw string
		pw, interrupted, err = runSessionLayout(runCtx, markovLayout(model, minLen, maxLen),
			sess, resumeFrom, limit, workers, &atomicAttempts, verifyFn)
		result = crackedResult{password: pw, found: pw != ""}
```

- [ ] **Step 6: Build and run the full package test suite**

Run: `go build ./... && go test ./internal/smith/... 2>&1 | tail -20`
Expected: builds clean, `ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/smith/crack.go
git commit -m "feat(markov): wire --hcstat2 and --markov-threshold into -a markov

--hcstat2 <path> loads a real hashcat-compatible positional statistics
file instead of training live from -w (mutually exclusive with it).
--markov-threshold N caps every position's ranked charset to the top N,
shrinking the keyspace; applies to both paths. --keyspace's markov case
now accounts for both, split out from brute's (which never had a
threshold to begin with)."
```

---

### Task 5: End-to-end integration test

**Files:**
- Create: `internal/smith/markov_hcstat2_e2e_test.go`

**Interfaces:**
- Consumes: everything above; exercises the CLI-level `doCrack`/`verifyCandidate` path (or the lowest-level equivalent already used by this project's own end-to-end tests — check `crack_test.go` or similar for the established pattern, e.g. how `TestMarkovBijection`'s sibling tests in this package invoke a full crack).

- [ ] **Step 1: Confirm the established end-to-end pattern in this codebase**

Run: `grep -n "func doCrack\|func TestDoCrack\|runSessionLayout(" internal/smith/*_test.go | head -20`

Use whatever pattern an existing brute/mask end-to-end test already follows (likely a direct `doCrack(...)` call against a `pbkdf2`/plain-hash target, or a `verifyCandidate`-based loop) — do not invent a new harness shape for this one test.

- [ ] **Step 2: Write the failing test**

```go
// internal/smith/markov_hcstat2_e2e_test.go
package smith

import "testing"

// TestMarkovHCStat2FindsTrainedPassword loads the committed real .hcstat2
// fixture (trained on "aab", "aac", "aad", "zzz") and confirms a brute-force
// walk ordered by it finds "aab" — and reaches it well before the
// lexicographic position brute force would, proving the ranking is doing
// real work rather than just passing candidates through unchanged.
func TestMarkovHCStat2FindsTrainedPassword(t *testing.T) {
	m, err := loadHCStat2("testdata/hcstat2_sample.hcstat2", 0)
	if err != nil {
		t.Fatalf("loadHCStat2: %v", err)
	}
	layout := markovLayout(m, 3, 3)

	target := "aab"
	foundAt := int64(-1)
	for i := int64(0); i < layout.total; i++ {
		if layout.candidate(i) == target {
			foundAt = i
			break
		}
	}
	if foundAt < 0 {
		t.Fatalf("markov layout never produced %q across its full keyspace (total=%d)", target, layout.total)
	}

	// Plain lexicographic brute force over the same 256-byte domain would
	// reach "aab" at index 'a'*256*256 + 'a'*256 + 'b' — astronomically
	// larger than where the trained ranking should place it, since 'a'
	// dominates positions 0 and 1 in the training data.
	lexicographicIndex := int64('a')*256*256 + int64('a')*256 + int64('b')
	if foundAt >= lexicographicIndex {
		t.Errorf("markov ranking did not surface %q earlier than lexicographic brute force would (found at %d, lexicographic at %d)",
			target, foundAt, lexicographicIndex)
	}
}
```

Adjust the harness/assertions in Step 2 to match whatever Step 1 found as this project's established end-to-end shape, if it differs from the direct `markovLayout`/`candidate` walk above (that walk is itself a legitimate, self-contained end-to-end check of the whole load→rank→enumerate path, so keep it even if a fuller `doCrack`-level test is added alongside).

- [ ] **Step 3: Run the test to verify it fails (or passes if Task 3/4 already cover this) — either is informative**

Run: `go test ./internal/smith/ -run TestMarkovHCStat2FindsTrainedPassword -v`
Expected: PASS if Tasks 1–3 are correct (this test exercises no new production code, only confirms the whole pipeline's observable behavior) — if it fails, the bug is in Task 1–3's code, not this test; debug there before proceeding.

- [ ] **Step 4: Run the full package suite one more time**

Run: `go test ./internal/smith/... 2>&1 | tail -20`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/smith/markov_hcstat2_e2e_test.go
git commit -m "test(markov): end-to-end check that hcstat2 ranking surfaces trained passwords early"
```
