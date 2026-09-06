# bcrypt Lane Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Hashsmith the fastest CPU bcrypt cracker of the three tools by hashing several candidates through interleaved Blowfish lanes in one goroutine, reaching >= 887 c/s single-thread at cost 5 against today's 302.

**Architecture:** A new `internal/bcryptlane` package vendors `x/crypto/blowfish` (its cipher state fields are unexported, so lanes cannot be driven through the public API) and adds a generated key schedule that advances N independent candidates through each Feistel round together. Two existing batching call sites consume it: the `dictAttack` worker, and a new eligibility predicate alongside `fastPathEligible`/`stdPathEligible` in `runBruteOrMaskLayout`.

**Tech Stack:** Go 1.25, `golang.org/x/crypto v0.31.0` (vendored, BSD-3-Clause), Python 3 for the code generator, `go test -bench`.

**Spec:** `docs/superpowers/specs/2026-09-06-bcrypt-lanes-design.md`

## Global Constraints

- Module root for all Go paths: `hashsmith/go_hashsmith/`. Run every `go` command from there.
- Go version floor: `go 1.25.0` (`go.mod`). No new module dependencies — `golang.org/x/crypto v0.31.0` is already required.
- Vendored code keeps its original copyright header verbatim and names the exact upstream version it came from.
- Scope is the bare `bcrypt` type, **single target only**. Do not touch multi-hash/dump paths (`batch.go`), and do not touch the composite formats that call `bcrypt.CompareHashAndPassword` from `crack_django.go`, `crack_hashcat_more_records.go`, `crack_hashcat_vendor_records.go`.
- Correctness contract is **parity with `golang.org/x/crypto/bcrypt@v0.31.0`**, not with any C bcrypt. Where x/crypto has bug-compatibility quirks (the trailing-NUL key byte, encoding only 23 of 24 bytes, no 72-byte key truncation, identical handling of all `$2?$` minor versions), reproduce x/crypto exactly. Never "fix" a quirk.
- Performance claims in docs must be measured, stated with the machine, and never rounded in Hashsmith's favour — matching the practice in `docs/superpowers/notes/`.
- `go build ./...` and `go vet ./...` must pass at the end of every task.

---

### Task 1: Establish the real bottleneck before writing any core

The spec's §2 states a hypothesis (store-to-load forwarding pressure) and explicitly refuses to assume it. This task replaces the hypothesis with a measurement, and — more importantly — proves that interleaving lanes actually helps *before* anyone builds a generator around the idea. If a 2-lane spike shows no gain, the whole plan needs rethinking and it is far cheaper to learn that here.

Everything built in this task is **throwaway**. Nothing lands in the repo except a note.

**Files:**
- Create (throwaway, outside the repo): `/tmp/bclane-spike/`
- Create: `docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md`

> **Pre-measurement from the planning session (2026-09-06, Apple M2).** The
> generator in Task 4 was extracted from this plan, run, and differential-tested
> against upstream before the plan was committed: `encryptBlock2`/`encryptBlock4`
> are bit-identical to N independent `encryptBlock` calls, and `expandKey2` and
> `expandKeyWithSalt2` leave state identical to upstream. Cipher-level throughput,
> best of three, each benchmark performing 512 block encryptions per op:
>
> | | ns/op | speedup |
> |---|---|---|
> | serial | 49,379 | 1.00x |
> | 2 lanes | 26,179 | 1.89x |
> | **4 lanes** | **23,000** | **2.15x** |
> | 8 lanes | 24,446 | 2.02x |
>
> Two things follow. **The go/no-go in Step 7 is already cleared** — 2 lanes buy
> 1.89x against a 1.35x threshold — so Task 1 is now a confirmation on the real
> bcrypt path rather than a gate that might stop the work. And **4 lanes is the
> likely winner**, with 8 measurably worse, so Task 5's tuning has a prior.
>
> The number that matters, stated plainly: 2.15x applied to the 302 c/s baseline
> projects to roughly **649 c/s** — which beats John's 591 but falls short of the
> 887 the spec's §2 target requires. This is a cipher-level microbenchmark, not
> the real path: it omits the store traffic `ExpandKey` generates between
> encryptions (which lanes should hide, pushing the real number up) and it omits
> the cache pressure of four lanes' 16 KB of *mutating* state (which pushes it
> down). Task 1 measures the real thing. But an executor should start knowing
> that spec §8's risk looks likely to materialize, and that the honest outcome
> may be "beats John, misses the margin" — which is a bar decision for the
> author, not a failure to engineer around.

**Interfaces:**
- Consumes: nothing.
- Produces: a go/no-go decision and a measured single-lane baseline in ns/op at cost 5, which Task 5's ratchet is set against.

- [ ] **Step 1: Create the spike module**

```bash
mkdir -p /tmp/bclane-spike && cd /tmp/bclane-spike
cp "$(go env GOMODCACHE)"/golang.org/x/crypto@v0.31.0/blowfish/*.go .
rm -f blowfish_test.go
chmod +w *.go
sed -i '' 's/^package blowfish$/package spike/' *.go
cat > go.mod <<'EOF'
module spike

go 1.25.0
EOF
```

- [ ] **Step 2: Add a hand-written 2-lane round-interleaved encryptBlock**

Create `/tmp/bclane-spike/lane2.go`. This interleaves at the *round* level, not the call level — that distinction is the entire point, so do not simplify it into two sequential `encryptBlock` calls.

```go
package spike

// encryptBlock2 advances two independent ciphers through all 16 Feistel rounds
// together, so each lane's four S-box loads issue while the other lane's
// dependent chain is still resolving.
func encryptBlock2(l0, r0 uint32, c0 *Cipher, l1, r1 uint32, c1 *Cipher) (uint32, uint32, uint32, uint32) {
	xl0, xr0 := l0, r0
	xl1, xr1 := l1, r1
	xl0 ^= c0.p[0]
	xl1 ^= c1.p[0]
	for i := 1; i <= 15; i += 2 {
		xr0 ^= ((c0.s0[byte(xl0>>24)] + c0.s1[byte(xl0>>16)]) ^ c0.s2[byte(xl0>>8)]) + c0.s3[byte(xl0)] ^ c0.p[i]
		xr1 ^= ((c1.s0[byte(xl1>>24)] + c1.s1[byte(xl1>>16)]) ^ c1.s2[byte(xl1>>8)]) + c1.s3[byte(xl1)] ^ c1.p[i]
		xl0 ^= ((c0.s0[byte(xr0>>24)] + c0.s1[byte(xr0>>16)]) ^ c0.s2[byte(xr0>>8)]) + c0.s3[byte(xr0)] ^ c0.p[i+1]
		xl1 ^= ((c1.s0[byte(xr1>>24)] + c1.s1[byte(xr1>>16)]) ^ c1.s2[byte(xr1>>8)]) + c1.s3[byte(xr1)] ^ c1.p[i+1]
	}
	xr0 ^= c0.p[16]
	xr1 ^= c1.p[16]
	// mirrors encryptBlock's final swap and p[17] fold
	xl0, xr0 = xr0, xl0^c0.p[17]
	xl1, xr1 = xr1, xl1^c1.p[17]
	return xl0, xr0, xl1, xr1
}
```

Note the loop here is a spike convenience. Task 4 generates fully unrolled code, because the loop-carried compare/branch competes with the lanes for issue slots.

- [ ] **Step 3: Write the spike benchmark**

Create `/tmp/bclane-spike/spike_test.go`:

```go
package spike

import "testing"

// expandKey1 is upstream ExpandKey, for the serial baseline.
func benchExpand(b *testing.B, lanes int) {
	key := []byte("w000123\x00")
	c0 := &Cipher{}
	c1 := &Cipher{}
	initCipher(c0)
	initCipher(c1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var l0, r0, l1, r1 uint32
		if lanes == 1 {
			for j := 0; j < 521*2; j++ {
				l0, r0 = encryptBlock(l0, r0, c0)
			}
		} else {
			for j := 0; j < 521; j++ {
				l0, r0, l1, r1 = encryptBlock2(l0, r0, c0, l1, r1, c1)
			}
		}
		_, _, _, _ = l0, r0, l1, r1
	}
	_ = key
}

func BenchmarkSerial521x2(b *testing.B) { benchExpand(b, 1) }
func BenchmarkLane2_521(b *testing.B)   { benchExpand(b, 2) }
```

Both benchmarks perform 1042 block encryptions per iteration, so their ns/op are directly comparable.

- [ ] **Step 4: Verify the 2-lane version is bit-identical to two serial calls**

Add to `spike_test.go`:

```go
func TestLane2MatchesSerial(t *testing.T) {
	c0, c1 := &Cipher{}, &Cipher{}
	initCipher(c0)
	initCipher(c1)
	ExpandKey([]byte("alpha\x00"), c0)
	ExpandKey([]byte("bravo\x00"), c1)

	w0, x0 := encryptBlock(0x01234567, 0x89abcdef, c0)
	w1, x1 := encryptBlock(0x01234567, 0x89abcdef, c1)

	g0, h0, g1, h1 := encryptBlock2(0x01234567, 0x89abcdef, c0, 0x01234567, 0x89abcdef, c1)
	if g0 != w0 || h0 != x0 || g1 != w1 || h1 != x1 {
		t.Fatalf("lane2 diverged: got (%08x %08x)(%08x %08x) want (%08x %08x)(%08x %08x)",
			g0, h0, g1, h1, w0, x0, w1, x1)
	}
}
```

Run: `cd /tmp/bclane-spike && go test -run TestLane2MatchesSerial -v`
Expected: PASS. If it FAILS, the round-interleaved rewrite has an indexing or swap error — fix it before benchmarking, because a fast wrong answer proves nothing.

- [ ] **Step 5: Measure**

```bash
cd /tmp/bclane-spike && go test -bench=. -benchtime=3s -run='^$' -count=3
```

Record all three runs of each. Compute `BenchmarkSerial521x2 ns/op ÷ BenchmarkLane2_521 ns/op` — the 2-lane speedup.

- [ ] **Step 6: Measure the single-lane cost-5 baseline for the ratchet**

```bash
cd /tmp/bclane-spike && cat > base_test.go <<'EOF'
package spike

import "testing"

func BenchmarkCost5Serial(b *testing.B) {
	key := []byte("w000123\x00")
	salt := []byte("0123456789abcdef")
	for i := 0; i < b.N; i++ {
		c, _ := NewSaltedCipher(key, salt)
		for j := 0; j < 32; j++ {
			ExpandKey(key, c)
			ExpandKey(salt, c)
		}
	}
}
EOF
go test -bench=Cost5Serial -benchtime=3s -run='^$' -count=3
```

- [ ] **Step 7: Write the note and decide**

Create `docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md` recording: the machine and core count, all raw benchmark runs verbatim (not just the best), the computed 2-lane speedup, the cost-5 baseline in ns/op and c/s, and an explicit go/no-go.

**Go/no-go rule, decided in advance so the result cannot be rationalized:** a 2-lane speedup of **>= 1.35x** proceeds to Task 2. Below that, stop and report — two lanes buying less than 1.35x means four will not reach 2.94x, and the spec's §8 assembly decision needs revisiting first. State the number plainly either way.

- [ ] **Step 8: Commit the note**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md
git commit -m "docs: measure the bcrypt lane hypothesis before building on it"
```

---

### Task 2: Vendor Blowfish into `internal/bcryptlane`

**Files:**
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/blowfish.go`
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/const.go`
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/blowfish_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `type state struct { p [18]uint32; s0, s1, s2, s3 [256]uint32 }`, `func initState(*state)`, `func expandKey(key []byte, c *state)`, `func expandKeyWithSalt(key, salt []byte, c *state)`, `func encryptBlock(l, r uint32, c *state) (uint32, uint32)`, `func nextWord(b []byte, pos int) uint32`, `func saltWord(salt []byte, pos int) uint32`. All unexported — Task 3 wraps them.

- [ ] **Step 1: Copy the upstream source**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith/hashsmith/go_hashsmith
mkdir -p internal/bcryptlane
UP="$(go env GOMODCACHE)/golang.org/x/crypto@v0.31.0/blowfish"
cp "$UP/block.go" internal/bcryptlane/blowfish.go
cp "$UP/const.go" internal/bcryptlane/const.go
chmod +w internal/bcryptlane/*.go
```

Do **not** copy `cipher.go`. Its `Encrypt`/`Decrypt` take byte slices, carry 32 of the package's 45 bounds checks, and bcrypt's inner loop never calls them. `NewSaltedCipher`'s logic is reproduced by hand in Step 3.

- [ ] **Step 2: Rename the package and the cipher type**

In both files change `package blowfish` to `package bcryptlane`. In `blowfish.go` replace every `*Cipher` with `*state` and every `c.p`/`c.s0`..`c.s3` stays as-is. Delete `decryptBlock` — nothing calls it, and dead code in a hot package invites confusion.

Add above the package clause in `blowfish.go`:

```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is vendored from golang.org/x/crypto/blowfish@v0.31.0 (block.go),
// with the Cipher type renamed to state, decryptBlock removed, and the package
// renamed.
//
// WHY THIS IS VENDORED RATHER THAN IMPORTED: bcrypt's cost is 34,057 Blowfish
// block encryptions, and the only way to make that faster on a CPU is to drive
// several independent candidates through each Feistel round together (see
// eks_lanes.go). blowfish.Cipher's p and s0..s3 fields are unexported, so the
// public ExpandKey(key, *Cipher) API can only advance one candidate at a time.
// Interleaving requires reaching inside the state, which requires owning it.
```

Put the same copyright header (naming `const.go`) at the top of `const.go`.

- [ ] **Step 3: Add the state constructor**

Append to `blowfish.go`:

```go
// newSaltedState reproduces blowfish.NewSaltedCipher for bcrypt's use: a key of
// any length (bcrypt keys routinely exceed Blowfish's nominal 56-byte maximum)
// and a non-empty salt. It returns nil for an empty key, matching upstream's
// KeySizeError case, which bcrypt never reaches because it always appends a
// trailing NUL.
func newSaltedState(key, salt []byte) *state {
	if len(key) < 1 {
		return nil
	}
	var c state
	initState(&c)
	expandKeyWithSalt(key, salt, &c)
	return &c
}
```

Rename the copied `initCipher` to `initState`.

- [ ] **Step 3b: Add the position-addressed word readers**

Upstream's `getNextWord(b []byte, pos *int)` mutates a caller-held cursor. The
generated lane code (Task 4) cannot share one cursor across lanes, so it needs a
version addressed by absolute position instead. These are exact behavioural
equivalents, not reinterpretations.

Append to `blowfish.go`:

```go
// nextWord reads four bytes big-endian from b starting at pos, wrapping
// circularly, which is what upstream getNextWord does with a running cursor.
// Upstream advances the cursor by exactly 4 per call, so the cursor before
// call i is (4*i) mod len(b) — hence an absolute position is equivalent and
// lets several lanes read their own keys independently.
func nextWord(b []byte, pos int) uint32 {
	j := pos % len(b)
	var w uint32
	for i := 0; i < 4; i++ {
		w = w<<8 | uint32(b[j])
		j++
		if j >= len(b) {
			j = 0
		}
	}
	return w
}

// saltWord is nextWord for the salt. It is a separate name only so the
// generated code reads clearly at the call site; the semantics are identical.
func saltWord(salt []byte, pos int) uint32 { return nextWord(salt, pos) }
```

- [ ] **Step 3c: Prove the readers match upstream**

Add to `blowfish_test.go`:

```go
// TestNextWordMatchesCursor pins the absolute-position readers to upstream's
// cursor semantics, including the wrap that happens mid-word for key lengths
// that are not multiples of four.
func TestNextWordMatchesCursor(t *testing.T) {
	for _, key := range [][]byte{[]byte("a"), []byte("abc"), []byte("abcd"), []byte("seven77"), []byte("password\x00")} {
		j := 0
		for i := 0; i < 18; i++ {
			// upstream's inlined cursor read
			var want uint32
			for k := 0; k < 4; k++ {
				want = want<<8 | uint32(key[j])
				j++
				if j >= len(key) {
					j = 0
				}
			}
			if got := nextWord(key, i*4); got != want {
				t.Errorf("key %q word %d: nextWord = %08x, cursor = %08x", key, i, got, want)
			}
		}
	}
}
```

- [ ] **Step 4: Write the parity test**

Create `internal/bcryptlane/blowfish_test.go`:

```go
package bcryptlane

import (
	"testing"

	"golang.org/x/crypto/blowfish"
)

// TestVendoredMatchesUpstream pins the vendored copy to the library it replaces.
// Any divergence here is a transcription error, and every later test in this
// package would inherit it.
func TestVendoredMatchesUpstream(t *testing.T) {
	keys := [][]byte{[]byte("a\x00"), []byte("password\x00"), []byte("a much longer key than blowfish nominally accepts, well past 56 bytes\x00")}
	salt := []byte("0123456789abcdef")

	for _, key := range keys {
		up, err := blowfish.NewSaltedCipher(key, salt)
		if err != nil {
			t.Fatalf("upstream rejected key %q: %v", key, err)
		}
		got := newSaltedState(key, salt)
		if got == nil {
			t.Fatalf("newSaltedState returned nil for key %q", key)
		}
		// Drive both through the same schedule bcrypt uses, then compare
		// ciphertext rather than reaching into upstream's unexported state.
		for j := 0; j < 4; j++ {
			blowfish.ExpandKey(key, up)
			expandKey(key, got)
			blowfish.ExpandKey(salt, up)
			expandKey(salt, got)
		}
		src := []byte("OrpheanB")
		wantBuf := make([]byte, 8)
		up.Encrypt(wantBuf, src)

		l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
		r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
		gl, gr := encryptBlock(l, r, got)
		gotBuf := []byte{
			byte(gl >> 24), byte(gl >> 16), byte(gl >> 8), byte(gl),
			byte(gr >> 24), byte(gr >> 16), byte(gr >> 8), byte(gr),
		}
		if string(gotBuf) != string(wantBuf) {
			t.Errorf("key %q: vendored %x, upstream %x", key, gotBuf, wantBuf)
		}
	}
}
```

- [ ] **Step 5: Run it**

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -run 'TestVendoredMatchesUpstream|TestNextWordMatchesCursor' -v`
Expected: PASS. A failure means a transcription slip in Step 2 — most likely a missed `Cipher`→`state` rename or a dropped line from `expandKeyWithSalt`'s four 256-entry loops.

- [ ] **Step 6: Commit**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add hashsmith/go_hashsmith/internal/bcryptlane/
git commit -m "feat(bcryptlane): vendor blowfish so lanes can reach the cipher state"
```

---

### Task 3: The `Hasher` API at one lane, differential-tested

Correctness first, speed later. This task produces a working bcrypt verifier with no interleaving at all, so Task 4's optimization has an oracle inside its own package.

**Files:**
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/bcrypt.go`
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/bcrypt_test.go`

**Interfaces:**
- Consumes: `state`, `initState`, `expandKey`, `expandKeyWithSalt`, `encryptBlock`, `newSaltedState` from Task 2.
- Produces:
  - `func NewHasher(crypt string) (*Hasher, error)`
  - `func (h *Hasher) Run(pw [][]byte, out []bool)`
  - `const Lanes int` (value `1` in this task; Task 5 tunes it)
  - `func (h *Hasher) Cost() int`

- [ ] **Step 1: Write the failing differential test**

Create `internal/bcryptlane/bcrypt_test.go`:

```go
package bcryptlane

import (
	"bytes"
	"math/rand"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// randPassword returns the awkward cases on purpose: bcrypt's bug-compatible
// trailing NUL, its circular key reuse, and its 23-of-24-byte encoding all show
// up at boundaries, not in the middle.
func randPassword(rng *rand.Rand) []byte {
	switch rng.Intn(8) {
	case 0:
		return []byte{}
	case 1:
		return []byte("a")
	case 2:
		return bytes.Repeat([]byte("x"), 72)
	case 3:
		return bytes.Repeat([]byte("y"), 100)
	case 4:
		return []byte("pass\x00word")
	case 5:
		return []byte("pässwörd–ünïcode")
	default:
		n := 1 + rng.Intn(40)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(33 + rng.Intn(94))
		}
		return b
	}
}

func TestRunMatchesXCrypto(t *testing.T) {
	rng := rand.New(rand.NewSource(20260906))
	for i := 0; i < 300; i++ {
		cost := 4 + rng.Intn(3) // 4..6 keeps the suite fast; costs 7-10 in TestRunMatchesXCryptoSlow
		pw := randPassword(rng)
		crypt, err := bcrypt.GenerateFromPassword(pw, cost)
		if err != nil {
			t.Fatalf("GenerateFromPassword(%q, %d): %v", pw, cost, err)
		}
		h, err := NewHasher(string(crypt))
		if err != nil {
			t.Fatalf("NewHasher(%q): %v", crypt, err)
		}
		out := make([]bool, 1)
		h.Run([][]byte{pw}, out)
		if !out[0] {
			t.Errorf("case %d: correct password %q rejected for %s", i, pw, crypt)
		}
		wrong := append(append([]byte{}, pw...), '!')
		h.Run([][]byte{wrong}, out)
		want := bcrypt.CompareHashAndPassword(crypt, wrong) == nil
		if out[0] != want {
			t.Errorf("case %d: %q against %s: got %v, x/crypto says %v", i, wrong, crypt, out[0], want)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -run TestRunMatchesXCrypto -v`
Expected: FAIL — `undefined: NewHasher`.

- [ ] **Step 3: Implement `bcrypt.go`**

```go
package bcryptlane

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
)

// Lanes is the interleave width: the maximum number of candidates Run hashes in
// one pass. Tuned by measurement in docs/superpowers/notes/, not by guesswork.
const Lanes = 1

// bcrypt's own base64 alphabet, which is not the standard one.
const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(alphabet).WithPadding(base64.NoPadding)

// magicCipherData is the plaintext bcrypt encrypts 64 times:
// "OrpheanBeholderScryDoubt".
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44, 0x6f, 0x75, 0x62, 0x74,
}

var errInvalidHash = errors.New("bcryptlane: not a bcrypt crypt string")

// Hasher is one parsed bcrypt target. Parsing happens once; Run is the hot path.
type Hasher struct {
	cost   int
	csalt  [16]byte
	digest [23]byte
}

// NewHasher parses a $2?$cc$<22-char salt><31-char digest> crypt string.
// It accepts exactly what x/crypto/bcrypt's newFromHash accepts, including
// every minor version, because parity with x/crypto is this package's contract.
func NewHasher(crypt string) (*Hasher, error) {
	if len(crypt) < 59 || crypt[0] != '$' || crypt[1] != '2' {
		return nil, errInvalidHash
	}
	i := 2
	if crypt[i] != '$' {
		i++ // minor version letter
	}
	if i >= len(crypt) || crypt[i] != '$' {
		return nil, errInvalidHash
	}
	i++
	if i+2 >= len(crypt) || crypt[i+2] != '$' {
		return nil, errInvalidHash
	}
	cost, err := strconv.Atoi(crypt[i : i+2])
	if err != nil {
		return nil, errInvalidHash
	}
	if cost < 4 || cost > 31 {
		return nil, errInvalidHash
	}
	rest := crypt[i+3:]
	if len(rest) != 53 {
		return nil, errInvalidHash
	}
	saltRaw, err := bcEncoding.DecodeString(rest[:22])
	if err != nil || len(saltRaw) < 16 {
		return nil, errInvalidHash
	}
	digRaw, err := bcEncoding.DecodeString(rest[22:])
	if err != nil || len(digRaw) < 23 {
		return nil, errInvalidHash
	}
	h := &Hasher{cost: cost}
	copy(h.csalt[:], saltRaw[:16])
	copy(h.digest[:], digRaw[:23])
	return h, nil
}

// Cost reports the target's cost factor.
func (h *Hasher) Cost() int { return h.cost }

// Run hashes each pw[i] against the target and writes the verdict to out[i].
// len(pw) must be <= Lanes and len(out) must be >= len(pw). A short pw slice is
// handled without padding: padding would spend a full bcrypt computation on a
// dummy candidate, which at cost 12 is the dominant cost of a partial batch.
func (h *Hasher) Run(pw [][]byte, out []bool) {
	for i, p := range pw {
		out[i] = h.one(p)
	}
}

func (h *Hasher) one(pw []byte) bool {
	// Bug compatibility with C bcrypt, preserved by x/crypto: the trailing NUL
	// of the key string participates in expansion.
	ckey := make([]byte, len(pw)+1)
	copy(ckey, pw)

	c := newSaltedState(ckey, h.csalt[:])
	if c == nil {
		return false
	}
	for i, rounds := uint64(0), uint64(1)<<uint(h.cost); i < rounds; i++ {
		expandKey(ckey, c)
		expandKey(h.csalt[:], c)
	}

	var buf [24]byte
	copy(buf[:], magicCipherData)
	for i := 0; i < 24; i += 8 {
		l := uint32(buf[i])<<24 | uint32(buf[i+1])<<16 | uint32(buf[i+2])<<8 | uint32(buf[i+3])
		r := uint32(buf[i+4])<<24 | uint32(buf[i+5])<<16 | uint32(buf[i+6])<<8 | uint32(buf[i+7])
		for j := 0; j < 64; j++ {
			l, r = encryptBlock(l, r, c)
		}
		buf[i], buf[i+1], buf[i+2], buf[i+3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
		buf[i+4], buf[i+5], buf[i+6], buf[i+7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
	}
	// Only 23 of the 24 bytes are encoded, matching every C implementation.
	return subtle.ConstantTimeCompare(buf[:23], h.digest[:]) == 1
}
```

- [ ] **Step 4: Run the test**

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -run TestRunMatchesXCrypto -v`
Expected: PASS.

If parsing fails on every case, check the `WithPadding(base64.NoPadding)` call — bcrypt's 22- and 31-character fields are unpadded and the standard encoder rejects them.

- [ ] **Step 5: Add the slow-cost and rejection tests**

Append to `bcrypt_test.go`:

```go
// TestRunMatchesXCryptoSlow covers the costs real targets use. It is slow by
// nature; -short skips it.
func TestRunMatchesXCryptoSlow(t *testing.T) {
	if testing.Short() {
		t.Skip("cost 7-10 bcrypt; run without -short")
	}
	rng := rand.New(rand.NewSource(6092026))
	for cost := 7; cost <= 10; cost++ {
		pw := randPassword(rng)
		crypt, err := bcrypt.GenerateFromPassword(pw, cost)
		if err != nil {
			t.Fatalf("cost %d: %v", cost, err)
		}
		h, err := NewHasher(string(crypt))
		if err != nil {
			t.Fatalf("cost %d: NewHasher: %v", cost, err)
		}
		out := make([]bool, 1)
		h.Run([][]byte{pw}, out)
		if !out[0] {
			t.Errorf("cost %d: correct password rejected", cost)
		}
	}
}

// TestNewHasherRejects pins the parser to x/crypto's acceptance set. Where
// x/crypto errors, NewHasher must error too - a target Hashsmith would have
// refused before must not silently start being cracked against a misparse.
func TestNewHasherRejects(t *testing.T) {
	valid := "$2a$05$24WDYwDgT9qSmz02emE1F.0YDG14PWmeoq8n.xCD71R7fA8/A2TxC"
	bad := []string{
		"", "$1$abc", "not a hash",
		valid[:len(valid)-1],           // truncated
		"$2a$99$" + valid[7:],          // cost out of range
		"$2a$0x$" + valid[7:],          // non-numeric cost
		"$3a$05$" + valid[7:],          // version too new
	}
	for _, s := range bad {
		if _, err := NewHasher(s); err == nil {
			t.Errorf("NewHasher(%q) accepted, want error", s)
		}
	}
	if _, err := NewHasher(valid); err != nil {
		t.Errorf("NewHasher(valid) = %v, want nil", err)
	}
	// Every minor version x/crypto accepts, this must accept.
	for _, minor := range []string{"$2$", "$2a$", "$2b$", "$2x$", "$2y$"} {
		s := minor + valid[4:]
		if _, err := NewHasher(s); err != nil {
			t.Errorf("NewHasher(%q) = %v, want nil", s, err)
		}
	}
}
```

- [ ] **Step 6: Run the full package**

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add hashsmith/go_hashsmith/internal/bcryptlane/
git commit -m "feat(bcryptlane): add the Hasher API, differential-tested against x/crypto"
```

---

### Task 4: The generator and the interleaved key schedule

**Files:**
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/bcryptlane_gen.py`
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/eks_lanes.go` (generated)
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/eks_lanes_test.go`
- Modify: `hashsmith/go_hashsmith/internal/bcryptlane/bcrypt.go` (`Run` decomposes into widths; `Hasher` gains scratch; `one` splits out `finish`)

**Interfaces:**
- Consumes: `state`, `expandKey`, `encryptBlock` (Task 2); `Hasher`, `Lanes` (Task 3).
- Produces: `func encryptBlockN(w int, l, r []uint32, c []*state)` is **not** the shape — instead the generator emits fixed-arity functions `expandKey2`, `expandKey4`, `expandKey8`, each `func(keys [N][]byte, c [N]*state)`, plus `expandKeyWithSalt2/4/8` with signature `func(keys [N][]byte, salt []byte, c [N]*state)`. Fixed arity is deliberate: slices of pointers would reintroduce bounds checks and defeat register allocation.

- [ ] **Step 1: Write the generator**

Create `internal/bcryptlane/bcryptlane_gen.py`. It follows the same shape as `cmd/hashsmith/md5neon_gen.py`.

```python
#!/usr/bin/env python3
"""Generate eks_lanes.go: Blowfish key schedules that advance N independent
candidates through each Feistel round together.

Why generated rather than hand-written: Go does not unroll loops, so the lanes
have to appear literally in the source for their dependency chains to interleave
in the scheduler. Four widths x sixteen rounds is far too much to maintain by
hand, and a transcription slip in round 11 of the 8-lane variant would be nearly
invisible in review.

Run: python3 bcryptlane_gen.py > eks_lanes.go && gofmt -w eks_lanes.go
"""

WIDTHS = [2, 4, 8]

def feistel(dst, src, lane, pidx):
    c = f"c{lane}"
    return (f"\tx{dst}{lane} ^= (({c}.s0[byte(x{src}{lane}>>24)] + {c}.s1[byte(x{src}{lane}>>16)]) ^ "
            f"{c}.s2[byte(x{src}{lane}>>8)]) + {c}.s3[byte(x{src}{lane})] ^ {c}.p[{pidx}]")

def emit_block(n):
    """One fully unrolled 16-round encryptBlock across n lanes."""
    args = ", ".join(f"l{i}, r{i} uint32" for i in range(n))
    cs = ", ".join(f"c{i} *state" for i in range(n))
    rets = ", ".join("uint32" for _ in range(2 * n))
    print(f"func encryptBlock{n}({args}, {cs}) ({rets}) {{")
    for i in range(n):
        print(f"\txl{i}, xr{i} := l{i}, r{i}")
    for i in range(n):
        print(f"\txl{i} ^= c{i}.p[0]")
    # rounds 1..16, alternating which half is updated
    for rnd in range(1, 17):
        dst, src = ("r", "l") if rnd % 2 == 1 else ("l", "r")
        for i in range(n):
            print(feistel(dst, src, i, rnd))
    for i in range(n):
        print(f"\txr{i} ^= c{i}.p[17]")
    print("\treturn " + ", ".join(f"xr{i}, xl{i}" for i in range(n)))
    print("}")
    print()

def emit_expand(n, salted):
    name = f"expandKeyWithSalt{n}" if salted else f"expandKey{n}"
    saltarg = ", salt []byte" if salted else ""
    print(f"func {name}(keys [{n}][]byte{saltarg}, c [{n}]*state) {{")
    print("\tfor i := 0; i < 18; i++ {")
    for i in range(n):
        print(f"\t\tc[{i}].p[i] ^= nextWord(keys[{i}], i*4)")
    print("\t}")
    for i in range(n):
        print(f"\tc{i} := c[{i}]")
    for i in range(n):
        print(f"\tvar l{i}, r{i} uint32")
    if salted:
        print("\tsj := 0")
    lanes = ", ".join(f"l{i}, r{i}" for i in range(n))
    cargs = ", ".join(f"c{i}" for i in range(n))
    def body(target, count):
        print(f"\tfor i := 0; i < {count}; i += 2 {{")
        if salted:
            for i in range(n):
                print(f"\t\tl{i} ^= saltWord(salt, sj)")
                print(f"\t\tr{i} ^= saltWord(salt, sj+4)")
            print("\t\tsj = (sj + 8) % len(salt)")
        print(f"\t\t{lanes} = encryptBlock{n}({lanes}, {cargs})")
        for i in range(n):
            print(f"\t\tc{i}.{target}[i], c{i}.{target}[i+1] = l{i}, r{i}")
        print("\t}")
    body("p", 18)
    for s in ("s0", "s1", "s2", "s3"):
        body(s, 256)
    print("}")
    print()

print("// Code generated by bcryptlane_gen.py. DO NOT EDIT.")
print()
print("package bcryptlane")
print()
for n in WIDTHS:
    emit_block(n)
    emit_expand(n, salted=False)
    emit_expand(n, salted=True)
```

**Important:** the salted variant's per-lane `l ^= saltWord(...)` above XORs the *same* salt into every lane, which is correct here and only here — every lane in a batch shares one target, therefore one salt (spec §3). `nextWord` and `saltWord` come from Task 2 Step 3b.

- [ ] **Step 1b: Have the generator emit the per-width Run bodies too**

Hand-writing `run2`, `run4` and `run8` would be three near-identical 40-line
functions kept in sync by hand — exactly what the generator exists to prevent.
Append to `bcryptlane_gen.py`:

```python
def emit_run(n):
    print(f"// run{n} hashes exactly {n} candidates through interleaved lanes,")
    print(f"// writing verdicts to h.verdicts[:{n}].")
    print(f"func (h *Hasher) run{n}(pw [][]byte) {{")
    print(f"	var keys [{n}][]byte")
    print(f"	var c [{n}]*state")
    print(f"	for i := 0; i < {n}; i++ {{")
    print("		k := h.keyScratch[i][:0]")
    print("		k = append(k, pw[i]...)")
    print("		// bug compatibility: the key's trailing NUL participates")
    print("		keys[i] = append(k, 0)")
    print("		// no zeroing: initState overwrites p and s0..s3 in full;")
    print("		// clearing 4 KB per lane per batch would be pure waste.")
    print("		c[i] = &h.scratch[i]")
    print("		initState(c[i])")
    print("	}")
    print(f"	salt := h.csalt[:]")
    print(f"	expandKeyWithSalt{n}(keys, salt, c)")
    print(f"	var saltKeys [{n}][]byte")
    print(f"	for i := 0; i < {n}; i++ {{ saltKeys[i] = salt }}")
    print("	for r, rounds := uint64(0), uint64(1)<<uint(h.cost); r < rounds; r++ {")
    print(f"		expandKey{n}(keys, c)")
    print(f"		expandKey{n}(saltKeys, c)")
    print("	}")
    print(f"	for i := 0; i < {n}; i++ {{")
    print("		h.verdicts[i] = h.finish(c[i])")
    print("	}")
    print("}")
    print()
```

and add `emit_run(n)` to the `for n in WIDTHS:` loop at the bottom of the file.

- [ ] **Step 2: Generate and inspect**

```bash
cd hashsmith/go_hashsmith/internal/bcryptlane
python3 bcryptlane_gen.py > eks_lanes.go && gofmt -w eks_lanes.go
go build ./...
wc -l eks_lanes.go
```

Expected: builds clean. If `gofmt` errors, the generator emitted malformed Go — read the offending line; it is almost always a missing comma in a joined argument list.

- [ ] **Step 3: Write the lane-invariance test**

Create `internal/bcryptlane/eks_lanes_test.go`:

```go
package bcryptlane

import (
	"math/rand"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestLaneInvariance is the test that makes Task 5's tuning safe: whatever width
// ships, the answers must be identical. It compares every generated width
// against the single-lane path already proven equal to x/crypto in Task 3.
func TestLaneInvariance(t *testing.T) {
	rng := rand.New(rand.NewSource(4041))
	for trial := 0; trial < 12; trial++ {
		cost := 4 + rng.Intn(2)
		correct := randPassword(rng)
		crypt, err := bcrypt.GenerateFromPassword(correct, cost)
		if err != nil {
			t.Fatal(err)
		}
		h, err := NewHasher(string(crypt))
		if err != nil {
			t.Fatal(err)
		}

		// A batch of 8 with the correct password at a rotating position, so
		// every lane index is exercised as the hit across trials.
		pw := make([][]byte, 8)
		hit := trial % 8
		for i := range pw {
			pw[i] = randPassword(rng)
		}
		pw[hit] = correct

		want := make([]bool, 8)
		for i := range pw {
			want[i] = h.one(pw[i])
		}
		if !want[hit] {
			t.Fatalf("trial %d: single-lane oracle rejected the correct password", trial)
		}

		got := make([]bool, 8)
		h.Run(pw, got)
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("trial %d lane %d: Run gave %v, single-lane gave %v", trial, i, got[i], want[i])
			}
		}
	}
}

// TestPartialBatch covers the tail: a wordlist whose length is not a multiple of
// the lane width must still test every candidate, including the last one.
func TestPartialBatch(t *testing.T) {
	correct := []byte("tail-case")
	crypt, err := bcrypt.GenerateFromPassword(correct, 4)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHasher(string(crypt))
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 9; n++ {
		for hit := 0; hit < n; hit++ {
			pw := make([][]byte, n)
			for i := range pw {
				pw[i] = []byte("wrong")
			}
			pw[hit] = correct
			out := make([]bool, n)
			h.Run(pw, out)
			for i := range out {
				if want := i == hit; out[i] != want {
					t.Errorf("n=%d hit=%d: out[%d] = %v, want %v", n, hit, i, out[i], want)
				}
			}
		}
	}
}

// TestNoBoundsChecksInRounds guards the property the vendored code already has.
// Lane state held in slices instead of fixed-size arrays would reintroduce
// checks into the hottest loop in the program.
func TestNoBoundsChecksInRounds(t *testing.T) {
	out, err := exec.Command("go", "build", "-gcflags=-d=ssa/check_bce/debug=1", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "eks_lanes.go") && strings.Contains(line, "IsInBounds") {
			t.Errorf("bounds check in generated round code: %s", line)
		}
	}
}
```

Add `"os/exec"` and `"strings"` to the imports.

- [ ] **Step 4: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -run 'TestLaneInvariance|TestPartialBatch|TestNoBoundsChecks' -v`

Expected: `TestLaneInvariance` and `TestPartialBatch` **PASS**. `Run` still routes
everything through `one`, which Task 3 proved correct, so they pass trivially and
are not yet testing the lanes. That is deliberate: they are the safety net that
must stay green across Step 5's rewrite, and a test that only starts passing
after a change cannot show the change preserved behaviour.

`TestNoBoundsChecksInRounds` is this step's real gate and must **PASS** now — if
the generator emitted slice-typed lane state, it fails here, before any of it is
wired in.

- [ ] **Step 5: Rewrite `Run` to decompose into generated widths**

Replace `Run` in `bcrypt.go`:

```go
// Run hashes each pw[i] against the target and writes the verdict to out[i].
// len(pw) must be <= Lanes and len(out) must be >= len(pw).
//
// A batch of any size is decomposed into the generated widths, largest first
// (8, 4, 2, then singles), so a tail of three candidates costs one 2-lane pass
// plus one single rather than a padded 4-lane pass. Padding would spend a whole
// bcrypt computation on a dummy candidate, which at cost 12 is most of the cost
// of the partial batch.
func (h *Hasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		switch n := len(pw) - i; {
		case n >= 8:
			h.run8(pw[i : i+8])
			copy(out[i:], h.verdicts[:8])
			i += 8
		case n >= 4:
			h.run4(pw[i : i+4])
			copy(out[i:], h.verdicts[:4])
			i += 4
		case n >= 2:
			h.run2(pw[i : i+2])
			copy(out[i:], h.verdicts[:2])
			i += 2
		default:
			out[i] = h.one(pw[i])
			i++
		}
	}
}
```

`run2`, `run4` and `run8` are generated by Step 1b. This step adds the state they
write into and the tail of `one` they share.

Change the `Hasher` struct and split `one`:

```go
// Hasher is one parsed bcrypt target. Parsing happens once; Run is the hot path.
//
// NOT SAFE FOR CONCURRENT USE. The scratch fields below exist so that hashing a
// full batch allocates nothing, which means two goroutines sharing one Hasher
// would corrupt each other's lane state. Tasks 6 and 7 give every worker its
// own via a factory; never share one.
type Hasher struct {
	cost   int
	csalt  [16]byte
	digest [23]byte

	scratch    [8]state    // per-lane Blowfish state, reused across batches
	keyScratch [8][]byte   // per-lane key buffers, reused across batches
	verdicts   [8]bool     // per-lane results, read by Run
}

// finish runs the 64 x 3 magic-data encryptions on a fully scheduled state and
// compares against the target digest. Shared by the single-lane path and every
// generated width, so the comparison rule lives in exactly one place.
func (h *Hasher) finish(c *state) bool {
	var buf [24]byte
	copy(buf[:], magicCipherData)
	for i := 0; i < 24; i += 8 {
		l := uint32(buf[i])<<24 | uint32(buf[i+1])<<16 | uint32(buf[i+2])<<8 | uint32(buf[i+3])
		r := uint32(buf[i+4])<<24 | uint32(buf[i+5])<<16 | uint32(buf[i+6])<<8 | uint32(buf[i+7])
		for j := 0; j < 64; j++ {
			l, r = encryptBlock(l, r, c)
		}
		buf[i], buf[i+1], buf[i+2], buf[i+3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
		buf[i+4], buf[i+5], buf[i+6], buf[i+7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
	}
	// Only 23 of the 24 bytes are encoded, matching every C implementation.
	return subtle.ConstantTimeCompare(buf[:23], h.digest[:]) == 1
}
```

Then replace the tail of `one` (everything from `var buf [24]byte` onward) with
`return h.finish(c)`, leaving its key-building and schedule loop as they are.
`one` stays the single-lane path and the oracle Task 4's tests compare against.

- [ ] **Step 6: Run tests and the width benchmark**

Add to `eks_lanes_test.go`:

```go
func benchWidth(b *testing.B, width int) {
	crypt, _ := bcrypt.GenerateFromPassword([]byte("benchmark"), 5)
	h, _ := NewHasher(string(crypt))
	pw := make([][]byte, width)
	for i := range pw {
		pw[i] = []byte("candidate")
	}
	out := make([]bool, width)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Run(pw, out)
	}
	// ns/op divided by width is the per-candidate cost; report it directly.
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*width), "ns/candidate")
}

func BenchmarkWidth1(b *testing.B) { benchWidth(b, 1) }
func BenchmarkWidth2(b *testing.B) { benchWidth(b, 2) }
func BenchmarkWidth4(b *testing.B) { benchWidth(b, 4) }
func BenchmarkWidth8(b *testing.B) { benchWidth(b, 8) }
```

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -v && go test ./internal/bcryptlane/ -bench=Width -benchtime=3s -run='^$' -count=3`
Expected: all tests PASS; `ns/candidate` falls as width rises.

- [ ] **Step 7: Commit**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add hashsmith/go_hashsmith/internal/bcryptlane/
git commit -m "feat(bcryptlane): generate interleaved key schedules at widths 2, 4 and 8"
```

---

### Task 5: Tune the width and lock in the ratchet

**Files:**
- Modify: `hashsmith/go_hashsmith/internal/bcryptlane/bcrypt.go` (the `Lanes` constant)
- Create: `hashsmith/go_hashsmith/internal/bcryptlane/speed_test.go`
- Create: `docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md`

**Interfaces:**
- Consumes: `Hasher`, `Run`, the width benchmarks (Task 4).
- Produces: the final `Lanes` value that Tasks 6 and 7 buffer against.

- [ ] **Step 1: Measure all widths properly**

```bash
cd hashsmith/go_hashsmith
go test ./internal/bcryptlane/ -bench=Width -benchtime=5s -run='^$' -count=5 | tee /tmp/width.txt
```

Take the **best** `ns/candidate` per width (best-of, like the Phase 1 note, because session load only ever adds time). Set `Lanes` to the width with the lowest per-candidate cost. If two widths are within 3%, choose the **smaller** — it uses less L1 and degrades more gracefully on machines with smaller caches than this one.

- [ ] **Step 2: Write the ratchet test**

Create `internal/bcryptlane/speed_test.go`:

```go
package bcryptlane

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// bcryptSpeedupFloor is a ratchet, not a target. Raise it as the core improves;
// never lower it to make a change pass.
//
// It is a RATIO against x/crypto/bcrypt measured in this same process, not an
// absolute c/s figure. An absolute floor would encode one machine's clock speed
// and flake on every other runner; the ratio is the quantity the work is
// actually about and is stable across hardware.
//
// Set from the measurement in docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md
// with a 15% margin below the observed value to absorb runner variance.
const bcryptSpeedupFloor = 0.0 // REPLACE with measured value * 0.85 in Step 4

func TestSpeedupOverXCrypto(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test; run without -short")
	}
	crypt, err := bcrypt.GenerateFromPassword([]byte("ratchet"), 5)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHasher(string(crypt))
	if err != nil {
		t.Fatal(err)
	}
	pw := make([][]byte, Lanes)
	for i := range pw {
		pw[i] = []byte("candidate")
	}
	out := make([]bool, Lanes)

	lane := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h.Run(pw, out)
		}
	})
	perCandidate := float64(lane.NsPerOp()) / float64(Lanes)

	ref := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bcrypt.CompareHashAndPassword(crypt, []byte("candidate"))
		}
	})

	got := float64(ref.NsPerOp()) / perCandidate
	t.Logf("x/crypto %d ns/op, bcryptlane %.0f ns/candidate at %d lanes, speedup %.2fx",
		ref.NsPerOp(), perCandidate, Lanes, got)
	if got < bcryptSpeedupFloor {
		t.Errorf("speedup %.2fx is below the %.2fx floor", got, bcryptSpeedupFloor)
	}
}
```

- [ ] **Step 3: Run it and read the logged speedup**

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -run TestSpeedupOverXCrypto -v`
Expected: PASS (floor is 0.0), with the real speedup in the log line.

- [ ] **Step 4: Set the floor and re-run**

Replace `bcryptSpeedupFloor` with the measured speedup times 0.85, written as a computed expression so the derivation stays visible — e.g. `const bcryptSpeedupFloor = 2.85 * 0.85`.

Run: `cd hashsmith/go_hashsmith && go test ./internal/bcryptlane/ -run TestSpeedupOverXCrypto -v -count=3`
Expected: PASS all three times. If it flakes, the 15% margin is too tight for this machine — widen it and say so in the note rather than deleting the test.

- [ ] **Step 5: Write the tuning note**

Create `docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md` with: the machine, all five runs per width verbatim, the chosen `Lanes` and why, the measured speedup over x/crypto, and the resulting single-thread c/s at cost 5 (`1e9 / ns-per-candidate`). State plainly whether that c/s clears the 887 target from spec §2 — and if it does not, say so without softening; spec §8 already records that this is a bar decision, not a failure.

- [ ] **Step 6: Commit**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add hashsmith/go_hashsmith/internal/bcryptlane/ docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md
git commit -m "perf(bcryptlane): tune the lane width and ratchet the speedup"
```

---

### Task 6: Wire the lane core into the dictionary attack

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/crack.go:1812-1935` (`dictAttack`)
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/crack.go:1367,1377` (both call sites)
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/lanes.go`
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/lanes_test.go`

**Interfaces:**
- Consumes: `bcryptlane.NewHasher`, `(*bcryptlane.Hasher).Run`, `bcryptlane.Lanes`.
- Produces: `func newLaneHasher(typ, targetHash, salt, saltMode string) (func() *bcryptlane.Hasher, bool)` — a **factory**, not a shared `*Hasher`, because Task 4 gave `Hasher` reusable scratch and it is not safe for concurrent use. Each worker calls the factory once.

- [ ] **Step 1: Write the failing test**

Create `cmd/hashsmith/lanes_test.go`:

```go
package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestDictAttackLanesFindsAtEveryPosition is the test that matters: the lane
// buffer must be flushed at end-of-batch and end-of-wordlist, or trailing
// candidates go untested and a crackable password is silently reported as not
// found - the worst possible failure for a cracker.
func TestDictAttackLanesFindsAtEveryPosition(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("needle"), 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 2, 3, 5, 7, 8, 9, 17} {
		for _, pos := range []int{0, n / 2, n - 1} {
			words := make([]string, n)
			for i := range words {
				words[i] = "chaff"
			}
			words[pos] = "needle"

			dir := t.TempDir()
			path := filepath.Join(dir, "wl.txt")
			var buf []byte
			for _, w := range words {
				buf = append(buf, w...)
				buf = append(buf, '\n')
			}
			if err := os.WriteFile(path, buf, 0o600); err != nil {
				t.Fatal(err)
			}

			var attempts int64
			verify := func(c string) bool {
				return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
			}
			res, err := dictAttack(context.Background(), path, 0, 0, 2, &attempts, nil,
				verify, string(crypt), "bcrypt", "", "prefix")
			if err != nil {
				t.Fatalf("n=%d pos=%d: %v", n, pos, err)
			}
			if res.password != "needle" {
				t.Errorf("n=%d pos=%d: got %q, want \"needle\"", n, pos, res.password)
			}
			if atomic.LoadInt64(&attempts) < int64(pos+1) {
				t.Errorf("n=%d pos=%d: only %d attempts counted", n, pos, attempts)
			}
		}
	}
}

// TestDictAttackLanesRuleLabels pins hit attribution: a match found in lane 3
// must report lane 3's rule label, not a neighbour's.
func TestDictAttackLanesRuleLabels(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("needle1"), 4)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(path, []byte("aaa\nbbb\nneedle\nccc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := newRuleEngineFromRules([]string{"$1"})
	if err != nil {
		t.Fatal(err)
	}
	var attempts int64
	verify := func(c string) bool {
		return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
	}
	res, err := dictAttack(context.Background(), path, 0, 0, 2, &attempts, rules,
		verify, string(crypt), "bcrypt", "", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	if res.password != "needle1" {
		t.Fatalf("got %q, want \"needle1\"", res.password)
	}
	if res.ruleLabel != "$1" {
		t.Errorf("rule label %q, want \"$1\"", res.ruleLabel)
	}
}
```

If `newRuleEngineFromRules` is not the constructor's real name, find it with `grep -n 'func newRuleEngine' cmd/hashsmith/rules.go` and use the actual one — do not invent a wrapper.

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith/ -run TestDictAttackLanes -v`
Expected: FAIL — `dictAttack` takes 8 arguments, not 12.

- [ ] **Step 3: Add the lane factory**

Create `cmd/hashsmith/lanes.go`:

```go
package main

import "hashsmith-go/internal/bcryptlane"

// newLaneHasher reports whether typ has an interleaved multi-candidate core for
// this target and, if so, returns a factory producing one hasher per worker.
//
// It returns a FACTORY rather than a shared *Hasher on purpose: the hasher owns
// reusable lane scratch so a batch allocates nothing, which makes it unsafe for
// concurrent use. One per worker, never one shared.
//
// bcrypt only, single target only. Every lane in a batch executes the same
// iteration count in lockstep, so they must share one cost and one salt - which
// is true of one target and false of a dump. Dumps keep the scalar path.
func newLaneHasher(typ, targetHash, salt, saltMode string) (func() *bcryptlane.Hasher, bool) {
	if canonicalHashType(typ) != "bcrypt" || salt != "" {
		return nil, false
	}
	if _, err := bcryptlane.NewHasher(targetHash); err != nil {
		return nil, false
	}
	return func() *bcryptlane.Hasher {
		h, err := bcryptlane.NewHasher(targetHash)
		if err != nil {
			return nil // caller falls back to the scalar verify
		}
		return h
	}, true
}
```

- [ ] **Step 4: Thread it through `dictAttack`**

Change the signature at `crack.go:1812` to append `targetHash, typ, salt, saltMode string`, and update both call sites at `crack.go:1367` and `crack.go:1377` to pass `targetHash, typ, salt, saltMode`.

Inside the worker goroutine, replace the one-at-a-time `tryCandidate` with a buffered version. Keep `tryCandidate`'s attempt-counter batching (`localAttempts >= 1024`) exactly as it is — it exists to avoid cache-line contention and the lane change must not disturb it.

```go
newHasher, laned := newLaneHasher(typ, targetHash, salt, saltMode)
// ... inside each worker goroutine:
var lh *bcryptlane.Hasher
if laned {
	lh = newHasher()
}
type cand struct{ pw, ruleLabel string }
buf := make([]cand, 0, bcryptlane.Lanes)
pwBuf := make([][]byte, bcryptlane.Lanes)
outBuf := make([]bool, bcryptlane.Lanes)

// flush tests everything buffered and reports the FIRST hit in buffer order,
// so a laned run reports the same password an unlaned run would.
flush := func() bool {
	if len(buf) == 0 {
		return false
	}
	// Re-slice into a local: assigning back to pwBuf would shorten it
	// permanently and cap every later batch at this batch's length.
	pw := pwBuf[:len(buf)]
	for i, c := range buf {
		pw[i] = []byte(c.pw)
	}
	lh.Run(pw, outBuf[:len(buf)])
	localAttempts += int64(len(buf))
	if localAttempts >= 1024 {
		atomic.AddInt64(atomicAttempts, localAttempts)
		localAttempts = 0
	}
	for i, ok := range outBuf[:len(buf)] {
		if ok {
			select {
			case resultCh <- crackedResult{password: buf[i].pw, ruleLabel: buf[i].ruleLabel}:
			default:
			}
			cancel()
			buf = buf[:0]
			return true
		}
	}
	buf = buf[:0]
	return false
}
```

`tryCandidate` becomes: when `lh == nil`, today's body unchanged; otherwise append to `buf` and call `flush()` when `len(buf) == bcryptlane.Lanes`.

**Then call `flush()` in three places or trailing candidates are lost:** after the `for _, word := range words` loop finishes each batch; before `return` on the `innerCtx.Done()` paths; and after the `case words, ok := <-batchCh` receives `!ok`. Missing the third is the bug this task's first test exists to catch.

- [ ] **Step 5: Run the tests**

Run: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith/ -run TestDictAttackLanes -v`
Expected: PASS both.

- [ ] **Step 6: Run the full package to check nothing regressed**

Run: `cd hashsmith/go_hashsmith && go build ./... && go vet ./... && go test ./cmd/hashsmith/ -short`
Expected: PASS. The other 456 formats route through the unchanged `lh == nil` branch.

- [ ] **Step 7: Commit**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add hashsmith/go_hashsmith/cmd/hashsmith/
git commit -m "perf(crack): hash bcrypt dictionary candidates through interleaved lanes"
```

---

### Task 7: Wire the lane core into brute and mask

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/lanes.go` (add the runner)
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/crack.go:73-110` (`runBruteOrMaskLayout` dispatch)
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/lanes_test.go`

**Interfaces:**
- Consumes: `newLaneHasher` (Task 6); `runSessionRunner(ctx, layout, sess, resumeFrom, run layoutRunner)` and `layoutRunner = func(watermark *int64) (string, error)` from `session.go:133`; `keyspaceLayout` from `keyspace.go`.
- Produces: `func runLayoutLanes(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64, workers int, atomicAttempts, watermark *int64, newHasher func() *bcryptlane.Hasher) (string, error)`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/hashsmith/lanes_test.go`:

```go
// TestMaskLanesFindsAtEveryPosition mirrors the dict test for the keyspace
// runner. The mask ?l?l covers 676 candidates; planting the answer at the first,
// a middle and the last index exercises the same flush boundaries.
func TestMaskLanesFindsAtEveryPosition(t *testing.T) {
	for _, pw := range []string{"aa", "mn", "zz"} {
		crypt, err := bcrypt.GenerateFromPassword([]byte(pw), 4)
		if err != nil {
			t.Fatal(err)
		}
		cfg := buildMaskConfig("?l?l", "", "", "", "", false, 0, false)
		var attempts int64
		got, err := maskAttack(context.Background(), string(crypt), "bcrypt", cfg, 2, "", "prefix", &attempts)
		if err != nil {
			t.Fatalf("%s: %v", pw, err)
		}
		if got != pw {
			t.Errorf("mask found %q, want %q", got, pw)
		}
	}
}

// TestLanesRespectSessionWatermark pins the contract runLayoutLanes shares with
// its sibling runners: a resumed run must not retest what the first run covered
// and must still find an answer past the resume point.
func TestLanesRespectSessionWatermark(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("zz"), 4)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := newLaneHasher("bcrypt", string(crypt), "", "prefix")
	if !ok {
		t.Fatal("newLaneHasher declined a valid bcrypt target")
	}
	layout, err := maskLayout(buildMaskConfig("?l?l", "", "", "", "", false, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	var attempts, watermark int64
	// Start past every candidate except the last few; the answer is index 675.
	got, err := runLayoutLanes(context.Background(), layout, 670, 0, 2, &attempts, &watermark, h)
	if err != nil {
		t.Fatal(err)
	}
	if got != "zz" {
		t.Errorf("resumed run found %q, want \"zz\"", got)
	}
	if watermark < 670 {
		t.Errorf("watermark went backwards: %d", watermark)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith/ -run 'TestMaskLanes|TestLanesRespectSession' -v`
Expected: FAIL — `undefined: runLayoutLanes`.

- [ ] **Step 3: Implement `runLayoutLanes`**

Copy `runLayout` (`keyspace.go:103-205`) into `lanes.go` as `runLayoutLanes`,
keeping its bounds arithmetic, chunk striping, `cur[]` watermark tracking, the
`watermark updater` goroutine and the return block **byte for byte**. `--session`
resume, `--skip`/`--limit` slicing and the progress counter all depend on those
details, and the runner must be indistinguishable from its siblings on every
axis except speed.

Change exactly two things. First the signature — it takes a hasher factory
instead of a verify closure:

```go
func runLayoutLanes(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	newHasher func() *bcryptlane.Hasher) (string, error) {
```

Second, the per-chunk inner loop. Replace `runLayout`'s `for idx := from; idx < end; idx++`
body with this. Everything outside the loop stays as copied:

```go
			// Each worker owns one Hasher for the life of the run: it carries
			// reusable lane scratch and must never be shared (see lanes.go).
			if lh == nil {
				lh = newHasher()
			}
			if lh == nil { // unparseable target; the dispatcher should have caught it
				return
			}

			var local int64
			iter := 0
			cands := make([]string, 0, bcryptlane.Lanes)
			pwBuf := make([][]byte, bcryptlane.Lanes)
			outBuf := make([]bool, bcryptlane.Lanes)

			// flush tests everything buffered, reporting the FIRST hit in
			// buffer order so a laned run reports the same candidate an
			// unlaned run would. Returns true when the run should stop.
			flush := func() bool {
				if len(cands) == 0 {
					return false
				}
				pw := pwBuf[:len(cands)]
				for i, c := range cands {
					pw[i] = []byte(c)
				}
				lh.Run(pw, outBuf[:len(cands)])
				local += int64(len(cands))
				for i, ok := range outBuf[:len(cands)] {
					if ok {
						hit := cands[i]
						atomic.AddInt64(atomicAttempts, local)
						select {
						case resultCh <- hit:
						default:
						}
						cancel()
						atomic.StoreInt64(&cur[wID], math.MaxInt64)
						return true
					}
				}
				cands = cands[:0]
				return false
			}

			for idx := from; idx < end; idx++ {
				if iter++; iter >= ctxCheckEvery {
					iter = 0
					select {
					case <-innerCtx.Done():
						// Cancelled mid-chunk: test what is buffered before
						// leaving, or those candidates are silently skipped.
						flush()
						atomic.AddInt64(atomicAttempts, local)
						return
					default:
					}
				}
				cands = append(cands, l.candidate(idx))
				if len(cands) == bcryptlane.Lanes {
					if flush() {
						return
					}
				}
			}
			// End of chunk: the tail is almost never a full lane width, and
			// dropping it would silently skip up to Lanes-1 candidates per
			// chunk. TestMaskLanesFindsAtEveryPosition covers exactly this.
			if flush() {
				return
			}
			atomic.AddInt64(atomicAttempts, local)
```

Declare `var lh *bcryptlane.Hasher` immediately inside the `go func(wID int)`
body, above the chunk loop, so one hasher serves every chunk that worker takes.

- [ ] **Step 4: Add the dispatch**

In `runBruteOrMaskLayout` (`crack.go:73`), after the `stdPathEligible` block and before the scalar fallback:

```go
	// bcrypt (and only bcrypt, single-target) has an interleaved multi-candidate
	// core: several candidates advance through each Blowfish round together,
	// which is the only way to make a CPU-bound KDF faster. See
	// internal/bcryptlane and docs/superpowers/specs/2026-09-06-bcrypt-lanes-design.md.
	if newHasher, ok := newLaneHasher(typ, effHash, effSalt, saltMode); ok {
		return runSessionRunner(ctx, layout, sess, resumeFrom, func(watermark *int64) (string, error) {
			return runLayoutLanes(ctx, layout, resumeFrom, limit, workers, atomicAttempts, watermark, newHasher)
		})
	}
```

Also swap the `verifyCandidate` closure in `maskAttack` (`mask.go:275`) for the same check, so `hashsmith crack -M mask` reaches it too.

- [ ] **Step 5: Run the tests**

Run: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith/ -run 'TestMaskLanes|TestLanesRespectSession' -v`
Expected: PASS.

- [ ] **Step 6: Run the full suite including the self-test vectors**

Run: `cd hashsmith/go_hashsmith && go build ./... && go vet ./... && go test ./... -short`
Then the known-answer vectors, which are the real regression net:
Run: `go run ./cmd/hashsmith selftest | tail -20`
Expected: the bcrypt vectors pass and the summary's published/cross-checked/regression counts are unchanged from before this branch.

- [ ] **Step 7: Commit**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add hashsmith/go_hashsmith/cmd/hashsmith/
git commit -m "perf(crack): route single-target bcrypt brute and mask through lanes"
```

---

### Task 8: Measure end to end against John and Hashcat, then document

**Files:**
- Create: `docs/superpowers/notes/2026-09-06-bcrypt-results.md`
- Modify: `README.md` (the "Measured against John and Hashcat" section, ~line 535)

**Interfaces:**
- Consumes: the finished binary.
- Produces: the numbers the claim rests on.

- [ ] **Step 1: Build a clean binary**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith/hashsmith/go_hashsmith
go build -o /tmp/hashsmith-lanes ./cmd/hashsmith
```

- [ ] **Step 2: Regenerate the fixtures**

```bash
cd /tmp && python3 -c "
import bcrypt
open('bc.txt','w').write(bcrypt.hashpw(b'notinlist', bcrypt.gensalt(5, prefix=b'2a')).decode()+'\n')
for n in (4000, 40000, 400000):
    open(f'wl{n}.txt','w').write('\n'.join('w%06d'%i for i in range(n))+'\n')
"
```

- [ ] **Step 3: Measure single-thread, the headline number**

```bash
cd /tmp && H=$(cat bc.txt)
for i in 1 2 3; do /usr/bin/time -p /tmp/hashsmith-lanes crack -t bcrypt "$H" -w wl4000.txt -p 1 -N --no-pot >/dev/null 2>e; grep real e; done
john --test=10 --format=bcrypt 2>&1 | tail -3
```

Single-thread c/s is `4000 ÷ best real`. Compare against John's `--test` figure and against the 302 c/s baseline from Task 1.

- [ ] **Step 4: Measure multi-threaded wall clock at all three sizes**

```bash
cd /tmp && H=$(cat bc.txt)
for n in 4000 40000 400000; do
  echo "== $n =="
  for i in 1 2; do /usr/bin/time -p /tmp/hashsmith-lanes crack -t bcrypt "$H" -w wl$n.txt -N --no-pot >/dev/null 2>e; grep real e; done
  for i in 1 2; do rm -f j.pot; /usr/bin/time -p john --format=bcrypt --wordlist=wl$n.txt --fork=8 --pot=j.pot --session=j$n$i bc.txt >/dev/null 2>e; grep real e; done
  for i in 1 2; do /usr/bin/time -p hashcat -m 3200 -a 0 --potfile-disable --quiet --session=h$n$i bc.txt wl$n.txt >/dev/null 2>e; grep real e; done
done
```

Discard each tool's first hashcat run at a new size — Task 1's baseline saw 37.90s then 22.32s from kernel cache warming, and comparing a cold run to a warm one would flatter Hashsmith.

- [ ] **Step 5: Write the results note**

Create `docs/superpowers/notes/2026-09-06-bcrypt-results.md` with the machine, every raw run verbatim, both single-thread and wall-clock tables, and an explicit verdict against the spec's two-part target (>= 887 c/s single-thread **and** faster wall clock at all three sizes). If either half is unmet, say which and by how much. The Phase 1 note's practice applies: never round in Hashsmith's favour, and state anything that cuts against the result — thermal drift on the 400k run especially.

- [ ] **Step 6: Update the README**

In "Measured against John and Hashcat", add a bcrypt subsection with **both** a per-thread table and a wall-clock table. The per-thread row is the point: §1 of the spec records that wall clock alone previously hid a 1.96x core deficit, and the README must not let it hide one again.

Update the comparison table's GPU row only if it is now wrong; do not otherwise touch that section.

- [ ] **Step 7: Full verification before claiming completion**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith/hashsmith/go_hashsmith
go build ./... && go vet ./... && go test ./... && go run ./cmd/hashsmith selftest -slow | tail -20
```
Expected: everything passes, including the 146 slow KDF vectors. Do not claim the work is complete on a partial run.

- [ ] **Step 8: Commit**

```bash
cd /Users/salihsefer36/Documents/GitHub/Hashsmith
git add README.md docs/superpowers/notes/2026-09-06-bcrypt-results.md
git commit -m "docs: record the measured bcrypt lane result against John and Hashcat"
```
