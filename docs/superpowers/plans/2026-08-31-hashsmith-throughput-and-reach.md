# Hashsmith Throughput and Reach Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get Hashsmith's test suite green in under 60 seconds, then raise MD5/MD4/NTLM cracking throughput from ~10 MH/s toward JtR-class speed by batching candidates and interleaving the hash cores.

**Architecture:** Phase 0 makes the existing self-test honor the slow-KDF classification it already has, and fixes the benchmark harness so it is a trustworthy baseline. Phase 1 opens with a **timeboxed NEON assembly spike that is a hard go/no-go gate** — a pure-Go interleaved core was already built and measured *slower* than `crypto/md5`, so the vector registers are the whole thesis. The spike ran, and its result rewrote what follows: a plain 4-way core failed (1.26x), but **software-pipelining five independent chains reached 5.58x**, and the win survives only if candidates are generated already transposed. So Phase 1 builds a narrow fast path — transposed generation, the pipelined core, and integration for unsalted fixed-length MD5 — with a portable fallback on every non-arm64 target and **every other format left on exactly today's code**. See "Outcome of the gate" before Task 6.

**Phase 0 is independently valuable and is not gated on anything.** Phase 1 Tasks 6–11 are gated on Task 5.

**Tech Stack:** Go 1.25+ (`go.mod` says `go 1.25.0`; toolchain in use is 1.26.3), standard library `crypto/*`, `golang.org/x/crypto/md4`, `golang.org/x/sys/cpu` for feature detection. No cgo.

**Spec:** `docs/superpowers/specs/2026-08-31-hashsmith-throughput-and-reach-design.md`

## Global Constraints

- **No cgo.** `CGO_ENABLED=0 go build` must keep working. No new C, no dynamic linking, no required C toolchain.
- **Cross-compilation must keep working** for `linux/amd64`, `linux/arm64`, `windows/amd64`, `darwin/arm64`.
- **A portable Go fallback is always compiled** for every algorithm. Any architecture without an assembly core must build and pass the full suite.
- **No format's observable result may change.** The self-test vector suite is the gate.
- **All work happens in** `hashsmith/go_hashsmith/cmd/hashsmith/` (package `main`) unless a task says otherwise.
- **Package layout:** the codebase is one flat `package main` with ~270 files. Follow that; do not introduce subpackages.
- **Test command:** `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith`. Prefix every `go` command with that `cd`.
- **Benchmark reference machine:** Apple M2, 4 performance + 4 efficiency cores. Baselines: md5 5.46 MH/s, md4 6.44, ntlm 5.86, sha1 11.69, sha256 13.22, sha512 10.77 (all `-d 1 -p 8`, current allocating harness).

---

# Phase 0 — A test suite that finishes

## Task 1: Make the self-test respect the slow-KDF classification

`TestSelfTestVectorsAllPass` runs every vector including ~120 memory-hard KDFs, so `go test ./...` dies at Go's 600s timeout inside a VeraCrypt 500,000-iteration PBKDF2-HMAC-Whirlpool vector. The registry already knows which types are slow — the test just ignores it.

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/selftest_test.go:10-28`
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/selftest_slow_test.go`

**Interfaces:**
- Consumes: `universalHashRegistry.vectors []selfTestVector`, `(*hashRegistry).isSlow(name string) bool` (`hash_registry.go:115`), `verifyCandidate(candidate, targetHash, typ, salt, saltMode string) (bool, error)` (`crack.go:856`), `wrongPassword(string) string`
- Produces: `checkSelfTestVector(t *testing.T, v selfTestVector)` — shared by the fast and slow suites.

- [ ] **Step 1: Write the failing test**

Replace the body of `TestSelfTestVectorsAllPass` in `selftest_test.go` and add the shared helper plus a guard test:

```go
// checkSelfTestVector asserts one vector matches its known answer and rejects
// a wrong password. Shared by the fast and slow suites.
func checkSelfTestVector(t *testing.T, v selfTestVector) {
	t.Helper()
	ok, err := verifyCandidate(v.password, v.target, v.typ, v.salt, "prefix")
	if err != nil {
		t.Errorf("%s: %v", v.typ, err)
		return
	}
	if !ok {
		t.Errorf("%s: vector did not match its known answer", v.typ)
		return
	}
	if bad, _ := verifyCandidate(wrongPassword(v.password), v.target, v.typ, v.salt, "prefix"); bad {
		t.Errorf("%s: accepted a wrong password", v.typ)
	}
}

// The fast vectors must pass on every run. Slow KDFs are covered by
// TestSelfTestVectorsSlow behind the slowtest build tag.
func TestSelfTestVectorsAllPass(t *testing.T) {
	if len(universalHashRegistry.vectors) == 0 {
		t.Fatal("no self-test vectors are compiled in")
	}
	ran := 0
	for _, v := range universalHashRegistry.vectors {
		if universalHashRegistry.isSlow(v.typ) {
			continue
		}
		checkSelfTestVector(t, v)
		ran++
	}
	if ran == 0 {
		t.Fatal("every vector was classified slow; the fast suite tested nothing")
	}
	t.Logf("fast vectors run: %d", ran)
}

// The split must actually exclude something, or the classification has
// silently stopped being applied and the suite will creep back to 600s.
func TestSlowVectorsAreExcludedFromFastSuite(t *testing.T) {
	slow := 0
	for _, v := range universalHashRegistry.vectors {
		if universalHashRegistry.isSlow(v.typ) {
			slow++
		}
	}
	if slow == 0 {
		t.Fatal("no vectors are classified slow — expected ~120 high-iteration KDFs")
	}
	t.Logf("slow vectors excluded from the fast suite: %d", slow)
}
```

- [ ] **Step 2: Run the test to verify the split works**

Run: `cd hashsmith/go_hashsmith && go test -run 'TestSelfTestVectors|TestSlowVectors' -timeout 120s ./cmd/hashsmith -v 2>&1 | tail -20`

Expected: PASS, in well under 120s. The log lines report how many vectors ran and how many were excluded. Before this change the same command timed out.

- [ ] **Step 3: Add the slow suite behind a build tag**

Create `selftest_slow_test.go`:

```go
//go:build slowtest

package main

import "testing"

// The high-iteration and memory-hard KDF vectors. Excluded from the default
// suite because they take minutes; run nightly with:
//   go test -tags slowtest -timeout 60m ./cmd/hashsmith
func TestSelfTestVectorsSlow(t *testing.T) {
	ran := 0
	for _, v := range universalHashRegistry.vectors {
		if !universalHashRegistry.isSlow(v.typ) {
			continue
		}
		checkSelfTestVector(t, v)
		ran++
	}
	if ran == 0 {
		t.Fatal("no slow vectors ran")
	}
	t.Logf("slow vectors run: %d", ran)
}
```

- [ ] **Step 4: Verify the slow suite compiles and the full default suite is green**

Run: `cd hashsmith/go_hashsmith && go vet -tags slowtest ./cmd/hashsmith && time go test ./cmd/hashsmith 2>&1 | tail -5`

Expected: vet clean; `ok hashsmith-go/cmd/hashsmith` and a wall time under 60s. Record the actual time — Task 4 asserts it.

- [ ] **Step 5: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/selftest_test.go \
        hashsmith/go_hashsmith/cmd/hashsmith/selftest_slow_test.go
git commit -m "fix: honor slow-KDF classification in the self-test suite

TestSelfTestVectorsAllPass ran every vector including ~120 memory-hard
KDFs, so go test ./... died at the 600s timeout inside a VeraCrypt
500k-iteration PBKDF2-HMAC-Whirlpool vector. The registry already had
isSlow(); the test just ignored it. Slow vectors move behind the
slowtest build tag for nightly runs."
```

---

## Task 2: Stop fast-classified vectors from silently becoming slow

A classification nothing enforces will drift back. Give each fast vector a time budget so a misclassification fails the build with a clear instruction.

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/selftest_test.go`

**Interfaces:**
- Consumes: `checkSelfTestVector` from Task 1.
- Produces: nothing new; tightens the existing fast suite.

- [ ] **Step 1: Write the failing test**

Add to `selftest_test.go`:

```go
// fastVectorBudget is the per-vector ceiling for the default suite. A vector
// slower than this belongs in slowSelfTestTypeSeed().
const fastVectorBudget = 50 * time.Millisecond

// A fast-classified vector that takes longer than the budget has been
// misclassified; failing here keeps the default suite from creeping back
// toward the 600s timeout one vector at a time.
func TestFastVectorsStayWithinBudget(t *testing.T) {
	var over []string
	for _, v := range universalHashRegistry.vectors {
		if universalHashRegistry.isSlow(v.typ) {
			continue
		}
		start := time.Now()
		verifyCandidate(v.password, v.target, v.typ, v.salt, "prefix")
		if d := time.Since(start); d > fastVectorBudget {
			over = append(over, fmt.Sprintf("%s took %v", v.typ, d.Round(time.Millisecond)))
		}
	}
	if len(over) > 0 {
		t.Errorf("%d fast-classified vector(s) exceeded %v; add each type to "+
			"slowSelfTestTypeSeed() in selftest.go:\n  %s",
			len(over), fastVectorBudget, strings.Join(over, "\n  "))
	}
}
```

Add `"fmt"`, `"time"` to the import block (`strings` and `testing` are already imported).

- [ ] **Step 2: Run it**

Run: `cd hashsmith/go_hashsmith && go test -run TestFastVectorsStayWithinBudget -timeout 300s ./cmd/hashsmith -v 2>&1 | tail -30`

Expected: either PASS, or a FAIL naming specific types. **A failure here is real information, not a broken test** — it means those types were misclassified.

- [ ] **Step 3: Fix any reported misclassifications**

For each type the test names, add it to the map returned by `slowSelfTestTypeSeed()` in `selftest.go:59`, keeping the existing grouping style:

```go
		"some-reported-type": true,
```

If the test passed in Step 2, skip this step and note that in the commit.

- [ ] **Step 4: Verify green**

Run: `cd hashsmith/go_hashsmith && go test -run 'TestSelfTest|TestFastVectors|TestSlowVectors' ./cmd/hashsmith`

Expected: `ok`.

- [ ] **Step 5: Split the four remaining heavy tests (added scope — see the ruling below)**

Task 1 fixed the self-test registry, but the default suite still runs ~160–210s
against the spec's <60s criterion. The remaining cost is four tests that call
cracking functions directly at production iteration counts, outside the
registry's `isSlow` classification:

| Test | File | Cost | Character |
|---|---|---|---|
| `TestVeraCryptVector` | `crack_veracrypt_test.go:10` | 85s | **Mixed** — slow `verifyVeraCrypt`, plus a *fast* `detectHashTypes` assertion |
| `TestVeraCryptStreebogPublishedVector` | `crack_hashcat_crypt_streebog_test.go:8` | 37s | Purely slow KDF verification |
| `TestVeraCryptCascadeRepresentatives` | `crack_hashcat_crypt_cascades_test.go:68` | 19s | Purely slow KDF verification |
| `TestHashcatCryptHeaderPublishedVectors` | `crack_hashcat_crypt_headers_test.go:5` | 8.7s | **Mixed** — slow verify, plus a *fast* `canonicalHashType` alias assertion |

**Do not blanket-move these to the slow suite.** Two of them carry fast
assertions that must stay in the default suite:

- **Purely slow** (`TestVeraCryptStreebogPublishedVector`,
  `TestVeraCryptCascadeRepresentatives`): move the whole test into a new
  `//go:build slowtest` file next to its current one.
- **Mixed** (`TestVeraCryptVector`, `TestHashcatCryptHeaderPublishedVectors`):
  **split** them. The fast assertions — `detectHashTypes(...)` returning
  `[veracrypt]`, and `canonicalHashType(mode)` returning the expected type —
  stay in the default suite as their own test. Only the
  `verifyVeraCrypt` / `verifyCandidate` calls move behind `slowtest`.

Use the `slowtest` build tag, matching Task 1. Do **not** convert these to the
pre-existing `HASHSMITH_EXHAUSTIVE_CRYPTO` env-var idiom
(`crack_hashcat_crypt_streebog_test.go:22`) and do not change that existing
test — a third gating mechanism is worse than two, and churning working code is
out of scope.

- [ ] **Step 6: Verify the split preserved fast coverage and hit the target**

```bash
cd hashsmith/go_hashsmith
# The fast assertions must still run by default — these must appear and pass:
go test -run 'VeraCrypt|HashcatCryptHeader' -v ./cmd/hashsmith 2>&1 | grep -E '^(=== RUN|--- (PASS|FAIL))'
# The whole default suite, timed:
time go test -count=1 -timeout 300s ./cmd/hashsmith
# The slow suite must still compile and contain the moved tests:
go vet -tags slowtest ./cmd/hashsmith
go test -tags slowtest -run 'TestVeraCryptStreebogPublishedVector' -timeout 600s ./cmd/hashsmith
```

Expected: the default suite under 60s; the fast detection/alias assertions
still present and passing; the slow build compiles and the moved test runs
under the tag. **Report the measured wall time.** If it is still above 60s,
report what dominates rather than moving more tests on your own judgement.

- [ ] **Step 7: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/
git commit -m "test: budget fast vectors and move heavy KDF tests to slowtest

Enforces a 50ms per-vector budget so the default suite cannot drift back
toward the 600s timeout as new high-iteration formats are added.

Also moves the four remaining production-iteration tests behind the
slowtest tag. TestVeraCryptVector and TestHashcatCryptHeaderPublishedVectors
are split rather than moved: their detectHashTypes and canonicalHashType
assertions are fast and stay in the default suite, so only the KDF
verification moves to nightly."
```

---

## Task 3: Fix the benchmark deadline overrun and its per-iteration allocation

`benchType` checks its deadline every 1024 iterations. At bcrypt cost 10 (~60ms/op) that commits to ~61s against a 1.0s budget — the cause of the 13 CPU-minute hang. It also calls `fv.match(string(buf))`, allocating a string per iteration, which understates every reported rate (5.46 MH/s for MD5 versus the 10.24 MH/s the real brute path achieves).

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/benchmark.go` (the `benchType` worker loop)
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/benchmark_test.go`

**Interfaces:**
- Consumes: `newFastVerifier(typ, targetHex string) (*fastVerifier, bool)` (`hashfast.go:79`), `benchSeed(typ string) (string, bool)`
- Produces: `benchType(typ string, workers int, dur time.Duration) (float64, bool)` — signature unchanged; only its timing behavior and allocation profile change.

- [ ] **Step 1: Write the failing test**

Add to `benchmark_test.go`:

```go
// A slow KDF must not overrun its time budget. The old loop checked the
// deadline every 1024 iterations, so bcrypt (~60ms/op) ran ~61s against a
// 1s budget.
func TestBenchTypeRespectsBudgetForSlowKDF(t *testing.T) {
	budget := 300 * time.Millisecond
	start := time.Now()
	if _, ok := benchType("bcrypt", 2, budget); !ok {
		t.Skip("bcrypt not benchmarkable in this build")
	}
	elapsed := time.Since(start)
	// One in-flight op per worker may still complete after the deadline;
	// bcrypt cost 10 is ~60ms, so allow generous slack but nothing like 61s.
	if elapsed > budget+2*time.Second {
		t.Errorf("bcrypt benchmark overran its %v budget: took %v", budget, elapsed)
	}
}

// matchBytes exists to remove the string conversion the measurement loop was
// paying per candidate. It must allocate strictly less than the string path.
//
// Note it is NOT expected to reach zero: the local digest buffer escapes
// because buf[:] is passed to a func-typed struct field the compiler cannot
// see through (measured: match() is 64 B/op, 1 allocs/op). Removing that last
// allocation would need a verifier-owned scratch field, and fastVerifier is
// shared across workers on the non-batch path, where a mutable field would
// race. The win being asserted here is the string conversion, nothing more.
func TestMatchBytesAllocatesLessThanMatch(t *testing.T) {
	fv, ok := newFastVerifier("md5", "5f4dcc3b5aa765d61d8327deb882cf99")
	if !ok {
		t.Fatal("md5 must have a fast verifier")
	}
	buf := []byte("benchAAAA")
	viaString := testing.AllocsPerRun(1000, func() { fv.match(string(buf)) })
	viaBytes := testing.AllocsPerRun(1000, func() { fv.matchBytes(buf) })
	if viaBytes >= viaString {
		t.Errorf("matchBytes allocated %v/run, match(string) allocated %v/run; "+
			"matchBytes must allocate strictly less", viaBytes, viaString)
	}
	t.Logf("allocs per run: match(string)=%v matchBytes=%v", viaString, viaBytes)
}
```

Ensure `"time"` and `"testing"` are imported.

- [ ] **Step 2: Run to verify both fail**

Run: `cd hashsmith/go_hashsmith && go test -run 'TestBenchTypeRespectsBudget|TestMatchBytesAllocatesLess' -timeout 300s ./cmd/hashsmith`

Expected: FAIL — `fv.matchBytes undefined`, and the bcrypt test overruns.

- [ ] **Step 3: Add the allocation-free byte entry point**

In `hashfast.go`, add alongside the existing `match`:

```go
// matchBytes is match for a candidate already in a byte slice — the form the
// batch pipeline produces. No string conversion, so no allocation.
func (f *fastVerifier) matchBytes(candidate []byte) bool {
	var buf [64]byte
	n := f.hashBytes(buf[:], candidate)
	if n != f.tlen {
		return false
	}
	for i := 0; i < n; i++ {
		if buf[i] != f.target[i] {
			return false
		}
	}
	return true
}
```

This requires `fastVerifier` to hold a byte-taking hasher. In `hashfast.go`, add a `hashBytes func(dst, s []byte) int` field to the `fastVerifier` struct, and a `rawHasherBytes(typ string) (func(dst, s []byte) int, bool)` mirroring `rawHasher` but taking `[]byte`. For the entries that currently do `md5.Sum([]byte(s))`, the byte version is `md5.Sum(s)` and so on. Populate it in `newFastVerifier` next to `hash`.

**Also fix the md4/ntlm entries while here** — they call `h.Sum(nil)`, which allocates on every candidate:

```go
	case "md4":
		return func(dst, s []byte) int {
			h := md4.New()
			_, _ = h.Write(s)
			var tmp [16]byte
			return copy(dst, h.Sum(tmp[:0]))
		}, true
```

- [ ] **Step 4: Fix the deadline stride in `benchType`**

Replace the fixed `local&1023` check in the worker loop with an adaptive stride. Before launching workers, time one operation to size it:

```go
	// Size the deadline-check stride from the measured cost of one op, so a
	// slow KDF checks every iteration while a fast digest is not distorted by
	// calling time.Now() in the hot loop.
	probeStart := time.Now()
	if fast {
		fv.matchBytes([]byte("benchprobe"))
	} else {
		verifyCandidate("benchprobe", target, typ, "", "prefix")
	}
	perOp := time.Since(probeStart)
	stride := int64(1)
	if perOp > 0 {
		stride = int64(time.Millisecond / perOp)
	}
	if stride < 1 {
		stride = 1
	}
	if stride > 1024 {
		stride = 1024
	}
	mask := int64(1)
	for mask < stride {
		mask <<= 1
	}
	mask--
```

Then in the worker loop use `local&mask == 0` instead of `local&1023 == 0`, and call `fv.matchBytes(buf)` instead of `fv.match(string(buf))`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd hashsmith/go_hashsmith && go test -run 'TestBenchType' -timeout 300s ./cmd/hashsmith -v 2>&1 | tail -15`

Expected: PASS for both.

- [ ] **Step 6: Verify the real command and record the corrected baseline**

Run:
```bash
cd hashsmith/go_hashsmith && go build -o /tmp/hs ./cmd/hashsmith
time /tmp/hs benchmark -N
for t in md5 md4 ntlm sha1 sha256 sha512; do /tmp/hs benchmark -t $t -d 1 -N 2>&1 | grep -E "^  $t "; done
```

Expected: the full default set completes in under 30s wall (previously never finished). MD5 should now report near 10 MH/s rather than 5.46. **Record these numbers in the commit message — they are the baseline Phase 1 is measured against.**

- [ ] **Step 7: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/benchmark.go \
        hashsmith/go_hashsmith/cmd/hashsmith/benchmark_test.go \
        hashsmith/go_hashsmith/cmd/hashsmith/hashfast.go
git commit -m "fix: benchmark overran its budget ~1000x and measured the allocator

benchType checked its deadline only every 1024 iterations, so bcrypt
(~60ms/op) ran ~61s against a 1s budget; a plain 'hashsmith benchmark'
burned 13 CPU-minutes without finishing. Stride is now sized from a
measured per-op cost.

The loop also called fv.match(string(buf)), allocating per iteration and
understating every rate. Adds fastVerifier.matchBytes and a byte-taking
rawHasherBytes, and drops the per-call h.Sum(nil) allocation in the
md4/ntlm hashers."
```

---

## Task 4: CI that keeps this green

**Files:**
- Create: `.github/workflows/ci.yml`
- Inspect first: `.github/` (a directory already exists; check for an existing workflow before creating one)

**Interfaces:**
- Consumes: the fast/slow split from Tasks 1–2.
- Produces: a CI contract later phases rely on.

- [ ] **Step 1: Check what already exists**

Run: `ls -la .github/ .github/workflows/ 2>/dev/null && cat .github/workflows/*.yml 2>/dev/null`

If a workflow already exists, extend it rather than creating a second one.

- [ ] **Step 2: Write the workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 3 * * *"   # nightly slow-KDF vectors

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: Build
        run: cd hashsmith/go_hashsmith && CGO_ENABLED=0 go build ./...
      - name: Vet
        run: cd hashsmith/go_hashsmith && go vet ./...
      - name: Test (fast vectors)
        run: cd hashsmith/go_hashsmith && go test -timeout 5m ./...

  race:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      # The race detector is what guards the concurrent keyspace runner added
      # in Phase 1. Two tests are excluded, and NEITHER should be re-added:
      # TestBenchTypeRespectsBudgetForSlowKDF and TestFastVectorsStayWithinBudget
      # are both wall-clock budget assertions. A race build carries ~10x
      # instrumentation overhead, so under -race they measure the instrumentation
      # rather than the code — an absolute millisecond threshold is meaningless
      # there, not merely strained. Loosening their constants to suit -race would
      # weaken them in the normal lane, which is where they do their real work.
      # Neither contributes anything to race detection.
      - name: Test (race detector)
        run: |
          cd hashsmith/go_hashsmith
          go test -race -timeout 20m \
            -skip 'TestBenchTypeRespectsBudgetForSlowKDF|TestFastVectorsStayWithinBudget' ./...

  cross-compile:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: Cross-compile all targets
        run: |
          cd hashsmith/go_hashsmith
          for target in linux/amd64 linux/arm64 windows/amd64 darwin/arm64; do
            echo "building $target"
            GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 \
              go build -o /dev/null ./cmd/hashsmith
          done

  slow-vectors:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: Test (all vectors incl. slow KDFs)
        run: cd hashsmith/go_hashsmith && go test -tags slowtest -timeout 60m ./...
```

- [ ] **Step 3: Verify the commands locally**

Run:
```bash
cd hashsmith/go_hashsmith && CGO_ENABLED=0 go build ./... && go vet ./... && go test -timeout 5m ./...
for target in linux/amd64 linux/arm64 windows/amd64 darwin/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/hashsmith && echo "$target ok"
done
```

Expected: all green, all four targets build.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: build, vet, fast tests, cross-compile, nightly slow vectors

Locks in the Phase 0 guarantees: default suite green in minutes, the
cgo-free static build cross-compiles to all four release targets, and
the slow-KDF vectors still run nightly."
```

---

# Phase 1 — Interleaved hash cores

> **Read this before starting Phase 1.**
>
> Phase 1's entire value depends on one unproven assumption: that a
> hand-written 4-way NEON MD5 in Go assembly can substantially beat Go's
> `crypto/md5`. **A pure-Go interleaved core was measured and rejected** — a
> fully-unrolled 4-lane implementation with all state in named scalars ran at
> **1.76 MH/s against `crypto/md5`'s 4.27 MH/s** (best of 5, single core,
> Apple M2). It is *slower*, because 4 lanes × (4 state + 16 message) words
> vastly exceed arm64's 31 general-purpose registers and spill to memory.
>
> The batch seam (Tasks 6–9) is **scaffolding with little standalone value** —
> roughly 1.15x from removing per-candidate allocations. It is worth building
> only to feed a vector core that actually delivers.
>
> **Therefore Task 5 is a spike and a hard go/no-go gate. Do not start Tasks
> 6–11 until it passes.**

### Outcome of the gate — read this too, it rewrote Tasks 6–9

Task 5 returned **NO-GO**: a correct 4-way NEON core reached only **1.26x**
core-only and **1.06x** end to end. Root cause: MD5's 64 steps are a strict
serial dependency chain, so wall-clock is **latency**-bound, not
throughput-bound — and NEON's per-step latency is *worse* than scalar, because
arm64 has no vector barrel-rotate (`VSHL`+`VSRI`, two dependent ops, against one
`RORW`) and `F`/`G` need an extra `VMOV` before the destructive `VBSL`.

**A correction to Section 2.3 of the spec:** it claims Go's `crypto/md5` ships
no arm64 assembly. That is false — `$(go env GOROOT)/src/crypto/md5/md5block_arm64.s`
exists. The baseline was never a soft target, and the "3–4x from replacing a
generic block function" headroom the spec projected does not exist.

Task 5b then tested the one lever Task 5 had flagged but not tried —
**software pipelining**, running several independent chains so an out-of-order
core overlaps their stalls — and returned **GO**:

| | MH/s | vs baseline |
|---|---|---|
| `crypto/md5` (same invocation, best of 14) | 6.46 | 1.00x |
| Pipelined, 5 chains / 20-way, core only | **36.01** | **5.58x** |
| Same, end to end with pack-then-transpose | 13.92 | 2.16x |

Two conclusions drive the task list below:

1. **Transpose elimination is the critical path.** It is the entire difference
   between 2.16x and 5.58x. Candidates are *generated* from a keyspace, so they
   can be written straight into the padded, transposed layout — Task 6.
2. **The general batch seam is cancelled.** `CandidateBatch`, `BatchVerifier`
   and the legacy adapter were designed when batching itself looked like the
   win. A byte-oriented batch cannot feed the fast path, and the ~455 non-raw-digest
   formats can never use a 4-lane MD5 core anyway. Building a seam through the
   verification path of every format would be the largest correctness risk in
   the plan for no measured gain. Tasks 6–9 build a **narrow fast path**
   instead — (raw MD5) × (fixed-length keyspace) — and leave every other format
   on exactly today's code.

**Caveats binding Tasks 6–9:** the 5.58x assumes generation in transposed
layout, which is unbuilt engineering, not a measurement; untranspose and
digest-compare were assumed near-zero and never measured; and saturation was
never found — the spike hit the 32-register wall at 5 chains while still
improving, so 5.58x is a floor for the core, not a ceiling.

---

## Task 5: NEON MD5 spike — go/no-go gate

**This is a spike. Its output is an answer and a recommendation, not code you keep.** Timebox: stop and report if it exceeds roughly a day of effort.

**Why NEON should succeed where pure Go failed:** arm64 has **32 × 128-bit vector registers**. A 4-way interleaved MD5 needs 4 state vectors (each holding one state word across 4 lanes) plus 16 message vectors — 20 registers, comfortably resident, with room for temporaries. That is precisely the register pressure that defeated the GPR version.

**Files:**
- Create (throwaway): a scratch Go module outside the repo, e.g. `/tmp/md5neon/`
- Create if the spike succeeds: nothing yet — productionizing is Task 10

**Interfaces:**
- Consumes: nothing.
- Produces: a measurement and a written recommendation. If it passes, the assembly file it produced becomes the starting point for Task 10.

- [ ] **Step 1: Establish the baseline on the target machine**

```bash
mkdir -p /tmp/md5neon && cd /tmp/md5neon && printf 'module md5neon\n\ngo 1.21\n' > go.mod
cat > base_test.go <<'EOF'
package main

import ("crypto/md5"; "testing")

func BenchmarkCryptoMD5(b *testing.B) {
	in := []byte("candidate")
	for i := 0; i < b.N; i++ { md5.Sum(in) }
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
}
EOF
go test -run XXX -bench . -benchtime 2s -count 5 . 2>&1 | grep MH/s
```

Record the **best** figure. On the reference M2 this is ~4.3 MH/s single core.

- [ ] **Step 2: Write the NEON 4-way core**

Create `md5neon_arm64.s` and its Go declaration. The shape:

```go
//go:build arm64

package main

//go:noescape
func md5x4NEON(state *[4][4]uint32, msg *[4][16]uint32)
```

Assembly notes for the implementer:

- Go uses Plan 9 assembly. arm64 NEON vector operands are written `V0.S4`
  (four 32-bit lanes).
- State: `V0`–`V3` hold a, b, c, d, each with one lane per message.
- Message: `V4`–`V19` hold `M[0]`–`M[15]`, lane *i* being message *i*'s word.
  The caller must transpose four messages into this layout.
- Instructions needed: `VADD` (`VADD V1.S4, V2.S4, V3.S4`), `VEOR`, `VAND`,
  `VORR`, `VBIC` (bit clear — computes `a AND NOT b`, which gives the `^b & d`
  term directly), `VSHL`, `VUSHR`, `VSRI`.
- Rotate left by *n*: `VSHL $n, Vx.S4, Vtmp.S4` then `VSRI $(32-n), Vx.S4,
  Vtmp.S4` — `VSRI` shifts right and inserts, merging both halves in one op.
- Round constants differ per round and are scalar; load each into a vector
  with `VDUP` from a general register, or keep a constant table in memory and
  `VLD1` it.
- The round structure is identical to the reference implementation; only the
  data layout changes.

**Correctness before speed.** Port the reference from
`docs/superpowers/specs/` Task 9 history or regenerate it, and assert every
lane matches `crypto/md5` for all lengths 0–55 before benchmarking anything.

- [ ] **Step 3: Verify correctness**

```go
func TestNEONMatchesCryptoMD5(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for length := 0; length <= 55; length++ {
		var msgs [4][]byte
		for l := range msgs { b := make([]byte, length); rng.Read(b); msgs[l] = b }
		got := hashFourNEON(msgs) // your padding + transpose + md5x4NEON wrapper
		for l := range msgs {
			if want := md5.Sum(msgs[l]); got[l] != want {
				t.Fatalf("len %d lane %d: got %x want %x", length, l, got[l], want)
			}
		}
	}
}
```

Expected: PASS for all 56 lengths × 4 lanes. **Do not proceed to Step 4 until this passes** — a fast wrong answer is worthless.

- [ ] **Step 4: Benchmark and compare**

```bash
go test -run XXX -bench . -benchtime 2s -count 5 . 2>&1 | grep MH/s
```

Report MH/s **per candidate** (that is, `b.N * 4 / seconds` for the 4-way core) against the Step 1 baseline.

- [ ] **Step 5: Decide and report**

Write the outcome to `docs/superpowers/notes/2026-08-31-neon-md5-spike.md`:

- The Step 1 baseline and the Step 4 result, both best-of-5.
- The speedup ratio per candidate.
- Whether the correctness suite passed.
- Effort actually spent.

**The gate:**

| Result | Decision |
|---|---|
| **≥ 3x** `crypto/md5` per candidate | **GO.** Proceed to Task 6. The spec's 100 MH/s floor is reachable. |
| **1.5x – 3x** | **Report and ask.** The seam's complexity may not be repaid; the user decides. |
| **< 1.5x** | **NO-GO.** Report. Phase 1 as specified does not work; the spec needs revisiting, and the honest recommendation is likely to redirect effort to Phase 2 (reach and workflow features), where the wins are certain. |

- [ ] **Step 6: Stop**

**This is a hard checkpoint.** Report the number and the recommendation, and get an explicit decision before starting Task 6. Do not begin the batch seam on the assumption that the spike passed.

---
## Task 6: Generate candidates directly in transposed NEON layout

**This is the critical path.** Task 5b measured the pipelined core at 5.58x
baseline, but only 2.16x once packing-then-transposing was included — the
transpose ate 61% of the gain. The fix is not to optimise the transpose but to
delete it: a mask/brute keyspace *generates* candidates, so it can write them
straight into the padded, transposed layout the core consumes.

**Files:**
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/transposed.go`
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/transposed_test.go`

**Interfaces:**
- Consumes: `keyspaceLayout` and `maskIdxInto` (`mask.go:173`).
- Produces:
  - `const neonChains = 5`, `const neonLanes = 4`, `const neonGroup = neonChains * neonLanes` (20)
  - `type transposedBatch struct{ words []uint32; length int; n int }`
  - `newTransposedBatch() *transposedBatch`
  - `(*transposedBatch) reset(candidateLen int) error`
  - `(*transposedBatch) fillFromSegment(sets [][]byte, from int64) int`
  - `(*transposedBatch) candidateAt(i int) []byte` — reconstructs candidate i, for reporting a hit
  - `transposedFixedLenOK(n int) bool`

**Layout** (this is the contract the assembly depends on — get it exactly right):
`words` is `[neonChains][16][neonLanes]uint32` flattened. The word for chain
`c`, message-word `w`, lane `l` sits at index `c*64 + w*4 + l`. Candidate index
`i` within the group maps to chain `i/4`, lane `i%4`. Each candidate is one
64-byte MD5 block: its bytes little-endian-packed into words 0..13, then the
`0x80` terminator, then the bit length in word 14 (word 15 stays zero, since
lengths under 56 bytes never reach it).

**Why this is fast:** candidate length is FIXED within a keyspace segment, so
almost the whole block is constant across the group. For a 5-character mask only
words 0 and 1 vary; words 2..13 are zero, word 14 is the constant bit length.
`reset` precomputes the invariant words once; `fillFromSegment` writes only the
words the candidate bytes actually touch.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The transposed layout must describe exactly the same candidates, in the same
// order, that the scalar path produces — and must be recoverable from the
// packed words, which is how a hit is reported.
func TestTransposedRoundTripsCandidates(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de"), []byte("fg")} // 3*2*2 = 12
	tb := newTransposedBatch()
	if err := tb.reset(len(sets)); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n := tb.fillFromSegment(sets, 0)
	if n != 12 {
		t.Fatalf("filled %d, want 12 (the whole segment)", n)
	}
	for i := 0; i < n; i++ {
		want := maskIdxToStr(int64(i), sets)
		if got := string(tb.candidateAt(i)); got != want {
			t.Errorf("candidate %d = %q, want %q", i, got, want)
		}
	}
}

// The packed words must be a correct MD5 block for each candidate: bytes
// little-endian in words 0..13, 0x80 terminator, bit length in word 14.
func TestTransposedBlockIsValidMD5Padding(t *testing.T) {
	sets := [][]byte{[]byte("ab"), []byte("cd"), []byte("ef"), []byte("gh"), []byte("ij")}
	tb := newTransposedBatch()
	if err := tb.reset(5); err != nil {
		t.Fatalf("reset: %v", err)
	}
	tb.fillFromSegment(sets, 0)

	for i := 0; i < 8; i++ {
		cand := tb.candidateAt(i)
		// Rebuild the reference block the scalar way.
		var want [64]byte
		copy(want[:], cand)
		want[len(cand)] = 0x80
		binary.LittleEndian.PutUint64(want[56:], uint64(len(cand))*8)

		chain, lane := i/neonLanes, i%neonLanes
		var got [64]byte
		for w := 0; w < 16; w++ {
			binary.LittleEndian.PutUint32(got[w*4:], tb.words[chain*64+w*4+lane])
		}
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("candidate %d block mismatch:\n got %x\nwant %x", i, got, want)
		}
	}
}

// A partial final group must leave the unused lanes as valid, harmless blocks
// rather than stale data from the previous group — a stale lane could produce a
// spurious hit.
func TestTransposedPartialGroupIsClean(t *testing.T) {
	sets := [][]byte{[]byte("abc")} // 3 candidates, less than one 20-wide group
	tb := newTransposedBatch()
	if err := tb.reset(1); err != nil {
		t.Fatalf("reset: %v", err)
	}
	n := tb.fillFromSegment(sets, 0)
	if n != 3 {
		t.Fatalf("filled %d, want 3", n)
	}
	// Lanes 3..19 are unused. They must be zero-length blocks, not garbage.
	for i := n; i < neonGroup; i++ {
		chain, lane := i/neonLanes, i%neonLanes
		w0 := tb.words[chain*64+0*4+lane]
		if w0 != 0x80 {
			t.Errorf("unused lane %d word0 = %#x, want 0x80 (empty padded block)", i, w0)
		}
	}
}

// Filling must not allocate in steady state — that is the whole point.
func TestTransposedFillDoesNotAllocate(t *testing.T) {
	sets := make([][]byte, 6)
	for i := range sets {
		sets[i] = []byte("abcdefghij")
	}
	tb := newTransposedBatch()
	if err := tb.reset(len(sets)); err != nil {
		t.Fatalf("reset: %v", err)
	}
	got := testing.AllocsPerRun(100, func() { tb.fillFromSegment(sets, 0) })
	if got != 0 {
		t.Errorf("fillFromSegment allocated %v times per run, want 0", got)
	}
}

func TestTransposedFixedLenOK(t *testing.T) {
	for _, c := range []struct {
		n    int
		want bool
	}{{0, true}, {55, true}, {56, false}, {100, false}} {
		if got := transposedFixedLenOK(c.n); got != c.want {
			t.Errorf("transposedFixedLenOK(%d) = %v, want %v", c.n, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestTransposed ./cmd/hashsmith`
Expected: FAIL — `undefined: newTransposedBatch`.

- [ ] **Step 3: Implement**

Create `transposed.go`. Key points: `reset` fills every lane with a valid
padded block for the target length (so unused lanes are harmless), and
`fillFromSegment` overwrites only the words the candidate bytes occupy.

```go
package main

import "encoding/binary"

// Candidate generation directly in the layout the pipelined NEON core reads.
//
// Task 5b measured the core at 5.58x crypto/md5, but only 2.16x when
// candidates were packed as bytes and transposed afterwards. Since a mask or
// brute-force keyspace GENERATES its candidates, the transpose is avoidable
// entirely: write each candidate's words straight into the interleaved slot
// the core will read them from.

const (
	neonChains = 5                        // independent 4-way chains in flight
	neonLanes  = 4                        // 32-bit lanes per 128-bit vector
	neonGroup  = neonChains * neonLanes   // candidates hashed per core call
	transposedMaxLen = 55                 // one MD5 block after padding
)

// transposedFixedLenOK reports whether a candidate length fits one block.
func transposedFixedLenOK(n int) bool { return n >= 0 && n <= transposedMaxLen }

// transposedBatch holds neonGroup candidates of a FIXED length, already padded
// and interleaved. words is [neonChains][16][neonLanes]uint32 flattened: the
// word for chain c, message-word w, lane l is at c*64 + w*4 + l.
type transposedBatch struct {
	words  []uint32
	length int
	n      int
}

func newTransposedBatch() *transposedBatch {
	return &transposedBatch{words: make([]uint32, neonChains*16*neonLanes)}
}

// wordIndex returns the slot for message-word w of candidate i.
func wordIndex(i, w int) int {
	return (i/neonLanes)*64 + w*4 + (i % neonLanes)
}

// reset prepares the batch for candidates of candidateLen bytes, writing a
// valid padded block into EVERY lane. Unused lanes therefore hash an empty
// message rather than stale bytes from the previous group, which could
// otherwise produce a spurious hit.
func reset0(tb *transposedBatch, candidateLen int) error {
	if !transposedFixedLenOK(candidateLen) {
		return errTransposedLen
	}
	tb.length = candidateLen
	tb.n = 0
	for i := range tb.words {
		tb.words[i] = 0
	}
	// Every lane starts as a valid zero-length block: 0x80 at byte 0.
	for i := 0; i < neonGroup; i++ {
		tb.words[wordIndex(i, 0)] = 0x80
	}
	return nil
}

func (tb *transposedBatch) reset(candidateLen int) error { return reset0(tb, candidateLen) }

// fillFromSegment writes up to neonGroup candidates starting at index `from`
// of the mixed-radix segment `sets`, returning how many it wrote. It allocates
// nothing: candidate bytes are decoded into a stack buffer and packed straight
// into their interleaved slots.
func (tb *transposedBatch) fillFromSegment(sets [][]byte, from int64) int {
	total := maskKeyspace(sets)
	n := 0
	var buf [transposedMaxLen]byte
	L := len(sets)
	bitLen := uint32(L) * 8
	for n < neonGroup {
		idx := from + int64(n)
		if idx >= total {
			break
		}
		maskIdxInto(buf[:L], idx, sets)
		// Pack L bytes plus the 0x80 terminator into words 0..(L/4).
		full := L / 4
		for w := 0; w < full; w++ {
			tb.words[wordIndex(n, w)] = binary.LittleEndian.Uint32(buf[w*4:])
		}
		// The partial final word carries the remaining bytes then 0x80.
		rem := L % 4
		var tail uint32
		for b := 0; b < rem; b++ {
			tail |= uint32(buf[full*4+b]) << (8 * b)
		}
		tail |= 0x80 << (8 * rem)
		tb.words[wordIndex(n, full)] = tail
		tb.words[wordIndex(n, 14)] = bitLen
		n++
	}
	tb.n = n
	return n
}

// candidateAt reconstructs candidate i's bytes, for reporting a hit. Not on the
// hot path, so clarity beats speed.
func (tb *transposedBatch) candidateAt(i int) []byte {
	out := make([]byte, tb.length)
	for b := 0; b < tb.length; b++ {
		w := tb.words[wordIndex(i, b/4)]
		out[b] = byte(w >> (8 * (b % 4)))
	}
	return out
}
```

Declare `errTransposedLen` with the other errors in the file, e.g.
`var errTransposedLen = errors.New("candidate length does not fit one MD5 block")`.

**Note on `reset` and partial groups:** after `reset`, lanes beyond `n` still
hold the zero-length block, but `fillFromSegment` writes `bitLen` into word 14
only for lanes it fills — so unused lanes keep bit length 0 and hash the empty
string. That is deliberate and is what `TestTransposedPartialGroupIsClean`
pins down.

- [ ] **Step 4: Run to verify it passes**

Run: `cd hashsmith/go_hashsmith && go test -run TestTransposed ./cmd/hashsmith -v 2>&1 | tail -20`
Expected: all five PASS. `TestTransposedBlockIsValidMD5Padding` is the important
one — it proves the layout matches what a scalar MD5 would see.

- [ ] **Step 5: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/transposed.go \
        hashsmith/go_hashsmith/cmd/hashsmith/transposed_test.go
git commit -m "feat: generate candidates directly in transposed NEON layout

The pipelined core measured 5.58x crypto/md5, but only 2.16x once
packing-then-transposing was counted. A mask or brute keyspace generates
its candidates, so the transpose is avoidable rather than optimisable:
write each candidate straight into the interleaved slot the core reads.

Candidate length is fixed within a keyspace segment, so most of the
64-byte block is invariant and is precomputed once per group."
```

---

## Task 7: Productionize the pipelined NEON core

**Files:**
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/md5neon_arm64.s` (from the Task 5b spike, `/tmp/md5neon/`)
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/md5neon_arm64.go` (`//go:build arm64`)
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/md5neon_generic.go` (`//go:build !arm64`)
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/md5neon_test.go`

**Interfaces:**
- Consumes: `transposedBatch` (Task 6); the verified assembly in `/tmp/md5neon/`.
- Produces:
  - `md5Group(tb *transposedBatch, out *[neonGroup][16]byte)` — hashes all `neonGroup` lanes. **NEON on arm64, a `crypto/md5` loop everywhere else. Both must produce identical output.**
  - `md5GroupAccelerated() bool` — whether this build has the vector core (for reporting).

- [ ] **Step 1: Port the spike's assembly**

The spike's working 5-chain (20-way) core lives in `/tmp/md5neon/` alongside its
generator (`gen3.py`) and tests. Bring the `.s` file and its `//go:noescape`
declaration into the package, adapting the entry point to take the
`transposedBatch.words` pointer directly — the layouts were designed to match,
so no marshalling should be needed. Keep the generator script's output
reproducible; if the assembly is generated, commit the generator alongside it
and say so in the file header.

- [ ] **Step 2: Write the portable fallback FIRST and prove the contract**

The fallback is mandatory (Global Constraints) and doubles as the reference the
assembly is tested against.

```go
//go:build !arm64

package main

import "crypto/md5"

// md5Group is the portable fallback: no vector core on this architecture, so
// hash each lane individually. Output is identical to the NEON path by
// construction — this is also the oracle md5neon_test.go compares against.
func md5Group(tb *transposedBatch, out *[neonGroup][16]byte) {
	for i := 0; i < neonGroup; i++ {
		out[i] = md5.Sum(tb.candidateAt(i))
	}
}

func md5GroupAccelerated() bool { return false }
```

- [ ] **Step 3: Write the correctness test (runs on BOTH builds)**

```go
func TestMD5GroupMatchesCryptoMD5(t *testing.T) {
	for length := 0; length <= transposedMaxLen; length++ {
		sets := make([][]byte, length)
		for i := range sets {
			sets[i] = []byte("abcdefghijklmnop")
		}
		tb := newTransposedBatch()
		if err := tb.reset(length); err != nil {
			t.Fatalf("len %d: reset: %v", length, err)
		}
		tb.fillFromSegment(sets, 0)
		var out [neonGroup][16]byte
		md5Group(tb, &out)
		for i := 0; i < neonGroup; i++ {
			want := md5.Sum(tb.candidateAt(i))
			if out[i] != want {
				t.Fatalf("len %d lane %d: got %x, want %x", length, i, out[i], want)
			}
		}
	}
}

// Lane independence across ALL chains: changing one candidate must perturb no
// other. This is the classic interleaved-SIMD bug and the spike's own suite
// checked it, so the shipped version must too.
func TestMD5GroupLanesAreIndependent(t *testing.T) {
	sets := [][]byte{[]byte("abcde"), []byte("fghij"), []byte("klmno"), []byte("pqrst")}
	tb := newTransposedBatch()
	if err := tb.reset(4); err != nil {
		t.Fatal(err)
	}
	tb.fillFromSegment(sets, 0)
	var ref [neonGroup][16]byte
	md5Group(tb, &ref)

	for changed := 0; changed < neonGroup; changed++ {
		tb2 := newTransposedBatch()
		if err := tb2.reset(4); err != nil {
			t.Fatal(err)
		}
		tb2.fillFromSegment(sets, 0)
		// Perturb exactly one lane's first word.
		tb2.words[wordIndex(changed, 0)] ^= 0x01
		var out [neonGroup][16]byte
		md5Group(tb2, &out)
		for i := 0; i < neonGroup; i++ {
			if i == changed {
				continue
			}
			if out[i] != ref[i] {
				t.Fatalf("changing lane %d altered lane %d", changed, i)
			}
		}
	}
}

func BenchmarkMD5Group(b *testing.B) {
	sets := make([][]byte, 8)
	for i := range sets {
		sets[i] = []byte("abcdefghijklmnopqrstuvwxyz")
	}
	tb := newTransposedBatch()
	if err := tb.reset(len(sets)); err != nil {
		b.Fatal(err)
	}
	var out [neonGroup][16]byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.fillFromSegment(sets, int64(i)*neonGroup)
		md5Group(tb, &out)
	}
	b.ReportMetric(float64(b.N*neonGroup)/b.Elapsed().Seconds()/1e6, "MH/s")
}

func BenchmarkMD5Scalar(b *testing.B) {
	buf := []byte("abcdefgh")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		md5.Sum(buf)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
}
```

- [ ] **Step 4: Verify both builds**

```bash
cd hashsmith/go_hashsmith
go test -run TestMD5Group ./cmd/hashsmith                       # arm64: the NEON core
GOARCH=amd64 GOOS=linux go build ./cmd/hashsmith                # fallback compiles
go vet ./cmd/hashsmith
```
Expected: both correctness tests pass on arm64, and the non-arm64 build
compiles. **If the assembly and fallback disagree on any length or lane, stop —
that is a correctness failure, not a tuning problem.**

- [ ] **Step 5: Measure**

```bash
cd hashsmith/go_hashsmith
go test -run XXX -bench 'BenchmarkMD5Group|BenchmarkMD5Scalar' -benchtime 2s -count 5 ./cmd/hashsmith 2>&1 | grep MH/s
```
Take best-of-5 for each (the machine's load varies ~40% within a session, so
same-invocation best-of-N is the only trustworthy comparison). **Report both
numbers and the ratio.** The spike saw 5.58x core-only; this measurement
includes generation, so expect somewhat less. Record it — Task 9 compares
against it.

- [ ] **Step 6: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/md5neon_arm64.s \
        hashsmith/go_hashsmith/cmd/hashsmith/md5neon_arm64.go \
        hashsmith/go_hashsmith/cmd/hashsmith/md5neon_generic.go \
        hashsmith/go_hashsmith/cmd/hashsmith/md5neon_test.go
git commit -m "feat: pipelined 20-way NEON MD5 core with portable fallback

Five independent 4-way chains, interleaved so the out-of-order core
overlaps their latency: MD5's 64 steps are a serial dependency chain, so
throughput comes from independent work in flight, not from one faster
hash. Register budget is 6N+2, which fits N=5 in 32 vector registers.

Verified against crypto/md5 for every length 0-55 on all 20 lanes, plus
cross-chain lane independence. Non-arm64 builds use a scalar fallback
that is also the test oracle."
```

---

## Task 8: Wire the fast path into cracking

Everything outside this path keeps today's code exactly. The fast path engages
only when all four conditions hold: arm64 with the vector core, target type is
raw MD5, no salt, and the attack is a fixed-length mask/brute segment.

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/keyspace.go` (add the fast runner beside `runLayout`)
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/crack.go` (select it for the `brute`/`mask` cases)
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/fastpath_test.go`

**Interfaces:**
- Consumes: `transposedBatch` + `fillFromSegment` (Task 6), `md5Group` (Task 7), `keyspaceLayout`, `runLayout`.
- Produces:
  - `fastPathEligible(typ, salt string, l *keyspaceLayout) bool`
  - `runLayoutFastMD5(ctx context.Context, l *keyspaceLayout, resumeFrom int64, workers int, atomicAttempts *int64, watermark *int64, target [16]byte) (string, error)`

- [ ] **Step 1: Write the failing test**

```go
// The fast path must find exactly what the scalar path finds — same candidate,
// same keyspace, including when the keyspace is not a multiple of the 20-wide
// group and when the answer sits in the final partial group.
func TestFastPathAgreesWithScalar(t *testing.T) {
	for _, plain := range []string{"aaa", "abc", "zzz", "mnq"} {
		l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
		sum := md5.Sum([]byte(plain))

		var a1, a2 int64
		fast, err := runLayoutFastMD5(context.Background(), l, 0, 4, &a1, nil, sum)
		if err != nil {
			t.Fatalf("%s: fast: %v", plain, err)
		}
		scalar, err := runLayout(context.Background(), l, 0, 4, &a2, nil,
			func(c string) bool { return md5.Sum([]byte(c)) == sum })
		if err != nil {
			t.Fatalf("%s: scalar: %v", plain, err)
		}
		if fast != plain || scalar != plain {
			t.Errorf("%s: fast=%q scalar=%q", plain, fast, scalar)
		}
	}
}

// A miss must exhaust the keyspace and report nothing — and must not report a
// spurious hit from an unused lane in the final partial group.
func TestFastPathExhaustsWithoutSpuriousHit(t *testing.T) {
	l := bruteLayout("ab", 1, 3) // 2 + 4 + 8 = 14, deliberately not a multiple of 20
	sum := md5.Sum([]byte("not-in-keyspace"))
	var attempts int64
	got, err := runLayoutFastMD5(context.Background(), l, 0, 2, &attempts, nil, sum)
	if err != nil {
		t.Fatalf("runLayoutFastMD5: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want no match", got)
	}
	if attempts != l.total {
		t.Errorf("attempts = %d, want the full keyspace %d", attempts, l.total)
	}
}

// The empty-string candidate must be reachable and must not be confused with an
// unused lane, which also hashes the empty string.
func TestFastPathHandlesEmptyCandidate(t *testing.T) {
	l := bruteLayout("ab", 0, 1)
	if l.total == 0 {
		t.Skip("layout does not include the empty candidate")
	}
	sum := md5.Sum([]byte(""))
	var attempts int64
	got, err := runLayoutFastMD5(context.Background(), l, 0, 1, &attempts, nil, sum)
	if err != nil {
		t.Fatalf("runLayoutFastMD5: %v", err)
	}
	if got != "" {
		t.Logf("empty candidate reported as %q", got)
	}
}

func TestFastPathEligibility(t *testing.T) {
	l := bruteLayout("abc", 3, 3)
	if !fastPathEligible("md5", "", l) && md5GroupAccelerated() {
		t.Error("plain md5 fixed-length brute should be eligible on an accelerated build")
	}
	if fastPathEligible("md5", "somesalt", l) {
		t.Error("salted md5 must not be eligible")
	}
	if fastPathEligible("sha256", "", l) {
		t.Error("sha256 must not be eligible — there is no sha256 vector core")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestFastPath ./cmd/hashsmith`
Expected: FAIL — `undefined: runLayoutFastMD5`.

- [ ] **Step 3: Implement**

`runLayoutFastMD5` mirrors `runLayout`'s chunk allocator, watermark, attempt
accounting and cancellation exactly — copy that structure so resume points stay
compatible — but each worker owns a `transposedBatch` and hashes `neonGroup`
candidates per `md5Group` call.

Two correctness requirements to hold onto:
- **Segment boundaries.** A group must not straddle two segments, because
  candidate length changes between them and the batch is fixed-length. Clamp
  each fill to the current segment's end.
- **Partial groups.** When fewer than `neonGroup` candidates remain, only lanes
  `0..n-1` may be considered for a hit. Unused lanes hash the empty string and
  would otherwise produce a false positive whenever the target is
  `md5("")`. `TestFastPathExhaustsWithoutSpuriousHit` and
  `TestFastPathHandlesEmptyCandidate` exist for exactly this.

Then in `crack.go`, in the `brute` and `mask` cases, select `runLayoutFastMD5`
when `fastPathEligible(typ, salt, layout)` and a session resume is not in play;
otherwise call the existing `runSessionLayout` unchanged. `fastPathEligible`
returns false unless `md5GroupAccelerated()`, `canonicalHashType(typ) == "md5"`,
`salt == ""`, and every segment length satisfies `transposedFixedLenOK`.

- [ ] **Step 4: Verify**

```bash
cd hashsmith/go_hashsmith
go test -run TestFastPath ./cmd/hashsmith -v 2>&1 | tail -20
go test -race -run TestFastPath ./cmd/hashsmith
go test ./cmd/hashsmith
go build -o /tmp/hs ./cmd/hashsmith
/tmp/hs crack -t md5 -M brute -C abcdefghijklmnopqrstuvwxyz -n 1 -x 4 \
  $(printf 'cafe' | md5) -N --no-pot
```
Expected: tests pass, race clean, full suite green, and the end-to-end crack
finds `cafe`.

- [ ] **Step 5: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/keyspace.go \
        hashsmith/go_hashsmith/cmd/hashsmith/crack.go \
        hashsmith/go_hashsmith/cmd/hashsmith/fastpath_test.go
git commit -m "feat: route unsalted fixed-length MD5 brute/mask through the NEON core

Engages only on arm64 with the vector core, for raw unsalted MD5 over a
fixed-length keyspace segment. Every other format, salt, and attack mode
keeps exactly today's code path.

Guards the two ways a lane-parallel core can lie: a group never straddles
a segment boundary (candidate length changes there), and unused lanes in
a partial final group are excluded from hit detection, since they hash
the empty string and would otherwise false-positive against md5(\"\")."
```

---

## Task 9: Measure and report

- [ ] **Step 1: Measure end to end, best of 5**

```bash
cd hashsmith/go_hashsmith && go build -o /tmp/hs ./cmd/hashsmith
K=11881376
for i in 1 2 3 4 5; do
  /usr/bin/time -p /tmp/hs crack -t md5 -M brute -C abcdefghijklmnopqrstuvwxyz \
    -n 5 -x 5 -p 8 fa246d0262c3925617b0c72bb20eeb1d -N --no-pot >/dev/null
done 2>&1 | awk -v k=$K '/real/{if(m==0||$2<m)m=$2} END{printf "best %.2fs  %.2f MH/s\n", m, k/m/1e6}'
```
Baseline to beat: **10.24 MH/s** (the spec's measured figure for this exact
command). Re-measure the baseline in the same session by checking out the
commit before Task 8 and running the identical command — the machine's load
varies ~40% within a session, so only same-session comparisons mean anything.

- [ ] **Step 2: Measure the kernel with `testing.B`**

```bash
go test -run XXX -bench 'BenchmarkMD5Group|BenchmarkMD5Scalar' -benchtime 2s -count 5 ./cmd/hashsmith 2>&1 | grep MH/s
```
Best-of-5 each. `hashsmith benchmark` is NOT an acceptance gate — Task 3's
review measured a >4x run-to-run spread in it.

- [ ] **Step 3: Write the report**

Create `docs/superpowers/notes/2026-08-31-phase1-measurements.md` recording:
- End-to-end MD5 before and after, same session, best-of-5 each.
- Kernel `testing.B` before and after.
- How much of the spike's 5.58x survived integration, and where the rest went.
- **A revised, measured statement of what Hashsmith's MD5 throughput now is**,
  replacing the spec's 100 MH/s floor, which was set before any of this was
  known and is almost certainly unreachable on this CPU.
- A recommendation on what is worth doing next: an MD4/NTLM core (same
  structure, and NTLM dominates Active Directory work), an amd64 AVX2 core
  (8-16 lanes, where JtR's large CPU figures actually come from), or stopping
  here and moving to Phase 2 reach features.

- [ ] **Step 4: Commit and stop**

```bash
git add docs/superpowers/notes/2026-08-31-phase1-measurements.md
git commit -m "docs: record measured Phase 1 throughput and revise the target"
```

**This is a hard checkpoint.** Report the numbers and the recommendation, and
get a decision before starting any further core work.

---
## Self-Review Notes

**Spec coverage:**
- Spec §4.1 (slow-vector split) → Task 1
- Spec §4.2 (time budget) → Task 2
- Spec §4.3 + §4.3.1 (deadline fix, allocation-free harness) → Task 3
- Spec §4.4 (CI) → Task 4
- Spec §4.5 (Phase 0 acceptance) → Tasks 1–4; verified in Task 1 Step 4, Task 3 Step 6, Task 4 Step 3
- Spec §5.4 (SIMD cores, priority 1 = MD5) → Tasks 5/5b (spikes), 7 (productionize)
- Spec §5.5 (correctness strategy) → Task 7 Steps 3–4: differential against `crypto/md5` at every length 0–55 on all 20 lanes, cross-chain lane independence, and the same suite run on both the NEON and fallback builds. Task 4's cross-compile job builds the fallback for every target but does not run it — it cannot substitute for actually executing the suite on the fallback path; see the deviation entry below for what §5.5 still lacks.
- Spec §5.6 (acceptance criteria) → Task 9, **which is required to restate them**: the 100 MH/s floor was set before any measurement and is almost certainly unreachable on this CPU
- Spec §6 (Phase 2/3 roadmap) → out of scope for this plan

**Deviations from the spec, with evidence:**

1. **§2.3 is factually wrong.** It states Go's `crypto/md5` ships no arm64
   assembly; `md5block_arm64.s` exists. The projected "3–4x from replacing a
   generic block function" does not exist. Discovered by Task 5.
2. **§2.4's competitive gap is unverified.** The "JtR ~250–400 MH/s on the same
   CPU, ~25–40x" row was an estimate, not a measurement. JtR's large CPU figures
   come from x86 AVX2/AVX-512 (8–16 lanes), not 4-lane NEON, so the arm64 gap is
   likely much smaller. Task 9 must not treat that row as a target.
3. **§5.1–5.3's batch seam is cancelled.** `CandidateBatch`, `BatchVerifier` and
   the legacy adapter assumed batching was itself the win. Task 5b showed the
   win requires *transposed generation*, which a byte-oriented batch cannot
   supply, and no non-raw-digest format can use a 4-lane MD5 core regardless.
   Replaced by a narrow fast path (Tasks 6–8) that leaves all other formats
   untouched — same gain, far smaller blast radius.
4. **The pure-Go interleaved core (originally Task 9) is cut.** Measured at
   1.27–1.76 MH/s against a 4.27 MH/s baseline — slower, from register spilling.
5. **§5.5's correctness strategy was 3-of-4 unmet.** Of the four numbered
   items in spec §5.5, only item 3 (lane-independence, shipped as
   `TestMD5GroupLanesAreIndependent`) was implemented as specified. Items 1,
   2, and 4 were not:
   - §5.5.1 calls for a differential property test across every length 0–256
     (shipped only 0–55, matching this format's one-block limit — acceptable)
     *and* across every lane-count remainder (a batch of 1, 2, 3, ...
     candidates must match a full batch). The remainder half was never added:
     `TestMD5GroupMatchesCryptoMD5` always fills the full 20-lane group, so no
     CI test exercises a partially-filled group. This is the exact gap a
     later review flagged: the portable fallback's md5Group, doubling as the
     test oracle, read `tb.length` bytes from every lane via `candidateAt`
     instead of each lane's own encoded bit length, so it silently hashed the
     wrong thing on lanes `fillFromSegment` had cleaned to the empty message
     — hiding a real padding-lane false-hit bug from CI on amd64 (the only
     architecture CI runs). This wave's Item 1 fixes the oracle to decode
     each lane from its own transposed words, which is a necessary
     precondition for a real §5.5.1 remainder test but is not that test
     itself — the dedicated 1/2/3-lane-remainder differential §5.5.1 asks for
     still does not exist.
   - §5.5.2's requirement that "the existing self-test vectors run against the
     SIMD path as well as the portable path" was not implemented as written:
     no test round-trips the standard known-answer vectors through `md5Group`
     specifically; correctness there rests only on the fast-path integration
     tests and the differential test above.
   - §5.5.4's build flag that "forces the generic core so the same suite
     proves both paths agree" does not exist. Fallback coverage today comes
     only from cross-compiling to non-arm64 (the `!arm64` build tag on
     `md5neon_generic.go` selects it naturally) — there is no way to force
     the generic path on an arm64 machine to compare it against the NEON path
     in the same run.

**Known deferrals, to be planned separately once Task 9 reports:**
- MD4/NTLM core, same structure as Task 7 (NTLM dominates Active Directory work)
- amd64 AVX2/AVX-512 core (8–16 lanes; where JtR's large CPU figures come from)
- The SHA-1/SHA-256/SHA-512 measure-then-decide gate (spec §5.4 priorities 3–5),
  noting both already reach ARMv8 crypto instructions on arm64
- Saturation beyond 5 chains, which the 32-register budget blocked

**Type consistency:** the identifiers Tasks 6-9 define and consume are `neonChains` / `neonLanes` / `neonGroup` / `transposedMaxLen`, `transposedBatch` with `reset` / `fillFromSegment` / `candidateAt` / `words`, `wordIndex`, `transposedFixedLenOK`, `newTransposedBatch`, `md5Group`, `md5GroupAccelerated`, `fastPathEligible`, and `runLayoutFastMD5` — each defined once and used with the same signature throughout. `fastVerifier.matchBytes` and `rawHasherBytes` ship from Task 3 and are unchanged by Phase 1.

The seam identifiers from the cancelled design — `CandidateBatch`, `Hit`, `BatchVerifier`, `batchTarget`, `newBatchVerifier`, `md5x4Short`, `(*keyspaceLayout).fill`, `runLayoutBatch` — appear nowhere in Tasks 6-9 and must not be reintroduced.
