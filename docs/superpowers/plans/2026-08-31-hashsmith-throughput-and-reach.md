# Hashsmith Throughput and Reach Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get Hashsmith's test suite green in under 60 seconds, then raise MD5/MD4/NTLM cracking throughput from ~10 MH/s toward JtR-class speed by batching candidates and interleaving the hash cores.

**Architecture:** Phase 0 makes the existing self-test honor the slow-KDF classification it already has, and fixes the benchmark harness so it is a trustworthy baseline. Phase 1 opens with a **timeboxed NEON assembly spike that is a hard go/no-go gate** — a pure-Go interleaved core was already built and measured *slower* than `crypto/md5`, so the vector registers are the whole thesis. Only if the spike passes does the batch seam (`CandidateBatch` / `BatchVerifier`) get built to feed it, with all 461 formats kept working through a legacy adapter and a portable fallback on every non-arm64 target.

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
## Task 6: The `CandidateBatch` buffer

A 4-way core needs four candidates at once. This is the reusable, allocation-free buffer that feeds it.

**Files:**
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/batchseam.go`
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/batchseam_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `const batchSize = 512`
  - `type CandidateBatch struct{ buf []byte; off []int32; n int }`
  - `newCandidateBatch(capBytes int) *CandidateBatch`
  - `(*CandidateBatch) Reset()`
  - `(*CandidateBatch) Add(word []byte) bool`
  - `(*CandidateBatch) At(i int) []byte`
  - `(*CandidateBatch) Len() int`
  - `type Hit struct{ Cand, Target int }`
  - `type BatchVerifier interface{ VerifyBatch(b *CandidateBatch, hits []Hit) int }`

- [ ] **Step 1: Write the failing test**

Create `batchseam_test.go`:

```go
package main

import (
	"bytes"
	"testing"
)

func TestCandidateBatchRoundTrip(t *testing.T) {
	b := newCandidateBatch(1024)
	words := [][]byte{[]byte("a"), []byte(""), []byte("hello"), []byte("password123")}
	for _, w := range words {
		if !b.Add(w) {
			t.Fatalf("Add(%q) returned false on an empty batch", w)
		}
	}
	if b.Len() != len(words) {
		t.Fatalf("Len() = %d, want %d", b.Len(), len(words))
	}
	for i, w := range words {
		if got := b.At(i); !bytes.Equal(got, w) {
			t.Errorf("At(%d) = %q, want %q", i, got, w)
		}
	}
}

func TestCandidateBatchResetReusesMemory(t *testing.T) {
	b := newCandidateBatch(1024)
	b.Add([]byte("first"))
	bufBefore, offBefore := &b.buf[0], &b.off[0]
	b.Reset()
	if b.Len() != 0 {
		t.Fatalf("Len() after Reset = %d, want 0", b.Len())
	}
	b.Add([]byte("second"))
	if &b.buf[0] != bufBefore || &b.off[0] != offBefore {
		t.Error("Reset reallocated; the batch must reuse its backing arrays")
	}
	if got := b.At(0); !bytes.Equal(got, []byte("second")) {
		t.Errorf("At(0) = %q, want %q", got, "second")
	}
}

func TestCandidateBatchRejectsWhenFull(t *testing.T) {
	b := newCandidateBatch(16)
	added := 0
	for i := 0; i < batchSize+10; i++ {
		if !b.Add([]byte("aaaa")) {
			break
		}
		added++
	}
	if added == 0 {
		t.Fatal("Add never succeeded")
	}
	if added > batchSize {
		t.Errorf("accepted %d candidates, exceeding batchSize %d", added, batchSize)
	}
	if b.Add([]byte("aaaa")) {
		t.Error("Add returned true after the batch reported full")
	}
}

// The batch must not allocate in steady state — that is its entire purpose.
func TestCandidateBatchFillDoesNotAllocate(t *testing.T) {
	b := newCandidateBatch(64 * 1024)
	word := []byte("candidate")
	got := testing.AllocsPerRun(100, func() {
		b.Reset()
		for i := 0; i < batchSize; i++ {
			b.Add(word)
		}
	})
	if got != 0 {
		t.Errorf("filling a batch allocated %v times per run, want 0", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestCandidateBatch ./cmd/hashsmith`

Expected: FAIL — `undefined: newCandidateBatch`.

- [ ] **Step 3: Implement**

Create `batchseam.go`:

```go
package main

// The batch seam between candidate generation and verification.
//
// A one-candidate-at-a-time verifier cannot feed an interleaved SIMD core,
// which needs 4/8/16 independent messages in flight to fill its lanes. Every
// generator fills a CandidateBatch; every verifier consumes one.

// batchSize is the number of candidates per batch: large enough to amortize
// call overhead and fill any lane width, small enough to stay in L1. It also
// divides keyspaceChunk (4096) evenly, so a chunk is exactly 8 batches.
const batchSize = 512

// CandidateBatch is a reusable, allocation-free run of candidates. Words are
// packed into buf with no separators; off[i]..off[i+1] delimits candidate i.
type CandidateBatch struct {
	buf []byte
	off []int32
	n   int
}

// newCandidateBatch allocates a batch whose byte arena starts at capBytes and
// grows only if a caller adds unusually long candidates.
func newCandidateBatch(capBytes int) *CandidateBatch {
	if capBytes < 1 {
		capBytes = 1
	}
	b := &CandidateBatch{
		buf: make([]byte, 0, capBytes),
		off: make([]int32, 1, batchSize+1),
	}
	b.off[0] = 0
	return b
}

// Reset empties the batch while keeping its backing arrays.
func (b *CandidateBatch) Reset() {
	b.buf = b.buf[:0]
	b.off = b.off[:1]
	b.off[0] = 0
	b.n = 0
}

// Add appends a candidate, returning false when the batch is full.
func (b *CandidateBatch) Add(word []byte) bool {
	if b.n >= batchSize {
		return false
	}
	b.buf = append(b.buf, word...)
	b.off = append(b.off, int32(len(b.buf)))
	b.n++
	return true
}

// At returns candidate i. The slice aliases the batch and is invalidated by
// the next Reset.
func (b *CandidateBatch) At(i int) []byte {
	return b.buf[b.off[i]:b.off[i+1]]
}

// Len is the number of candidates currently held.
func (b *CandidateBatch) Len() int { return b.n }

// Hit identifies which candidate matched which target.
type Hit struct {
	Cand   int // index into the batch
	Target int // index into the compiled target set
}

// BatchVerifier tests a whole batch. Implementations are compiled once per run
// and then called billions of times: all format resolution, salt decoding and
// target parsing happens at compile time, never per candidate.
type BatchVerifier interface {
	// VerifyBatch writes matches into hits and returns how many it wrote.
	// hits must have room for at least b.Len() entries.
	VerifyBatch(b *CandidateBatch, hits []Hit) int
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd hashsmith/go_hashsmith && go test -run TestCandidateBatch ./cmd/hashsmith -v 2>&1 | tail -15`

Expected: all four PASS, including the zero-allocation test.

- [ ] **Step 5: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/batchseam.go \
        hashsmith/go_hashsmith/cmd/hashsmith/batchseam_test.go
git commit -m "feat: add CandidateBatch and BatchVerifier seam

An interleaved SIMD core needs 4/8/16 candidates in flight; the current
match(string) bool interface can only supply one. This is the
allocation-free buffer that will feed those cores."
```

---

## Task 7: Fill a batch from the keyspace without allocating

`keyspaceLayout.candidate` allocates one string per candidate (42 ns, 1 alloc — ~14% of the per-candidate budget). `maskIdxInto` already writes into a caller buffer, so this is mostly wiring.

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/keyspace.go` (add alongside `candidate`, `keyspace.go:45`)
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/keyspace_test.go`

**Interfaces:**
- Consumes: `keyspaceLayout`, `maskIdxInto(dst []byte, index int64, sets [][]byte)` (`mask.go:173`), `CandidateBatch` from Task 6.
- Produces: `(*keyspaceLayout) fill(b *CandidateBatch, from int64, n int) int`

- [ ] **Step 1: Write the failing test**

Add to `keyspace_test.go`:

```go
// fill must produce exactly the same candidates, in the same order, as
// repeated candidate() calls — it is the same keyspace, just batched.
func TestLayoutFillMatchesCandidate(t *testing.T) {
	layouts := map[string]*keyspaceLayout{
		"brute-single-len": bruteLayout("abc", 3, 3),
		"brute-multi-len":  bruteLayout("ab", 1, 4),
	}
	for name, l := range layouts {
		t.Run(name, func(t *testing.T) {
			b := newCandidateBatch(4096)
			var got []string
			for from := int64(0); from < l.total; from += 7 {
				n := int64(7)
				if from+n > l.total {
					n = l.total - from
				}
				b.Reset()
				wrote := l.fill(b, from, int(n))
				if int64(wrote) != n {
					t.Fatalf("fill(from=%d, n=%d) wrote %d", from, n, wrote)
				}
				for i := 0; i < wrote; i++ {
					got = append(got, string(b.At(i)))
				}
			}
			if int64(len(got)) != l.total {
				t.Fatalf("filled %d candidates, want %d", len(got), l.total)
			}
			for i := range got {
				if want := l.candidate(int64(i)); got[i] != want {
					t.Fatalf("index %d: fill gave %q, candidate() gave %q", i, got[i], want)
				}
			}
		})
	}
}

func TestLayoutFillStopsAtBatchCapacity(t *testing.T) {
	l := bruteLayout("abcdefghij", 4, 4) // 10000 candidates
	b := newCandidateBatch(8192)
	wrote := l.fill(b, 0, batchSize+100)
	if wrote != batchSize {
		t.Errorf("fill wrote %d, want it capped at batchSize %d", wrote, batchSize)
	}
}

func TestLayoutFillDoesNotAllocate(t *testing.T) {
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 6, 6)
	b := newCandidateBatch(64 * 1024)
	got := testing.AllocsPerRun(50, func() {
		b.Reset()
		l.fill(b, 0, batchSize)
	})
	if got != 0 {
		t.Errorf("fill allocated %v times per run, want 0", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestLayoutFill ./cmd/hashsmith`

Expected: FAIL — `l.fill undefined`.

- [ ] **Step 3: Implement**

Add to `keyspace.go`, after `candidate`:

```go
// fill appends up to n candidates starting at global index `from` to b,
// returning how many it wrote. It stops early at the end of the keyspace or
// when the batch is full. Unlike candidate(), it allocates nothing: each word
// is decoded straight into the batch's arena.
//
// Layouts with a gen override (Markov) have no mixed-radix decode, so they
// fall back to gen per candidate.
func (l *keyspaceLayout) fill(b *CandidateBatch, from int64, n int) int {
	wrote := 0
	var word [64]byte
	seg := 0
	for wrote < n {
		i := from + int64(wrote)
		if i >= l.total {
			break
		}
		if l.gen != nil {
			if !b.Add([]byte(l.gen(i))) {
				break
			}
			wrote++
			continue
		}
		// Locate the segment for i. Indices advance monotonically, so the
		// search resumes from the previous segment rather than restarting.
		if l.offsets[seg] > i {
			seg = 0
		}
		for seg+1 < len(l.offsets) && l.offsets[seg+1] <= i {
			seg++
		}
		sets := l.segments[seg]
		if len(sets) > len(word) {
			// Longer than the stack buffer; fall back to the allocating path.
			if !b.Add([]byte(maskIdxToStr(i-l.offsets[seg], sets))) {
				break
			}
			wrote++
			continue
		}
		maskIdxInto(word[:len(sets)], i-l.offsets[seg], sets)
		if !b.Add(word[:len(sets)]) {
			break
		}
		wrote++
	}
	return wrote
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd hashsmith/go_hashsmith && go test -run TestLayoutFill ./cmd/hashsmith -v 2>&1 | tail -20`

Expected: all three PASS. The equivalence test is the important one — it proves batching changed no candidate.

- [ ] **Step 5: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/keyspace.go \
        hashsmith/go_hashsmith/cmd/hashsmith/keyspace_test.go
git commit -m "feat: add allocation-free keyspaceLayout.fill

candidate() allocates a string per candidate (~14% of the per-candidate
budget). fill decodes straight into a CandidateBatch arena and is proven
equivalent to repeated candidate() calls across segment boundaries."
```

---

## Task 8: The legacy adapter — all 461 formats keep working

Before any engine change, every existing format needs a `BatchVerifier`. This adapter wraps the current path so nothing regresses while fast cores are added incrementally.

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/batchseam.go`
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/batchseam_test.go`

**Interfaces:**
- Consumes: `verifyCandidate` (`crack.go:856`), `newFastVerifier` / `fastVerifier.matchBytes` (Task 3), `CandidateBatch`, `Hit`, `BatchVerifier`.
- Produces:
  - `type batchTarget struct{ Raw string }`
  - `newBatchVerifier(typ, salt, saltMode string, targets []batchTarget) BatchVerifier`
  - `type fastBatchVerifier struct{...}`, `type legacyBatchVerifier struct{...}`

- [ ] **Step 1: Write the failing test**

Add to `batchseam_test.go`:

```go
// The fast path and the legacy path must agree exactly. This is the contract
// that lets formats be promoted one at a time without changing behavior.
func TestBatchVerifierFastAndLegacyAgree(t *testing.T) {
	cases := []struct{ typ, target, plain string }{
		{"md5", "5f4dcc3b5aa765d61d8327deb882cf99", "password"},
		{"sha1", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "password"},
		{"sha256", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			targets := []batchTarget{{Raw: c.target}}
			fast := newBatchVerifier(c.typ, "", "prefix", targets)
			legacy := &legacyBatchVerifier{targets: targets, typ: c.typ, saltMode: "prefix"}

			b := newCandidateBatch(4096)
			words := []string{"wrong", c.plain, "alsowrong", ""}
			for _, w := range words {
				b.Add([]byte(w))
			}
			hitsFast := make([]Hit, batchSize)
			hitsLegacy := make([]Hit, batchSize)
			nf := fast.VerifyBatch(b, hitsFast)
			nl := legacy.VerifyBatch(b, hitsLegacy)

			if nf != nl {
				t.Fatalf("fast found %d hits, legacy found %d", nf, nl)
			}
			if nf != 1 {
				t.Fatalf("expected exactly 1 hit, got %d", nf)
			}
			if hitsFast[0] != hitsLegacy[0] {
				t.Errorf("fast hit %+v != legacy hit %+v", hitsFast[0], hitsLegacy[0])
			}
			if got := string(b.At(hitsFast[0].Cand)); got != c.plain {
				t.Errorf("matched candidate %q, want %q", got, c.plain)
			}
		})
	}
}

// A format with no fast path must still verify, via the legacy adapter.
func TestBatchVerifierFallsBackForComplexFormat(t *testing.T) {
	// bcrypt has no raw-digest fast path; newBatchVerifier must still work.
	targets := []batchTarget{{Raw: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}}
	v := newBatchVerifier("bcrypt", "", "prefix", targets)
	b := newCandidateBatch(1024)
	b.Add([]byte("nope"))
	b.Add([]byte("password"))
	hits := make([]Hit, batchSize)
	if n := v.VerifyBatch(b, hits); n != 1 || hits[0].Cand != 1 {
		t.Errorf("VerifyBatch returned n=%d hits[0]=%+v, want n=1 cand=1", n, hits[0])
	}
}

// Multi-target: one batch, several targets, each matched independently.
func TestBatchVerifierMultipleTargets(t *testing.T) {
	targets := []batchTarget{
		{Raw: "5f4dcc3b5aa765d61d8327deb882cf99"}, // password
		{Raw: "21232f297a57a5a743894a0e4a801fc3"}, // admin
	}
	v := newBatchVerifier("md5", "", "prefix", targets)
	b := newCandidateBatch(1024)
	for _, w := range []string{"admin", "nope", "password"} {
		b.Add([]byte(w))
	}
	hits := make([]Hit, batchSize)
	n := v.VerifyBatch(b, hits)
	if n != 2 {
		t.Fatalf("got %d hits, want 2", n)
	}
	found := map[string]int{}
	for i := 0; i < n; i++ {
		found[string(b.At(hits[i].Cand))] = hits[i].Target
	}
	if found["admin"] != 1 || found["password"] != 0 {
		t.Errorf("wrong target mapping: %v", found)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestBatchVerifier ./cmd/hashsmith`

Expected: FAIL — `undefined: newBatchVerifier`.

- [ ] **Step 3: Implement**

Add to `batchseam.go`:

```go
// batchTarget is one parsed hash record. Raw is kept verbatim for potfile
// output, --left, and the legacy verifier.
type batchTarget struct {
	Raw string
}

// newBatchVerifier compiles a verifier once for a run. Raw-digest formats get
// the zero-allocation fast path; everything else falls back to the legacy
// adapter, which keeps all remaining formats working unchanged.
func newBatchVerifier(typ, salt, saltMode string, targets []batchTarget) BatchVerifier {
	if salt == "" && len(targets) > 0 {
		fvs := make([]*fastVerifier, len(targets))
		allFast := true
		for i, t := range targets {
			fv, ok := newFastVerifier(typ, t.Raw)
			if !ok {
				allFast = false
				break
			}
			fvs[i] = fv
		}
		if allFast {
			return &fastBatchVerifier{verifiers: fvs}
		}
	}
	return &legacyBatchVerifier{targets: targets, typ: typ, salt: salt, saltMode: saltMode}
}

// fastBatchVerifier checks each candidate against every target using the
// zero-allocation raw-digest path.
type fastBatchVerifier struct {
	verifiers []*fastVerifier
}

func (f *fastBatchVerifier) VerifyBatch(b *CandidateBatch, hits []Hit) int {
	n := 0
	for i := 0; i < b.Len(); i++ {
		cand := b.At(i)
		for t, fv := range f.verifiers {
			if fv.matchBytes(cand) {
				hits[n] = Hit{Cand: i, Target: t}
				n++
			}
		}
	}
	return n
}

// legacyBatchVerifier adapts the existing verifyCandidate path. The string
// conversion allocates, but that cost is confined to formats that have not
// been promoted to a native batch core.
type legacyBatchVerifier struct {
	targets  []batchTarget
	typ      string
	salt     string
	saltMode string
}

func (l *legacyBatchVerifier) VerifyBatch(b *CandidateBatch, hits []Hit) int {
	n := 0
	for i := 0; i < b.Len(); i++ {
		cand := string(b.At(i))
		for t := range l.targets {
			if ok, _ := verifyCandidate(cand, l.targets[t].Raw, l.typ, l.salt, l.saltMode); ok {
				hits[n] = Hit{Cand: i, Target: t}
				n++
			}
		}
	}
	return n
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd hashsmith/go_hashsmith && go test -run TestBatchVerifier ./cmd/hashsmith -v 2>&1 | tail -20`

Expected: all three PASS.

- [ ] **Step 5: Run the whole suite — nothing may regress**

Run: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith`

Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/batchseam.go \
        hashsmith/go_hashsmith/cmd/hashsmith/batchseam_test.go
git commit -m "feat: add batch verifiers with a legacy adapter

newBatchVerifier picks the zero-allocation raw-digest path when every
target supports it and falls back to verifyCandidate otherwise, so all
461 formats work through the batch seam from day one. Formats get
promoted to native cores by measured hotness, never in a big bang."
```

---

## Task 9: Run the keyspace engine through the batch seam

Wire `runLayout`'s worker loop to fill batches instead of verifying one candidate at a time. Behavior must be identical; this is the change that lets a 4-way core actually be used.

**Files:**
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/keyspace.go:107-200` (`runLayout`)
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/keyspace_test.go`

**Interfaces:**
- Consumes: `(*keyspaceLayout).fill` (Task 7), `CandidateBatch`, `Hit`, `BatchVerifier` (Tasks 6, 8).
- Produces: `runLayoutBatch(ctx context.Context, l *keyspaceLayout, resumeFrom int64, workers int, atomicAttempts *int64, watermark *int64, mk func() BatchVerifier) (string, error)` — `mk` returns a per-worker verifier, since verifiers hold scratch state and must not be shared across goroutines.

- [ ] **Step 1: Write the failing test**

Add to `keyspace_test.go`:

```go
// The batched runner must find exactly what the per-candidate runner finds.
func TestRunLayoutBatchFindsSameResult(t *testing.T) {
	l := bruteLayout("abcdef", 1, 4)
	targetWord := "cafe"
	mk := func() BatchVerifier {
		return newBatchVerifier("md5", "", "prefix",
			[]batchTarget{{Raw: md5HexOf(targetWord)}})
	}
	var attempts int64
	got, err := runLayoutBatch(context.Background(), l, 0, 4, &attempts, nil, mk)
	if err != nil {
		t.Fatalf("runLayoutBatch: %v", err)
	}
	if got != targetWord {
		t.Errorf("runLayoutBatch = %q, want %q", got, targetWord)
	}
	if attempts == 0 {
		t.Error("attempts counter was never advanced")
	}
}

// An exhausted keyspace with no match returns empty, not an error.
func TestRunLayoutBatchExhaustsWithoutMatch(t *testing.T) {
	l := bruteLayout("ab", 1, 3)
	mk := func() BatchVerifier {
		return newBatchVerifier("md5", "", "prefix",
			[]batchTarget{{Raw: md5HexOf("not-in-this-keyspace")}})
	}
	var attempts int64
	got, err := runLayoutBatch(context.Background(), l, 0, 2, &attempts, nil, mk)
	if err != nil {
		t.Fatalf("runLayoutBatch: %v", err)
	}
	if got != "" {
		t.Errorf("runLayoutBatch = %q, want empty", got)
	}
	if want := l.total; attempts != want {
		t.Errorf("attempts = %d, want the full keyspace %d", attempts, want)
	}
}

// Cancellation must stop the run promptly rather than draining the keyspace.
func TestRunLayoutBatchHonorsCancellation(t *testing.T) {
	l := bruteLayout("abcdefghijklmnop", 6, 6) // large
	mk := func() BatchVerifier {
		return newBatchVerifier("md5", "", "prefix",
			[]batchTarget{{Raw: md5HexOf("unreachable")}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var attempts int64
	start := time.Now()
	if _, err := runLayoutBatch(ctx, l, 0, 4, &attempts, nil, mk); err != nil {
		t.Fatalf("runLayoutBatch: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("cancellation took %v; the run did not stop promptly", elapsed)
	}
	if attempts >= l.total {
		t.Error("the run drained the whole keyspace despite cancellation")
	}
}

// md5HexOf is a test helper: the hex MD5 of s.
func md5HexOf(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
```

Add `"context"`, `"crypto/md5"`, `"encoding/hex"`, `"time"` to the test file's imports as needed.

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestRunLayoutBatch ./cmd/hashsmith`

Expected: FAIL — `undefined: runLayoutBatch`.

- [ ] **Step 3: Implement**

Add `runLayoutBatch` to `keyspace.go`. It mirrors `runLayout`'s chunk allocator and watermark logic exactly; only the inner loop changes:

```go
// runLayoutBatch is runLayout driven through the batch seam: each worker fills
// a CandidateBatch from the layout and hands it to its own BatchVerifier. The
// chunk allocator, watermark, cancellation and attempt accounting are
// unchanged, so resume points remain compatible with runLayout.
//
// mk is called once per worker: verifiers hold scratch buffers and must not be
// shared across goroutines.
func runLayoutBatch(ctx context.Context, l *keyspaceLayout, resumeFrom int64,
	workers int, atomicAttempts *int64, watermark *int64,
	mk func() BatchVerifier) (string, error) {

	if l.total == 0 || resumeFrom >= l.total {
		return "", nil
	}
	if resumeFrom < 0 {
		resumeFrom = 0
	}
	if workers < 1 {
		workers = 1
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	firstChunk := resumeFrom / keyspaceChunk
	nextChunk := firstChunk
	resultCh := make(chan string, 1)

	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			v := mk()
			batch := newCandidateBatch(batchSize * 32)
			hits := make([]Hit, batchSize)
			for {
				c := atomic.AddInt64(&nextChunk, 1) - 1
				start := c * keyspaceChunk
				if start >= l.total {
					atomic.StoreInt64(&cur[wID], math.MaxInt64)
					return
				}
				atomic.StoreInt64(&cur[wID], c)
				end := start + keyspaceChunk
				if end > l.total {
					end = l.total
				}
				from := start
				if from < resumeFrom {
					from = resumeFrom
				}

				var local int64
				for idx := from; idx < end; {
					select {
					case <-innerCtx.Done():
						atomic.AddInt64(atomicAttempts, local)
						return
					default:
					}
					want := int(end - idx)
					if want > batchSize {
						want = batchSize
					}
					batch.Reset()
					wrote := l.fill(batch, idx, want)
					if wrote == 0 {
						break
					}
					n := v.VerifyBatch(batch, hits)
					local += int64(wrote)
					if n > 0 {
						atomic.AddInt64(atomicAttempts, local)
						select {
						case resultCh <- string(batch.At(hits[0].Cand)):
						default:
						}
						cancel()
						atomic.StoreInt64(&cur[wID], math.MaxInt64)
						return
					}
					idx += int64(wrote)
				}
				atomic.AddInt64(atomicAttempts, local)
			}
		}(w)
	}

	if watermark != nil {
		atomic.StoreInt64(watermark, resumeFrom)
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-innerCtx.Done():
					return
				case <-t.C:
					updateWatermark(cur, watermark, l.total)
				}
			}
		}()
	}

	wg.Wait()
	if watermark != nil {
		updateWatermark(cur, watermark, l.total)
	}
	select {
	case r := <-resultCh:
		return r, nil
	default:
		return "", nil
	}
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd hashsmith/go_hashsmith && go test -run TestRunLayoutBatch -timeout 120s ./cmd/hashsmith -v 2>&1 | tail -20`

Expected: all three PASS.

- [ ] **Step 5: Run the full suite and a race check**

Run: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith && go test -race -run 'TestRunLayoutBatch|TestCandidateBatch|TestLayoutFill' ./cmd/hashsmith`

Expected: both `ok`. The race detector matters here — this is concurrent code.

- [ ] **Step 6: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/keyspace.go \
        hashsmith/go_hashsmith/cmd/hashsmith/keyspace_test.go
git commit -m "feat: add runLayoutBatch, the batched keyspace runner

Same chunk allocator, watermark and resume semantics as runLayout, but
each worker fills a CandidateBatch and verifies it in one call. This is
the path an interleaved SIMD core can actually saturate."
```

---

## Task 10: Productionize the NEON core and route MD5 through it

**Files:**
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/md5x4_arm64.s` (from the Task 5 spike)
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/md5x4_arm64.go` (`//go:build arm64` — padding, transpose, `//go:noescape` declaration)
- Create: `hashsmith/go_hashsmith/cmd/hashsmith/md5x4_generic.go` (`//go:build !arm64` — portable fallback)
- Modify: `hashsmith/go_hashsmith/cmd/hashsmith/batchseam.go`
- Test: `hashsmith/go_hashsmith/cmd/hashsmith/md5x4_test.go`, `hashsmith/go_hashsmith/cmd/hashsmith/batchseam_test.go`

**Interfaces:**
- Consumes: the verified NEON kernel from Task 5; `newBatchVerifier` (Task 8).
- Produces:
  - `md5x4Short(out *[4][16]byte, in *[4][]byte)` — MD5 of four messages, each ≤ 55 bytes. **NEON on arm64; a `crypto/md5` loop everywhere else.** Both builds must produce identical output.
  - `md5x4ShortOK(n int) bool` — reports whether a length fits the single-block path (`n <= 55`).
  - `type md5x4BatchVerifier struct{...}` implementing `BatchVerifier`, selected inside `newBatchVerifier` for `typ == "md5"`.

- [ ] **Step 0: Move the spike's kernel into the tree behind a build tag**

The portable fallback is mandatory (Global Constraints) — every non-arm64 target must still build and pass:

```go
//go:build !arm64

package main

import "crypto/md5"

const md5x4MaxLen = 55

func md5x4ShortOK(n int) bool { return n <= md5x4MaxLen }

// md5x4Short is the portable fallback: no vector core on this architecture,
// so hash the four messages one at a time. Output is identical to the NEON
// path by construction.
func md5x4Short(out *[4][16]byte, in *[4][]byte) {
	for l := 0; l < 4; l++ {
		out[l] = md5.Sum(in[l])
	}
}
```

Port the spike's correctness test (all lengths 0–55, all four lanes, lane independence) into `md5x4_test.go` so it runs on **both** builds. Verify the fallback compiles and passes:

```bash
cd hashsmith/go_hashsmith && GOARCH=amd64 GOOS=linux go build ./cmd/hashsmith && go test -run TestMD5x4 ./cmd/hashsmith
```

- [ ] **Step 1: Write the failing test**

Add to `batchseam_test.go`:

```go
// The 4-way MD5 verifier must agree with the legacy path on every candidate,
// including batch sizes that are not a multiple of 4 and over-long candidates
// that fall back to the scalar path.
func TestMD5x4BatchVerifierAgreesWithLegacy(t *testing.T) {
	targets := []batchTarget{
		{Raw: md5HexOf("password")},
		{Raw: md5HexOf("admin")},
		{Raw: md5HexOf(strings.Repeat("y", 70))}, // longer than one block
	}
	fast := newBatchVerifier("md5", "", "prefix", targets)
	if _, ok := fast.(*md5x4BatchVerifier); !ok {
		t.Fatalf("md5 did not select the 4-way verifier, got %T", fast)
	}
	legacy := &legacyBatchVerifier{targets: targets, typ: "md5", saltMode: "prefix"}

	words := []string{"password", "nope", "admin", "", "x", strings.Repeat("y", 70), "zzz"}
	for size := 1; size <= len(words); size++ {
		b := newCandidateBatch(8192)
		for _, w := range words[:size] {
			b.Add([]byte(w))
		}
		hf := make([]Hit, batchSize)
		hl := make([]Hit, batchSize)
		nf := fast.VerifyBatch(b, hf)
		nl := legacy.VerifyBatch(b, hl)
		if nf != nl {
			t.Fatalf("batch of %d: fast found %d hits, legacy found %d", size, nf, nl)
		}
		for i := 0; i < nf; i++ {
			if hf[i] != hl[i] {
				t.Errorf("batch of %d, hit %d: fast %+v != legacy %+v", size, i, hf[i], hl[i])
			}
		}
	}
}

func TestMD5x4BatchVerifierDoesNotAllocate(t *testing.T) {
	v := newBatchVerifier("md5", "", "prefix", []batchTarget{{Raw: md5HexOf("password")}})
	b := newCandidateBatch(64 * 1024)
	for i := 0; i < batchSize; i++ {
		b.Add([]byte("candidate"))
	}
	hits := make([]Hit, batchSize)
	got := testing.AllocsPerRun(50, func() { v.VerifyBatch(b, hits) })
	if got != 0 {
		t.Errorf("VerifyBatch allocated %v times per run, want 0 "+
			"(scratch is owned by the verifier, so nothing should escape)", got)
	}
}
```

Add `"strings"` to the test imports if not present. `md5HexOf` comes from Task 9's test file (same package).

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestMD5x4Batch ./cmd/hashsmith`

Expected: FAIL — `undefined: md5x4BatchVerifier`.

- [ ] **Step 3: Implement**

Add to `batchseam.go`:

```go
// md5x4BatchVerifier hashes candidates four at a time through md5x4Short and
// compares raw digest bytes. Candidates too long for the single-block path
// fall back to crypto/md5 for that lane.
type md5x4BatchVerifier struct {
	digests [][16]byte // one per target, decoded once at compile time
	// Scratch owned by the verifier, not the call. Task 9 constructs one
	// BatchVerifier per worker via mk(), so ownership is exclusive; keeping
	// these here makes the zero-allocation property structural instead of
	// dependent on escape analysis (which does not hold on the non-arm64
	// fallback, where md5x4Short is ordinary Go).
	in  [4][]byte
	out [4][16]byte
}

func (m *md5x4BatchVerifier) VerifyBatch(b *CandidateBatch, hits []Hit) int {
	n := 0
	in, out := &m.in, &m.out
	total := b.Len()

	for base := 0; base < total; base += 4 {
		lanes := total - base
		if lanes > 4 {
			lanes = 4
		}
		fastLanes := true
		for l := 0; l < 4; l++ {
			if l < lanes {
				in[l] = b.At(base + l)
				if !md5x4ShortOK(len(in[l])) {
					fastLanes = false
				}
			} else {
				// Pad unused lanes with a harmless empty message; their
				// results are ignored below.
				in[l] = nil
			}
		}
		if fastLanes {
			md5x4Short(out, in)
		} else {
			for l := 0; l < lanes; l++ {
				out[l] = md5.Sum(in[l])
			}
		}
		for l := 0; l < lanes; l++ {
			for t := range m.digests {
				if out[l] == m.digests[t] {
					hits[n] = Hit{Cand: base + l, Target: t}
					n++
				}
			}
		}
	}
	return n
}
```

Add `"crypto/md5"` and `"encoding/hex"` to `batchseam.go`'s imports, and select the verifier inside `newBatchVerifier` — insert this immediately after the `if salt == "" && len(targets) > 0 {` line, before the existing fast-path block:

```go
		if canonicalHashType(typ) == "md5" {
			digests := make([][16]byte, len(targets))
			allDecoded := true
			for i, t := range targets {
				raw, err := hex.DecodeString(strings.TrimSpace(t.Raw))
				if err != nil || len(raw) != 16 {
					allDecoded = false
					break
				}
				copy(digests[i][:], raw)
			}
			if allDecoded {
				return &md5x4BatchVerifier{digests: digests}
			}
		}
```

Add `"strings"` to the imports if not already present.

- [ ] **Step 4: Run to verify it passes**

Run: `cd hashsmith/go_hashsmith && go test -run 'TestMD5x4Batch|TestBatchVerifier' ./cmd/hashsmith -v 2>&1 | tail -20`

Expected: all PASS.

- [ ] **Step 5: Full suite plus an end-to-end crack**

Run:
```bash
cd hashsmith/go_hashsmith && go test ./cmd/hashsmith && go build -o /tmp/hs ./cmd/hashsmith
/tmp/hs crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99 -N --no-pot
```

Expected: suite `ok`; the crack finds `password`.

- [ ] **Step 6: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/batchseam.go \
        hashsmith/go_hashsmith/cmd/hashsmith/batchseam_test.go
git commit -m "feat: verify MD5 batches through the 4-way core

Selected automatically for md5 targets, with a scalar fallback for
candidates longer than one block. Proven to agree with the legacy path
across every batch size, including non-multiples of 4."
```

---

## Task 11: Measure, then decide on assembly

The spec makes assembly a measure-then-decide gate rather than an assumption. This task produces the measurement and the recommendation.

**Files:**
- Create: `docs/superpowers/notes/2026-08-31-phase1-measurements.md`
- Modify: none (measurement only)

**Interfaces:**
- Consumes: everything from Tasks 5–10.
- Produces: a written recommendation on whether to proceed to NEON/AVX2 assembly cores.

- [ ] **Step 1: Wire the batch runner into the real brute/mask path**

In `crack.go`, the `brute` and `mask` cases call `runSessionLayout`. Add a batched variant selected when the compiled verifier is a `BatchVerifier` and no session resume is in play, so `hashsmith crack -M brute` exercises Task 9's runner. Keep `runLayout` as the fallback so resume semantics are untouched.

Verify equivalence before measuring:

```bash
cd hashsmith/go_hashsmith && go test ./cmd/hashsmith
go build -o /tmp/hs ./cmd/hashsmith
/tmp/hs crack -t md5 -M brute -C abc -n 1 -x 4 $(printf 'cafe' | md5) -N --no-pot
```

Expected: finds `cafe`.

- [ ] **Step 2: Measure MD5 end to end**

Run the same benchmark the spec baselined, best of 3, nothing else running:

```bash
K=11881376
for i in 1 2 3; do
  /usr/bin/time -p /tmp/hs crack -t md5 -M brute -C abcdefghijklmnopqrstuvwxyz \
    -n 5 -x 5 -p 8 fa246d0262c3925617b0c72bb20eeb1d -N --no-pot >/dev/null
done 2>&1 | awk -v k=$K '/real/{if(m==0||$2<m)m=$2} END{printf "best %.2fs  %.2f MH/s\n", m, k/m/1e6}'
```

Baseline to beat: **10.24 MH/s**.

- [ ] **Step 3: Measure the per-algorithm set — with `testing.B`, NOT `benchmark`**

**`hashsmith benchmark` is not an acceptance gate.** During Task 3's review,
`benchType("ntlm", NumCPU, 1s)` was run eight times back to back on an idle
machine and returned 1.97, 2.65, 3.10, 3.39, 4.72, 5.87, 5.88, 7.94 MH/s — a
**>4x run-to-run spread**. That noise swamps any plausible Phase 1 signal, and
gating on it could report success or failure from noise alone. The same review
showed Go `testing.B` microbenchmarks of the same code are stable to a few
percent (ntlm 425–494 ns/op across five runs).

So measure with `testing.B`, using the per-type benchmarks added in Task 3's
fix round:

```bash
cd hashsmith/go_hashsmith
go test -run XXX -bench 'BenchmarkFastVerifier' -benchtime 2s -count 5 ./cmd/hashsmith \
  2>&1 | tee /tmp/phase1-bench.txt
```

Take the **best** of the five counts per type (best-of-N rejects the machine's
downward thermal noise; averaging does not). Compare against the same
measurement taken at Phase 0's end — if that baseline was not captured with
`testing.B`, capture it now by checking out `391abe8` and re-running the
identical command, so both sides of the comparison use the same instrument.

`hashsmith benchmark` output may still be quoted in the report as a
human-facing sanity check, clearly labelled as indicative only.

- [ ] **Step 4: Write the measurements and recommendation**

Create `docs/superpowers/notes/2026-08-31-phase1-measurements.md` recording:
- The end-to-end MD5 rate before (10.24 MH/s) and after.
- The Task 5 spike's per-candidate kernel speedup, and how much of it survived integration. **A large gap between the two means the engine, not the core, is now the bottleneck** — say so explicitly rather than averaging it away.
- The per-algorithm table before and after.
- Distance to the spec's ship floor (100 MH/s) and parity target (250 MH/s).
- **A recommendation on what to do next**, choosing among: an AVX2 core for amd64 (the same spike, different architecture); the MD4/NTLM core (spec §5.4 priority 2, mirroring this task's structure); or stopping here and moving to Phase 2. Include the spec's caution that on arm64 SHA-1/SHA-256 already reach ARMv8 crypto instructions, so hand-written cores for those may well lose — that is the §5.4 measure-then-decide gate, and it should be settled with a spike like Task 5, never assumed.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/notes/2026-08-31-phase1-measurements.md \
        hashsmith/go_hashsmith/cmd/hashsmith/crack.go
git commit -m "perf: route brute/mask through the batch runner and record results

Wires the batched keyspace runner into the real crack path and records
the measured gain against the Phase 0 baseline, with a recommendation on
whether the NEON/AVX2 assembly cores are justified."
```

- [ ] **Step 6: Stop and report**

**This is a checkpoint, not a continuation point.** Report the measurements and the recommendation, and get a decision before starting any further core work.

---

## Self-Review Notes

**Spec coverage:**
- Spec §4.1 (slow-vector split) → Task 1
- Spec §4.2 (time budget) → Task 2
- Spec §4.3 + §4.3.1 (deadline fix, allocation-free harness) → Task 3
- Spec §4.4 (CI) → Task 4
- Spec §4.5 (Phase 0 acceptance) → Tasks 1–4 collectively; verified in Task 1 Step 4, Task 3 Step 6, Task 4 Step 3
- Spec §5.1 (batch seam) → Tasks 6, 8
- Spec §5.2 (allocation-free generation) → Task 7
- Spec §5.3 (legacy adapter) → Task 8
- Spec §5.4 (SIMD cores, priority 1 = MD5) → Tasks 5 (spike) and 10 (productionize). Priority 2 (MD4/NTLM) and priorities 3–5 (SHA family) are deferred to the recommendation in Task 11.
- Spec §5.5 (correctness strategy) → Task 5 Step 3 and Task 10 Step 0 (differential across all lengths and lanes, on both the NEON and fallback builds); Task 10 Step 1 (fast/legacy agreement); Task 4 (cross-compile proves the fallback builds everywhere)
- Spec §5.6 (acceptance criteria) → Task 11
- Spec §6 (Phase 2/3 roadmap) → deliberately out of scope for this plan

**Deviation from the spec, with evidence.** Spec §5.4 assumed interleaved
cores would be written directly. Before writing this plan I implemented and
measured a pure-Go 4-way interleaved MD5 two ways:

| Implementation | Rate (single core, best of 5, M2) |
|---|---|
| `crypto/md5` baseline | **4.27 MH/s** |
| 4-way, state in arrays | 1.27 MH/s |
| 4-way, fully unrolled, state in named scalars | 1.76 MH/s |

Both are **slower** than the baseline: four lanes need 4 state + 16 message
words each, far exceeding arm64's 31 general-purpose registers, so they spill.
Correctness was verified in all cases (all lengths 0–55, all lanes, against
`crypto/md5`), so this is a performance result and not a broken implementation.

Two consequences, both reflected above: the pure-Go interleaved core is **cut
entirely**, and because the batch seam is only worth ~1.15x on its own, the
NEON spike is promoted to **Task 5 as a hard go/no-go gate ahead of it**. NEON
is expected to succeed where GPRs failed because arm64 has 32 × 128-bit vector
registers, which hold all 20 live values comfortably — but that is a
hypothesis, which is exactly why Task 5 is a spike and not an assumption.

**Known deferrals, to be planned separately once Task 11 reports:**
- AVX2 core for amd64 (the Task 5 spike, different architecture)
- MD4/NTLM core (spec §5.4 priority 2)
- The SHA-1/SHA-256/SHA-512 measure-then-decide gate (spec §5.4 priorities 3–5)
- MD4/NTLM 4-way core, mirroring Task 9's structure

**Type consistency:** `CandidateBatch`, `Hit{Cand,Target}`, `BatchVerifier.VerifyBatch`, `batchTarget{Raw}`, `newBatchVerifier`, `md5x4Short`, `md5x4ShortOK`, `fastVerifier.matchBytes`, `(*keyspaceLayout).fill`, `runLayoutBatch` are each defined once and used with the same signature throughout.
