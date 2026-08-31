# Hashsmith: Throughput and Reach

**Date:** 2026-08-31
**Status:** Approved design, pending implementation plan
**Scope of this spec:** Phase 0 and Phase 1. Phases 2 and 3 are recorded as
roadmap context so the Phase 1 interfaces are designed to carry them, but they
are not specified in implementable detail here.

---

> **ERRATUM (added after Phase 1 implementation, 2026-08-31):** Several
> claims below did not survive contact with implementation and measurement.
> The text is left as originally written; this note corrects it rather than
> rewriting history.
>
> - **§2.3** ("Go's `crypto/md5` ships no arm64 assembly") is **false**.
>   `md5block_arm64.s` exists in the Go standard library. The projected
>   headroom from replacing a "generic" block function with a hand-written
>   one never existed on that basis — MD5's arm64 assembly is simply not as
>   fast as a dedicated SIMD-interleaved core, which is a different and much
>   narrower argument than "no assembly at all."
> - **§2.4**'s "JtR ~250–400 MH/s, ~25–40x gap" was an unverified estimate
>   pulled from general knowledge, not a measurement taken on this or any
>   comparable machine. Treat it as an order-of-magnitude guess, not a
>   benchmark result.
> - **§5.6**'s 100 MH/s floor and 250 MH/s parity target were set before any
>   Phase 1 measurement existed and are retired as acceptance criteria.
> - The actual measured outcome of Phase 1 lives in
>   `docs/superpowers/notes/2026-08-31-phase1-measurements.md` — use that
>   document, not the numbers below, for anything load-bearing.

---

## 1. Goal

Make Hashsmith a tool a working password cracker would choose over John the
Ripper and Hashcat.

That goal is deliberately narrowed by two findings in Section 3:

- **Beating Hashcat on GPU throughput is not a stated goal.** It is a decade of
  hand-tuned per-mode kernels across CUDA/HIP/OpenCL/Metal, and it is the only
  thing Hashcat does. We do not compete there.
- **Beating John the Ripper on CPU throughput is a stated goal, and is
  reachable.** It requires SIMD hash cores, which is the substance of Phase 1.

Everything Hashsmith already wins on — format coverage, identification, the
unified toolkit, single-binary distribution — is preserved and not re-litigated
by this work.

---

## 2. Where Hashsmith stands today

Measured on the development machine, not estimated:

- **Hardware:** Apple M2, 4 performance + 4 efficiency cores
- **Toolchain:** Go 1.26.3, `darwin/arm64`
- **Build:** default (`CGO_ENABLED=0`, no GPU tag)

### 2.1 Throughput

MD5 brute-force, `-C abcdefghijklmnopqrstuvwxyz -n 5 -x 5`, keyspace 11,881,376,
best of 3 runs with no competing load:

| Workers | Wall time | Rate    | Scaling |
|---------|-----------|---------|---------|
| `-p 1`  | 3.56 s    | 3.34 MH/s  | 1.00x |
| `-p 4`  | 1.45 s    | 8.19 MH/s  | 2.45x |
| `-p 8`  | 1.16 s    | **10.24 MH/s** | 3.07x |

3.07x on 4P+4E cores is reasonable; the efficiency cores are substantially
slower for this workload. **Parallel scaling is not a primary problem.**

### 2.2 Where a candidate's time goes

Micro-benchmarks against the real code paths (temporary probe, since removed):

```
BenchmarkCandidateGen-8         42.15 ns/op     5 B/op    1 allocs/op
BenchmarkFastVerifierMatch-8   262.0  ns/op    64 B/op    1 allocs/op
BenchmarkGenPlusMatch-8        370.5  ns/op    69 B/op    2 allocs/op
```

Roughly **75–88% of every candidate is spent inside the MD5 compression
function itself.** Candidate generation is ~14%. Engine overhead is the
remainder.

### 2.3 The actual bottleneck

Go's `crypto/md5` ships **no arm64 assembly**. Measured on this machine:

```
BenchmarkMD5Sum5-8              352.5 ns/op
BenchmarkMD5Throughput-8        231.80 MB/s
```

231 MB/s is roughly a third of what optimized scalar C achieves and an order of
magnitude below SIMD-interleaved implementations.

**Conclusion: Hashsmith's throughput problem is the hash cores, not the
engine architecture around them.**

### 2.3.1 Per-algorithm baselines, and why they are not uniform

`hashsmith benchmark -t <type> -d 1` at `-p 8`:

| Algorithm | Rate | Hardware/asm support on arm64 |
|---|---|---|
| md5    | 5.46 MH/s  | **none** — generic Go |
| md4    | 6.44 MH/s  | **none** — generic Go |
| ntlm   | 5.86 MH/s  | **none** — MD4-based |
| sha1   | 11.69 MH/s | ARMv8 crypto extensions |
| sha256 | 13.22 MH/s | ARMv8 crypto extensions |
| sha512 | 10.77 MH/s | partial |

SHA-1 and SHA-256 are **more than twice as fast as MD5** despite being more
work per block. That inversion is the tell: Go uses the ARMv8 SHA instructions
for them and falls back to generic Go for MD5/MD4.

This has a direct consequence for Phase 1 priorities (Section 5.4): the SIMD
win is algorithm- and architecture-dependent, and **MD5/MD4/NTLM are where the
gain is largest on arm64.**

Note also that these benchmark figures are lower than the 10.24 MH/s measured
for MD5 in 2.1, because `benchType` calls `fv.match(string(buf))`, allocating a
string per iteration. Phase 0 fixes this so the harness is a trustworthy
baseline (Section 4.3.1).

This corrects an earlier hypothesis that per-candidate dispatch overhead in
`verifyCandidate` (`crack.go:856`) was the dominant cost. It is not.
`fastVerifier` (`hashfast.go:79`) already provides a zero-copy, raw-digest-
comparing fast path for raw digest formats, and it is already what the brute /
mask / dict engines use. `verifyCandidate`'s ~500-arm switch is the *fallback*
for complex formats, not the hot path.

### 2.4 The competitive gap

| | MD5 rate | vs Hashsmith |
|---|---|---|
| **Hashsmith today** | 10.2 MH/s | 1x |
| JtR, NEON 4-way SIMD, same CPU | ~250–400 MH/s | **~25–40x** |
| Hashcat, this machine's GPU (Metal) | ~5–8 GH/s | ~500–800x |

Phase 1 targets closing this gap: a ship floor of ~10x and a parity target of
~25x (Section 5.6). The GPU column is explicitly out of scope.

### 2.5 Correctness and tooling defects found

Both are Phase 0 blockers.

**(a) The test suite does not pass.** `go test ./...` fails at Go's 600 s
timeout:

```
panic: test timed out after 1m30s
	running tests:
		TestSelfTestVectorsAllPass
```

The stack lands in `crack.go:895` → `crack_veracrypt.go:191` →
`pbkdf2.Key(..., 500000 iterations)` → HMAC over `whirlpool.go:157`.

The cause is *not* that the vectors are wrong. `slowSelfTestTypeSeed()`
(`selftest.go:59`) already classifies ~120 memory-hard and high-iteration KDFs
as opt-in for the `hashsmith selftest` **command** — but
`TestSelfTestVectorsAllPass` (`selftest_test.go:10`) ignores that
classification and runs every vector unconditionally.

Consequence: CI cannot be green, and the README's claim that every format "is
validated against a known-answer vector before shipping" is not currently
enforceable by a test that finishes.

**(b) `benchmark` overruns its time budget by ~1000x.** `benchType`
(`benchmark.go`) checks its deadline only every 1024 iterations:

```go
if local&1023 == 0 && time.Now().After(deadline) {
    break
}
```

For a fast digest this is fine. For bcrypt at cost 10 (~60 ms/op) it commits to
1024 × 60 ms ≈ 61 s of work against a **1.0 s** budget. Observed: a plain
`hashsmith benchmark` consumed 13 CPU-minutes without completing and had to be
killed.

---

## 3. Strategy

Three decisions were taken during design review and are settled inputs to this
spec:

1. **Compete on CPU throughput and workflow, not GPU throughput.** GPU support
   remains a bonus behind its existing build tag.
2. **Reach SIMD via Go assembly, not cgo.** Hand-written Plan 9 assembly for the
   hot cores, with portable Go fallbacks. This preserves every current
   distribution promise: `CGO_ENABLED=0`, one static binary, cross-compiles,
   plain `go build`.
3. **Pursue deep hashcat/JtR compatibility** — flags *and* file formats — so
   existing scripts, rule files and potfiles work unchanged.

---

## 4. Phase 0 — A test suite that finishes

**Goal:** a green `go test ./...` in under 60 seconds, and a `benchmark` command
that respects its budget. This is a prerequisite for Phase 1: SIMD assembly is
the riskiest change in this program, and without a fast, trustworthy correctness
baseline there is no way to prove a hand-written core did not silently break one
of 461 formats.

### 4.1 Split the self-test vectors by cost

`selftest.go` already has the classification. Make the test honor it.

- Add `func isSlowSelfTestVector(v selfTestVector) bool`, backed by the existing
  `slowSelfTestTypeSeed()`, resolving through `canonicalHashType`.
- `TestSelfTestVectorsAllPass` runs **fast vectors only**.
- Add `selftest_slow_test.go` guarded by `//go:build slowtest`, running the slow
  vectors, with `-timeout 60m`.

### 4.2 Enforce the classification with a time budget

A classification nothing checks will drift. Each fast vector is individually
timed; any fast-classified vector exceeding **50 ms** fails the test with a
message naming the type and instructing that it be added to
`slowSelfTestTypeSeed()`.

This makes misclassification a build failure rather than a slow creep back to a
600 s suite.

### 4.3 Fix the benchmark deadline

Replace the fixed `local&1023` stride with an adaptive check:

- Check the deadline every iteration when the measured per-op cost exceeds
  ~1 ms (slow KDFs).
- Retain a strided check for fast digests, where `time.Now()` would itself
  distort the measurement.

Implementation: time the first iteration, derive a stride of roughly
`max(1, 1ms / per_op_cost)`, clamped to `[1, 1024]`.

#### 4.3.1 Make the harness allocation-free

`benchType` currently calls `fv.match(string(buf))`, allocating a string every
iteration and understating the true rate (5.46 MH/s reported for MD5 versus
10.24 MH/s measured through the real brute path). Since this harness is the
baseline Phase 1 is measured against, it must not carry overhead the cracker
does not have. Convert it to the batch interface once Section 5.1 lands, and in
the meantime hash the byte slice directly.

Phase 1's acceptance numbers are quoted against the **corrected** harness, so
Phase 0 must land this fix before any Phase 1 measurement is taken.

### 4.4 CI

- **Every push / PR:** `go build ./... && go vet ./... && go test ./...`
  (fast vectors), budgeted under 60 s.
- **Nightly:** `go test -tags slowtest -timeout 60m ./...` (all vectors).

### 4.5 Phase 0 acceptance criteria

- `go test ./...` exits 0 in under 60 s on the reference machine.
- `go test -tags slowtest ./...` exits 0.
- `hashsmith benchmark` completes its default 13-type set in under 30 s wall.
- `hashsmith benchmark -t bcrypt -d 1` completes in ~1 s, not ~61 s.
- A deliberately misclassified slow vector causes a clear, named test failure.

---

## 5. Phase 1 — Batched candidate pipeline and SIMD hash cores

**Goal:** MD5 from 10.2 MH/s to 150+ MH/s on the reference machine, without cgo
and without regressing any of the 461 formats.

These two pieces are specified together and deliberately **not** split into
separate phases: the batching refactor has little standalone value (~1.3x from
removing two allocations), and SIMD is impossible without it. Batching exists to
fill vector lanes.

### 5.1 The batch seam

The current hot interface is one candidate at a time:

```go
func (f *fastVerifier) match(candidate string) bool
```

A 4-way NEON core needs four candidates simultaneously. Introduce:

```go
// CandidateBatch is a reusable, allocation-free buffer of candidates.
// buf holds them packed with no separators; off[i]..off[i+1] delimits
// candidate i. A batch is Reset and refilled, never reallocated.
type CandidateBatch struct {
    buf []byte
    off []int32 // len == n+1
    n   int
}

func (b *CandidateBatch) Reset()
func (b *CandidateBatch) Add(word []byte) bool // false when full
func (b *CandidateBatch) At(i int) []byte
func (b *CandidateBatch) Len() int

// Hit identifies which candidate matched which target.
type Hit struct {
    Cand   int // index into the batch
    Target int // index into the compiled target set
}

// BatchVerifier tests a whole batch. Implementations are compiled once per
// run and then called billions of times; all format resolution, salt
// decoding and target parsing happens at compile time, never per candidate.
type BatchVerifier interface {
    // VerifyBatch appends matches to hits and returns how many it wrote.
    VerifyBatch(b *CandidateBatch, hits []Hit) int
}
```

`BatchSize` defaults to 512: large enough to amortize call overhead and fill any
lane width, small enough to stay in L1.

### 5.2 Candidate generation without allocation

`keyspaceLayout.candidate(i int64) string` (`keyspace.go:45`) allocates one
string per candidate (42 ns, 1 alloc). Add an allocation-free sibling that
writes directly into a batch:

```go
// fill appends candidates [from, from+n) to b, returning how many it wrote.
func (l *keyspaceLayout) fill(b *CandidateBatch, from int64, n int) int
```

`maskIdxInto` (`mask.go:173`) already writes into a caller-supplied buffer, so
this is largely wiring rather than new logic. `candidate()` is retained for
resume, display, and the legacy path.

### 5.3 The legacy adapter — nothing regresses

All 461 existing formats keep working from day one via an adapter that wraps the
current path as a slow single-candidate `BatchVerifier`:

```go
type legacyVerifier struct {
    targets  []Target
    typ      string
    salt     string
    saltMode string
}

func (l *legacyVerifier) VerifyBatch(b *CandidateBatch, hits []Hit) int {
    n := 0
    for i := 0; i < b.Len(); i++ {
        c := string(b.At(i)) // allocation confined to the legacy path
        for t := range l.targets {
            if ok, _ := verifyCandidate(c, l.targets[t].Raw, l.typ, l.salt, l.saltMode); ok {
                hits[n] = Hit{Cand: i, Target: t}
                n++
            }
        }
    }
    return n
}
```

Formats are promoted to native batch verifiers **by measured hotness**, never in
a big bang. Phase 1 promotes exactly the SIMD set in 5.4.

### 5.4 SIMD hash cores

Interleaved (vertical) SIMD: lane *i* processes candidate *i*. This is what
yields 4–16x; vectorizing a *single* hash yields nearly nothing, because MD5 and
SHA-2 are inherently serial within one message.

Layout per algorithm:

```
md5_neon_arm64.s        4-way    NEON, 128-bit
md5_avx2_amd64.s        8-way    AVX2, 256-bit
md5_avx512_amd64.s     16-way    AVX-512F, runtime-detected
md5_generic.go          1-way    portable Go, always present
md5_dispatch.go                  selects once at init
```

Selection happens once at init via `golang.org/x/sys/cpu`. The generic path is
always compiled and is the fallback for any architecture or feature level
without an assembly core.

**Scope for Phase 1**, ordered by expected gain rather than by popularity
alone. Section 2.3.1 showed SHA-1/SHA-256 already reach ARMv8 crypto
instructions on arm64 while MD5/MD4 do not, so the two groups are not equally
worth the assembly effort:

| Priority | Algorithm | Current | Rationale |
|---|---|---|---|
| 1 | MD5 | 5.46 MH/s | No hardware support on any target arch; largest headroom; base of many composites |
| 2 | MD4 / NTLM | 6.44 / 5.86 MH/s | Same lack of hardware support, and NTLM dominates Active Directory work |
| 3 | SHA-1 | 11.69 MH/s | Already hardware-accelerated on arm64; **the win here is on amd64 via AVX2**, and from lane-parallelism where the hardware path is serial |
| 4 | SHA-256 | 13.22 MH/s | As SHA-1 |
| 5 | SHA-512 | 10.77 MH/s | Completes the SHA-2 family |

Priorities 1–2 are committed Phase 1 scope. Priorities 3–5 are Phase 1 scope
*if* a per-architecture measurement shows interleaved SIMD beats the existing
hardware-instruction path; on arm64 it may not, and shipping a slower
hand-written core would be a net loss. **This is an explicit measure-then-decide
gate, not an assumption.**

Everything else retains the portable core and loses nothing relative to today.

### 5.5 Correctness strategy for hand-written assembly

This is the risk concentration of the whole program, and is treated
accordingly:

1. **Differential property tests.** Each SIMD core is tested against the
   corresponding `crypto/*` implementation on random inputs across every length
   from 0 to 256 bytes, and across every lane-count remainder (a batch of 1, 2,
   3, ... candidates must produce identical results to a full batch). Run in
   default CI.
2. **Known-answer vectors.** The existing self-test vectors run against the SIMD
   path as well as the portable path.
3. **Lane-independence test.** Deliberately assert that lane *i*'s output
   depends only on lane *i*'s input — the classic interleaved-SIMD bug.
4. **Fallback parity.** A build flag forces the generic core so the same suite
   proves both paths agree.

### 5.6 Phase 1 acceptance criteria

Throughput, at `-p 8` on the reference machine, measured with the corrected
harness (4.3.1):

| Metric | Floor (ship) | Target (parity with JtR) |
|---|---|---|
| MD5 | ≥ 100 MH/s | ≥ 250 MH/s |
| MD4 / NTLM | ≥ 100 MH/s | ≥ 250 MH/s |
| SHA-1 / SHA-256 / SHA-512 | no regression | ≥ 3x current, if the 5.4 gate passes |

The floor is what makes the work worth shipping; the target is what makes the
Section 1 goal — beating JtR on CPU — actually true. A 4-way NEON core on 4
performance cores puts the 250 MH/s target within reach but does not guarantee
it, so both numbers are stated rather than one optimistic figure.

Correctness and portability, all mandatory:

- `go test ./...` and `-tags slowtest` both still green.
- `CGO_ENABLED=0 go build` still produces a static binary; cross-compilation to
  `linux/amd64`, `linux/arm64`, `windows/amd64`, `darwin/arm64` all succeed.
- On an architecture with no assembly core, the binary builds and passes the
  full suite on the portable path.
- No format's result changes. Verified by the full vector suite.

---

## 6. Roadmap context (not specified here)

Recorded so Phase 1's interfaces are designed to carry them.

### Phase 2 — Reach

- **`--keyspace`, `--skip N`, `--limit N`.** Hashsmith currently **cannot split
  a job across machines at all**; this is how every cluster and farm works.
  `runLayout` already accepts `resumeFrom` and `keyspaceLayout` already computes
  `total`, so this is small and high-leverage.
- **`--username`, `--left`, `--outfile-format`, hashcat-compatible potfiles.**
- **Single-crack mode.** JtR's highest-yield mode on real engagements: per-hash
  candidates derived from that account's own username/GECOS. Cheap, because the
  candidate count per hash is tiny. Depends on `--username`.
- **Rule preprocessor and stacking** (`-j`/`-k`, `[abc]` ranges,
  `--debug-rules`), plus removing the per-word `map` allocation in
  `ruleEngine.expand` (`rules.go:555`).
- **Loopback**, **PRINCE**, **association attack** (`-a 9`), and
  **hcstat2-compatible 2nd-order Markov** with `--markov-threshold`, replacing
  today's ad-hoc first-order model.

### Phase 3 — Compatibility

A flag-translation front end accepting hashcat (`-a`, `-m`, `-1..-4`,
`--increment-min/max`, `--show`, `--left`) and JtR (`--format=`, `--wordlist=`,
`--rules=`, `--incremental`, `--fork`) spellings, plus reading hashcat `.rule`
and JtR rule syntax into the same `ruleProgram`.

**Constraint:** this lives in a single file that only rewrites `argv`.
Compatibility surfaces rot when smeared through an engine. The policy is *alias
flags, never fork semantics*.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Hand-written SIMD assembly is subtly wrong | Section 5.5's four-layer strategy; portable fallback always present and always tested |
| Assembly becomes a maintenance burden | Scope capped at 5 algorithms; everything else stays portable Go |
| 461 formats are a long migration tail | Legacy adapter (5.3) keeps all of them working; promote by measured hotness only |
| Phase 1 target proves unreachable | Phase 0 stands alone; the batch seam is independently useful; partial SIMD coverage still ships real gains |
| Deep compat becomes a maintenance sink | Single argv-rewriting file; documented alias-not-fork policy |

---

## 8. Explicit non-goals

- Competing with Hashcat on GPU throughput.
- Rewriting all 461 formats onto the batch interface.
- Changing Hashsmith's native CLI vocabulary (Phase 3 *adds* aliases).
- Introducing cgo, dynamic linking, or a required C toolchain.
