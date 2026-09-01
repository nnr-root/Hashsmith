# Phase 1 measurements: MD5 NEON fast path (Task 9)

Measured on this machine (darwin/arm64, 8 physical/8 logical cores),
2026-08-31, in one session, before/after runs interleaved to cancel
session-level load drift (this machine's load varies ~40% within a
session — see below). `hashsmith benchmark` (the CLI's built-in benchmark
subcommand) was **not** used as evidence anywhere in this report: an
earlier review measured a >4x run-to-run spread in it (`benchType("ntlm")`
returning 1.97–7.94 MH/s across eight consecutive runs), so it is not
trustworthy for before/after comparison.

- BEFORE commit: `43d4c91` (tip of Phase 0 — Tasks 6/7 added code without
  changing cracking behaviour, so this is the honest "before").
- AFTER commit: `42cb9b4` (HEAD of `hashsmith-core-rewrite` at the start of
  this task).
- Both binaries were built from clean `git worktree` checkouts (no dirty
  working tree, no detached HEAD left on the main checkout).

## 1. End-to-end (CLI), the headline number

Command (both binaries, unsalted fixed-length MD5 brute, keyspace
11,881,376, target hash deliberately absent so both binaries exhaust the
full space):

```
crack -t md5 -M brute -C abcdefghijklmnopqrstuvwxyz -n 5 -x 5 -p 8 \
  fa246d0262c3925617b0c72bb20eeb1d -N --no-pot
```

Timed with the shell's own `time` builtin (millisecond precision; all
program output, including the progress bar, redirected to `/dev/null` so
it cannot distort timing), before and after run alternated on every
iteration, best of 5 each:

| Run | before (s) | after (s) |
|---|---|---|
| 1 | 0.787 | 0.152 |
| 2 | 0.811 | 0.178 |
| 3 | 0.855 | 0.140 |
| 4 | 0.776 | 0.140 |
| 5 | 0.795 | 0.148 |
| **best** | **0.776** | **0.140** |

**Before: 15.31 MH/s. After: 84.87 MH/s. Ratio: 5.54x.**

A second interleaved best-of-5 round, run immediately afterward as a
consistency check under measurably higher session load (the shell's own
`time` reported before-run totals up to 1.34s in this round, vs. ≤0.86s in
the first — direct evidence of the ~40% intra-session drift the brief
warned about), gave 13.91 MH/s / 79.74 MH/s = **5.73x**. The two rounds
agree to within their own noise band; **5.5–5.7x is the honest end-to-end
range**, both comfortably above the ≥3x go/no-go bar this design set for
Phase 1.

Both binaries were run with `-p 8` (8 worker goroutines, matching this
machine's 8 cores); observed CPU utilization was 610–670% for the before
binary and 520–680% for the after binary on the timed runs above —
consistent with real multi-core parallelism on both sides, not an artifact
of one binary using more threads than the other.

**Fast path confirmed engaged, not silently falling back:** a dedicated
probe test (`t.Logf("md5GroupAccelerated() = %v", md5GroupAccelerated())`,
run against the HEAD worktree) confirmed `md5GroupAccelerated()` returns
`true` on this darwin/arm64 machine, which is the first gate in
`fastPathEligible` (`cmd/hashsmith/keyspace.go:226`). As a second check, a
non-MD5 format (NTLM, same charset/length/keyspace shape,
`crack -t ntlm -M brute ...`) was run on both binaries: before 7.377s best
of 3, after 7.594s best of 3 — statistically indistinguishable (~3%
apart, within session noise), confirming the fast path correctly declines
non-MD5 targets and leaves that code path's performance unchanged.

## 2. Kernel level (`testing.B`)

```
go test -run XXX -bench 'BenchmarkMD5Group|BenchmarkMD5Scalar' -benchtime 2s -count 5 ./cmd/hashsmith
```

Run against the HEAD worktree only — `BenchmarkMD5Group` does not exist
before Task 7, so there is no "before" kernel number; this benchmark
measures the new core's contribution in isolation, single-threaded, one
`testing.B` goroutine, best of 5:

```
BenchmarkMD5Group-8    2356858   1021 ns/op   19.59 MH/s
BenchmarkMD5Group-8    2354719   1020 ns/op   19.60 MH/s
BenchmarkMD5Group-8    2345844   1093 ns/op   18.29 MH/s
BenchmarkMD5Group-8    2280157   1019 ns/op   19.62 MH/s
BenchmarkMD5Group-8    2354125   1015 ns/op   19.70 MH/s   <- best

BenchmarkMD5Scalar-8  15430854   155.6 ns/op   6.427 MH/s
BenchmarkMD5Scalar-8  15413804   156.3 ns/op   6.396 MH/s
BenchmarkMD5Scalar-8  15342554   157.4 ns/op   6.352 MH/s
BenchmarkMD5Scalar-8  15428473   155.7 ns/op   6.424 MH/s
BenchmarkMD5Scalar-8  15234644   155.3 ns/op   6.437 MH/s   <- best
```

**Best-of-5: 19.70 MH/s (Group) vs 6.437 MH/s (Scalar) = 3.06x.** This
closely reproduces Task 7's own measurement of the same benchmark
(19.34 vs 6.468 MH/s = 2.99x) — the kernel is stable to a few percent
run-to-run, as expected, and there has been no regression since Task 7
landed.

## 3. How much of the spike's 5.58x survived integration, and where the rest went

Three different numbers exist for this core, from three different
measurement scopes, and they are not directly comparable to each other
without accounting for what each one includes:

| Stage | Ratio | Scope | Threading |
|---|---|---|---|
| Task 5 spike, "core-only" ceiling | **5.58x** | hashes only; candidate generation *assumed* free (not yet built) | single-threaded |
| Task 7 / this task, `testing.B` kernel | **2.99x–3.06x** | Group: real generation (`fillFromSegment`) + hash. Scalar: `crypto/md5.Sum` on a **fixed, pre-built** 8-byte buffer — no generation at all | single-threaded |
| This task, end-to-end CLI | **5.54x–5.73x** | full production pipeline both sides: real candidate generation, digest verification, chunk allocation, watermark/resume bookkeeping, context-check cadence, worker scheduling | 8-way parallel |

The kernel number (~3x) looks like a big loss from the spike's 5.58x, but
it is **not evidence that integration lost throughput** — it is an
artifact of an apples-to-oranges comparison baked into the benchmark
itself. `BenchmarkMD5Scalar` hashes a fixed, already-in-memory 8-byte
slice with `crypto/md5.Sum`, paying zero cost for candidate generation.
`BenchmarkMD5Group` pays full transposed-generation cost every call
(`tb.fillFromSegment`). That is a legitimate way to benchmark the *core*,
but it structurally understates what the *old scalar production path*
actually costs per candidate, because the real scalar path
(`runLayout` in `cmd/hashsmith/keyspace.go:96`) does not hash a
pre-built buffer — it calls `l.candidate(idx)`
(`keyspace.go:45`, delegating to `maskIdxToStr`) to **allocate a new Go
string per candidate** via mixed-radix decode, then hashes and compares
that. That allocation-and-decode cost, entirely absent from
`BenchmarkMD5Scalar`, is real production overhead the old path always
paid and the microbenchmark never captures.

The end-to-end numbers confirm this. Back-computing per-core throughput
from the CLI runs (best-of-5 runs above, matched to their reported CPU
utilization):

- Scalar, production: 15.31 MH/s over ~6.43 cores active ≈ **2.38
  MH/s/core** — a ~2.7x drop from the isolated microbenchmark's 6.44
  MH/s/core. This drop is the allocation/decode cost `BenchmarkMD5Scalar`
  never pays.
- Group, production: 84.87 MH/s over ~6.28 cores active ≈ **13.5
  MH/s/core** — a ~31% drop from the isolated kernel's 19.70 MH/s/core.
  This smaller drop is genuine integration overhead on the new path:
  per-group digest comparison across all 20 lanes, the watermark-updater
  goroutine, chunk/segment-boundary bookkeeping in
  `runLayoutFastMD5` (`keyspace.go:265`), and the `fastCtxCheckEvery`
  cancellation-poll cadence — none of which `BenchmarkMD5Group` exercises,
  since it just calls `fillFromSegment` + `md5Group` in a tight loop with
  no comparison, chunking, or scheduling around it.

Put together: the Group side gives back ~31% of its kernel throughput to
real integration cost; the Scalar side's own kernel number was never a
fair baseline to begin with, understating real production cost by ~2.7x.
When both sides are measured paying their *actual* production cost — the
end-to-end CLI numbers in §1 — the ratio recovers to 5.5–5.7x, close to
and statistically consistent with the spike's original 5.58x "core-only"
ceiling. **The headline finding is not "most of the spike's gain was
lost in integration" — it's the opposite: nearly all of it survived,
and the design's core advantage (allocation-free transposed generation
directly into pre-padded lanes, avoiding exactly the per-candidate string
allocation the scalar path pays) is what makes that possible.** The
3x kernel figure undersells the work; report the end-to-end number as the
one that matters.

## 4. Revised, measured statement of Hashsmith's MD5 throughput

The spec's Phase 1 acceptance table (`docs/superpowers/specs/2026-08-31-hashsmith-throughput-and-reach-design.md:415`)
set:

> MD5 floor ≥ 100 MH/s (ship), target ≥ 250 MH/s (JtR parity)

That floor was set before any measurement, extrapolated from an
unverified competitive claim (spec §2.4's "JtR ~250–400 MH/s on the same
CPU" row, itself flagged elsewhere in this plan as an estimate, not a
measurement, and one that conflates JtR's x86 AVX2/AVX-512 figures — 8–16
SIMD lanes — with what a 4-lane ARM NEON core can do). **It is not
reachable on this CPU with this architecture and should be retired.**

The measured reality on this machine (Apple Silicon, darwin/arm64, 8
cores), for the one path this phase accelerated — unsalted, fixed-length
MD5 brute/mask attacks — is:

- **Before (scalar, all formats, unchanged): ~15 MH/s** end-to-end at
  `-p 8`, exhaustive brute over a 26-symbol alphabet, length 5–8.
- **After (NEON fast path, unsalted fixed-length MD5 brute/mask only):
  ~80–85 MH/s** end-to-end under the same conditions, with a
  same-session best-of-5 measured range of 79.7–84.9 MH/s (5.5x–5.7x
  over the before baseline).
- Every other case — salted MD5, non-MD5 formats (confirmed directly:
  NTLM unaffected within measurement noise), variable-length or
  Markov-generated candidates — is untouched and still runs at the
  pre-Phase-1 scalar rate (~15 MH/s class, format-dependent).

So: **Hashsmith's real MD5 fast-path throughput on this CPU is
~80 MH/s, not 100 MH/s**, and that number applies to a narrower slice of
attacks (unsalted, fixed-length, brute/mask) than the spec's floor
implied applied to "MD5" generally. It clears the design's actual go/no-go
bar (≥3x same-session improvement) with room to spare, but it does not
clear the spec's invented 100 MH/s floor and very likely never will on a
4-lane NEON core on this CPU class — closing that gap needs more lanes
(amd64 AVX2/AVX-512, §5 below), not further tuning of this core.

## 5. Recommendation: what's worth doing next

Three options were on the table. In priority order:

1. **Fix the `maskKeyspace` int64 overflow first, before any further core
   work.** See "Known pre-existing bug" below — this is a **silent
   correctness bug**, not a throughput one, and it outranks throughput
   work on severity: a user running a realistic `?a`-style mask at length
   ≥10 gets a false "not found" after silently searching ~7.6% of the
   space they asked for. A throughput improvement that makes wrong
   answers arrive 5x faster is not a net win.
2. **MD4/NTLM core, same structure as this one.** Reuses the exact
   pipelined-NEON-chain architecture and transposed-generation machinery
   already built and proven correct (bit-exact differential testing at
   every length, cross-chain lane independence). NTLM dominates real
   Active Directory engagement work, arguably a more valuable target than
   further MD5 tuning, and the marginal engineering cost is low because
   the hard parts (assembly generator, transposed batch layout, fast-path
   integration pattern, correctness-test scaffolding) are now a known
   quantity from Tasks 6–8.
3. **amd64 AVX2/AVX-512 core.** This is where JtR's large competitive
   numbers actually come from (8–16 lanes vs. this core's 4), and would
   be the only route to something in the spec's original ballpark. But it
   is new architecture-specific assembly work from a colder start (no
   existing amd64 spike), and Hashsmith's own target platform for this
   session is darwin/arm64 — this is a larger, riskier undertaking than
   #2 and should follow it, not precede it.

**Recommendation: fix the mask-overflow bug first (small, high-severity,
unrelated to throughput), then build the MD4/NTLM core next** using the
same architecture as this one — it's the highest-value, lowest-risk next
step. Hold the amd64 AVX2/AVX-512 core and Phase 2 reach/workflow features
for a subsequent decision once NTLM lands.

## 6. Known pre-existing bug: `maskKeyspace` int64 overflow — flagged, not fixed

`cmd/hashsmith/mask.go:134` (`maskKeyspace`):

```go
func maskKeyspace(sets [][]byte) int64 {
	total := int64(1)
	for _, s := range sets {
		if len(s) == 0 {
			return 0
		}
		total *= int64(len(s))
	}
	return total
}
```

No overflow check on the accumulating product. Verified directly (Python,
cross-checked against the real binary by Task 7's independent oracle): a
`?a` mask (95-symbol hashcat-style alphabet) at length 10 computes
`95^10 = 59,873,693,923,837,890,625`, which does not fit in an `int64`
(max ≈ 9.22×10^18) and wraps via twos-complement overflow to
`4,533,461,702,709,235,777` — **positive**, so nothing fails loudly, no
panic, no error message. The run silently enumerates only
`4,533,461,702,709,235,777 / 59,873,693,923,837,890,625 ≈ 7.57%` of the
keyspace the user actually asked for, then reports the password "not
found" once that (much smaller) count is exhausted.

**Severity: high.** This is not a corner case — a length-10 `?a` mask is
an entirely ordinary hashcat-style attack, and the failure mode is silent:
no error, no warning, a plausible-looking progress bar and a
false-negative "not found" result that looks identical to a real
exhaustive miss. Anyone relying on Hashsmith's "not found" as proof a
password isn't crackable with a given mask is currently getting a wrong
answer roughly 92% of the time for masks in this range, with no
indication anything went wrong. This was discovered incidentally during
Task 7's correctness testing and reconfirmed here; per the orchestrator's
instruction it is documented, not fixed, in this task.

## Repo state at time of writing

- Branch: `hashsmith-core-rewrite`, clean, no stray changes.
- Two temporary worktrees were used for before/after builds
  (`wt-before` at `43d4c91`, `wt-after` at `42cb9b4`) and removed before
  finishing this task; `git worktree list` shows only the main checkout.

---

# Phase 1 measurements: MD4/NTLM fast path (Task 4 of the MD4/NTLM plan)

Measured on this machine (darwin/arm64, 8 physical/8 logical cores),
2026-08-31, in one session, same session load-drift caveat as above (this
machine's load varies ~40% within a session). All before/after pairs
below are **interleaved** (before, after, before, after, ...),
**best-of-5**, N=5 stated per pair. `hashsmith benchmark` was again not
used as evidence, for the same reason as above (measured >4x run-to-run
spread).

**Methodology correction from the prior section:** the MD5 numbers above
used a 5-character keyspace (11,881,376), which this task's own
measurement now shows is too small to trust — a 5-char sweep finishes in
roughly 0.1s where process startup dominates the wall clock, and an
independent 6-char re-measure on this same machine has previously given a
figure ~20% lower than a 5-char run reported (65.31 MH/s vs. 84.87 MH/s
for the same binary). **Every number in this section uses the 6-character
keyspace, 308,915,776 candidates** (`-C abcdefghijklmnopqrstuvwxyz -n 6 -x
6`), which runs long enough (multiple seconds) that startup cost is
negligible.

- BEFORE commit: `92d3d5f` (merge base of `md4-ntlm-fast-path`, i.e.
  before Task 1 of this plan — MD5's fast path already existed here from
  the prior plan; only MD4/NTLM are new in AFTER).
- AFTER commit: `de1a156` (HEAD of `md4-ntlm-fast-path` at the start of
  this task).
- Both binaries were built from clean `git worktree` checkouts (`git
  worktree add --detach /tmp/hs-before-wt 92d3d5f`, `go build`), and the
  worktree was removed (`git worktree remove`) and pruned before this
  task finished; the main checkout was never left dirty or detached.
- Target hash for each algorithm was `hash(zzzzz0)` (contains a digit,
  provably absent from the pure `a-z` 6-char keyspace under test), so
  both BEFORE and AFTER exhaust the full 308,915,776-candidate space —
  a fair throughput comparison, not a first-match race. stderr (which
  carries the progress bar) was redirected to `/dev/null` for every timed
  run so it could not distort wall-clock timing.

## 1. End-to-end (CLI)

Command shape (both binaries, `-p 8`):

```
crack -t <ntlm|md4|md5> -M brute -C abcdefghijklmnopqrstuvwxyz \
  -n 6 -x 6 -p 8 <hash-not-in-keyspace> --no-pot
```

Wall-clock times (seconds) for all 5 interleaved rounds, before/after per
algorithm:

**NTLM**
| round | BEFORE (92d3d5f) | AFTER (de1a156) |
|---|---|---|
| 1 | 59.035 | 5.480 |
| 2 | 65.60  | 6.526 |
| 3 | 53.711 | 4.528 |
| 4 | 57.486 | 17.411 (contention outlier) |
| 5 | 72.02  | 6.969 |

Best-of-5: BEFORE = 53.711s → **5.75 MH/s**; AFTER = 4.528s →
**68.22 MH/s**. **Ratio: 11.86x.**

**MD4**
| round | BEFORE (92d3d5f) | AFTER (de1a156) |
|---|---|---|
| 1 | 45.977 | 9.745 (contention outlier) |
| 2 | 56.857 | 4.465 |
| 3 | 32.695 | 4.057 |
| 4 | 36.406 | 3.741 |
| 5 | 46.196 | 4.098 |

Best-of-5: BEFORE = 32.695s → **9.45 MH/s**; AFTER = 3.741s →
**82.58 MH/s**. **Ratio: 8.74x.**

**MD5 (control — must be unchanged)**
| round | BEFORE (92d3d5f) | AFTER (de1a156) |
|---|---|---|
| 1 | 3.475 | 3.963 |
| 2 | 3.719 | 3.950 |
| 3 | 3.820 | 3.966 |
| 4 | 3.541 | 3.883 |
| 5 | 4.015 | 4.018 |

Best-of-5 as run: BEFORE = 3.475s → 88.90 MH/s; AFTER = 3.883s →
79.56 MH/s (ratio 0.89x) — a ~11% gap that, taken alone, would look like
a regression. Because MD5 is the control this task is explicitly on the
hook for (Tasks 1-3 refactored its runner), a second confirmation set was
run with the run order reversed (AFTER, BEFORE, AFTER, BEFORE, ...) to
separate a real regression from an order/session-drift artifact:

| round | AFTER (first) | BEFORE (second) |
|---|---|---|
| 1 | 3.509 | 4.061 |
| 2 | 4.054 | 3.715 |
| 3 | 5.380 | 9.208 |
| 4 | 5.335 | 5.720 |
| 5 | 5.340 | 6.413 |

In this reversed set AFTER's best-of-5 (3.509s) beats BEFORE's
(3.715s). Combined across both sets (best-of-10 each side): BEFORE =
3.475s → 88.90 MH/s, AFTER = 3.509s → **88.04 MH/s, ratio 0.99x**. The
first set's apparent 11% gap does not hold up once run order is
controlled for — it is session-load drift of the kind this machine is
already known to produce (~40% swings), not a code regression. **MD5 is
confirmed unchanged** within measurement noise.

## 2. Kernel level (`testing.B`, count=5, benchtime=2s, single build at HEAD)

```
go test -run XXX -bench 'BenchmarkMD4Group|BenchmarkMD4Scalar|BenchmarkMD5Group|BenchmarkMD5Scalar' -benchtime 2s -count 5 ./cmd/hashsmith
```

Best-of-5 per benchmark:

| Benchmark | Best MH/s (single-core, one `Group`/`Scalar` call) |
|---|---|
| `BenchmarkMD4Group`  | 20.85 |
| `BenchmarkMD4Scalar` | 3.880 |
| `BenchmarkMD5Group`  | 18.38 |
| `BenchmarkMD5Scalar` | 6.475 |

MD4 kernel ratio (Group/Scalar): **5.37x**. MD5 kernel ratio: **2.84x**.
These are single-core, single-call figures (`neonGroup` = 20 lanes per
call) and are not directly comparable to the multi-worker end-to-end
numbers above; they isolate the vector core's own per-call speedup from
everything else the CLI does (worker fan-out, candidate generation,
progress reporting).

MD4's kernel speedup (5.37x) is noticeably larger than MD5's (2.84x)
because MD4 is the cheaper algorithm per hash (48 steps, 3 round
constants, no trailing `+ b` in the step, vs. MD5's 64 steps and 64-entry
constant table) — the scalar baseline it is compared against is
correspondingly cheaper too, but the vector core's fixed per-call
overhead amortizes better over MD4's shorter compute, giving it more
relative headroom.

## 3. Chain count: MD4 core is 5 chains, same as MD5, not reduced to 4

`neonChains = 5` (`transposed.go`) is unchanged and shared by both the
MD5 and MD4 cores — `md4Group` (`md4neon_arm64.go`) drives all 5 chains
per call, exactly like `md5Group`. The plan flagged a risk that MD4's
majority function `G` might not fit the per-chain register budget at 5
chains, forcing a drop to 4 (and since the constant is shared, that would
have silently cost MD5 a chain too). That risk did not materialize:
MD4 is the *simpler* of the two algorithms in every register-relevant
way — 48 steps instead of 64, only 3 per-pass round constants instead of
a 64-entry table, and no trailing `+ b` in the step — so it fit
comfortably at the full 5-chain (20-way) width already proven for MD5.

## 4. Confirming the fast path actually engaged

`runBruteOrMaskLayout` (`crack.go`) only takes the NEON branch when `sess
== nil`; passing `--session <name>` forces `sess != nil`, which routes
through `runSessionLayout` (the pre-existing scalar, session-aware
runner) even on the AFTER binary. Single confirmation runs (not
best-of-5 — these are a sanity check, not a throughput measurement):

- **NTLM, AFTER binary, `--session bench-check-ntlm`:** 46.312s wall —
  same order of magnitude as the scalar BEFORE binary's 53–72s range,
  confirming the session-forced run took the scalar path. Compare to the
  non-session AFTER best-of-5 of 4.528s: an 10x gap between "fast path
  available" and "fast path forced off" on the identical binary, which is
  only possible if the fast path was genuinely engaged in the unforced
  run.
- **MD4, AFTER binary, `--session bench-check-md4`:** 33.499s wall —
  again matching scalar-class timing (BEFORE's 32.7–56.9s range) versus
  the non-session AFTER best-of-5 of 3.741s.

Both confirm the fast path was live for the headline numbers above, not
silently falling back while still producing a fast-looking number for
some other reason.

## 5. What is now accelerated, precisely — and what is not

**Accelerated:** unsalted, fixed-length MD5, MD4, and NTLM brute-force and
mask attacks, on **arm64 builds only**, where NTLM is further restricted
to candidates drawn entirely from **ASCII (< 0x80) charsets**. This is
the complete eligibility test in `fastPathEligible` (`keyspace.go`): the
build must have the vector core; the hash type must be MD5/MD4/NTLM with
no salt; the attack must have no generator override (rules out Markov and
similar); every segment must fit one fixed-length block under the
algorithm's encoding; and for NTLM, every byte of every charset must be
ASCII.

**Not accelerated — still exactly the pre-existing scalar path:**
- Every other hash format Hashsmith supports (there are roughly 460
  registered formats; only 3 — md5, md4, ntlm — have a fast algorithm at
  all).
- Salted targets of any of the three accelerated algorithms (e.g. salted
  MD5).
- Dictionary attacks, session-resume runs (`--session`/`--restore`,
  including the sanity-check runs in §4 above), Markov/hybrid/combinator
  modes, and any attack whose candidate length varies (fast path requires
  fixed-length segments).
- NTLM brute/mask attacks whose charset contains any non-ASCII byte
  (0x80–0xFF) — see §6.
- Any non-arm64 build/platform (amd64, etc.) — see §7.

Readers of the headline 8–12x figures above should not generalize them to
"Hashsmith is now 8–12x faster" — they apply to this narrow slice of
attacks only. Everything else runs at the pre-existing scalar rate
(~5–10 MH/s class on this machine, format-dependent), unchanged by this
plan.

## 6. The ASCII guard, and why it exists

Hashsmith's own NTLM implementation (`utf16le`, `hash.go:468`) does:

```go
func utf16le(s string) []byte {
	runes := utf16.Encode([]rune(s))
	...
}
```

This is a UTF-8 **decode** (`[]rune(s)`) followed by a UTF-16 **encode**,
not a naive per-byte `b, 0x00` expansion. For any non-ASCII byte the two
diverge: `[]rune(string([]byte{0xC3}))` decodes the invalid UTF-8 byte
0xC3 to U+FFFD (the replacement character), which UTF-16-encodes to bytes
`FD FF` — not the naive expansion's `C3 00`. The fast path's transposed
candidate generator (`fillFromSegment`'s `encUTF16LE` mode), by contrast,
always does the naive `b, 0x00` expansion for speed. For a charset
containing only ASCII bytes the two are identical (ASCII round-trips
through UTF-8/UTF-16 as itself), so the divergence only matters for
non-ASCII charsets — which is exactly what `fastPathEligible` excludes
(`keyspace.go`, the `algo.enc == encUTF16LE` byte-range check).

This was verified by mutation during the implementation tasks: with the
ASCII guard neutered, an NTLM brute-force over charset `ab\xC3` against a
target hash provably reachable within that keyspace exhausted all 9
candidates (3^2) and reported "Not found" — a silent wrong answer, because
the fast path was computing a different digest than Hashsmith's own
scalar `utf16le` would for the same candidate. With the guard restored,
the same run found the password in 3 attempts. Non-ASCII NTLM charsets
therefore fall back to the scalar path rather than risk this class of
silent miss.

## 7. x86 findings, for whoever picks up that work next

Rosetta 2 on this machine reports `AVX=false, AVX2=false, AVX512F=false,
SSE4.2=true` — **AVX2 cannot be executed or benchmarked on this machine
at all**, under emulation or otherwise. Any x86 work needs real x86
hardware or CI from the start; there is no local spike path here.

Separately, the pipelining that produced the arm64 win (5 independent
4-lane chains in flight, `neonChains = 5`, `neonLanes = 4`, 20-way total)
needs roughly 30 vector registers to keep 5 chains' working state live
simultaneously. AVX2 provides only 16 YMM registers — the same
architecture likely will not fit at anywhere near 5 chains, and a
plain 8-way (2-chain, or single wide-lane) AVX2 implementation risks
landing in the same ~1.26x trap that failed the original NEON gate before
the pipelined-chain redesign fixed it (a single wide SIMD lane without
independent chains in flight does not hide the algorithm's serial
dependency latency). AVX-512's 32 ZMM registers are the true register-count
analogue of what made the NEON core work.

**Recommendation:** treat x86/AVX2/AVX-512 as a spike-first go/no-go gate,
the same way Task 5 of the prior plan gated the original NEON core, run on
real x86 hardware or CI (not this machine) and targeting AVX-512
primarily — AVX2's register file is a poor match for the technique that
made the arm64 core worth building.

## 8. Recommendation: what's worth doing next

The MD4/NTLM fast path clears its own bar decisively: 11.86x (NTLM) and
8.74x (MD4) end-to-end, well past any reasonable go/no-go threshold, with
MD5 confirmed unregressed (0.99x, within noise) and the fast path's
engagement independently confirmed via the `--session`-forced scalar
comparison. There is no correctness concern outstanding from this task —
the ASCII guard closes the one identified silent-failure mode, and it is
enforced, not merely documented.

What's worth doing next, in priority order:
1. **Ship this as-is.** It is a straightforward, well-tested win for the
   two highest-value newly-accelerated targets (NTLM dominates real
   Active Directory work; MD4 is its common building block/relative).
   Nothing here blocks release.
2. **x86/AVX2/AVX-512, spike-first, on real hardware or CI** — per §7.
   This is the only path to the large multi-lane numbers the original
   design spec's floor implied, but it is new architecture-specific
   assembly work that cannot even be attempted correctly on this machine,
   so it should be scoped as a dedicated go/no-go spike before any
   committed implementation work, exactly like the prior plan's Task 5
   gated NEON.
3. **Salted MD5/MD4/NTLM fast path**, if there is demand — the transposed
   generation and pipelined core both already exist; the work would be
   threading the salt into the fixed-length block layout, which is a
   smaller lift than either of the above once the go/no-go on #2 lands.

## Repo state at time of writing

- Branch: `md4-ntlm-fast-path`, clean, no stray changes.
- One temporary worktree was used for the BEFORE build
  (`/tmp/hs-before-wt` at `92d3d5f`) and removed (`git worktree remove`,
  `git worktree prune`) before finishing this task; `git worktree list`
  shows only the main checkout.

---

# AVX2 on x86 — measured 2026-09-01

The vector fast path now runs on x86-64 as well as arm64. Unsalted,
fixed-length **MD5** brute and mask attacks use a 24-way AVX2 core (3 chains of
8 lanes) on amd64 CPUs reporting AVX2, and the existing 20-way NEON core on
arm64. MD4 and NTLM remain arm64-only — there is no AVX2 MD4 core.

## The headline

End-to-end, the real CLI, one binary, one machine, one run: the fast path
against the same binary with `--session` forcing the scalar runner. Best of 3
over a 6-character lowercase keyspace (308,915,776 candidates) with a target
deliberately absent, so both sides exhaust the space.

| runner | fast path | forced scalar | ratio |
|---|---|---|---|
| amd64 — AMD EPYC 7763 | **53.08 MH/s** | 12.79 MH/s | **4.15x** |
| arm64 — GitHub hosted | **58.29 MH/s** | 14.31 MH/s | **4.07x** |

Two different instruction sets landing within 2% of each other suggests we are
measuring the pipeline rather than a quirk of one CPU. **x86 users now get
essentially the same speedup Apple Silicon users do**, which was the point.

## Four numbers, four different questions

A spike measured this core at **12.3x** and that figure was reported upward
before it was understood. It was a real measurement of a different question.
All four, on amd64:

| measurement | MH/s | vs scalar | answers |
|---|---|---|---|
| spike, core only (EPYC 9V74) | 93.28 | 12.3x | how fast is the assembly, alone |
| core only, controlled (EPYC 9V45) | 69.42 | 5.54x | same, sibling CPU, same run as the rows below |
| core + candidate generation | 27.88 | 2.23x | the kernel as production shapes it |
| **end-to-end vs scalar CLI** | **53.08** | **4.15x** | **what a user actually gets** |

Only the last belongs in a README.

## Why the spike's 12.3x did not survive

**Candidate generation, not CPU generation.** Measured in one invocation on one
CPU, so the two are separated:

| | amd64 | arm64 |
|---|---|---|
| vector core alone | 69.42 MH/s | 38.23 MH/s |
| core + generation | 27.88 MH/s | 13.29 MH/s |
| generation cost | 21.5 ns/candidate | 49.1 ns/candidate |
| share of core throughput consumed | **60%** | **65%** |

Core-only on a Zen 5 9V45 measures 69.42 against the spike's 93.28 on a Zen 5
9V74 — the same ballpark. The 93 -> 28 collapse is generation cost the
core-only benchmark never charged, not silicon.

## And why the kernel figure understates the truth

`BenchmarkMD5Scalar` hashes a pre-built buffer and pays no generation at all,
while the *Group benchmarks pay full generation — unfair to the vector core in
one direction. But the real scalar path is not that benchmark: it allocates a
string per candidate via `maskIdxToStr`. Measured against the code users
actually run, the gain is 4.15x, not 2.23x. The same asymmetry took NEON from
3.06x at the kernel to 5.6x end to end on an M2.

**Generation is now the bottleneck, not hashing.** At 21-49 ns/candidate it
costs more than the vector core does. A wider core (AVX-512 — CI runners do
expose it) would speed up the half that is already cheap while generation stays
flat, so its end-to-end gain would be well below its core-level gain.
Optimising `fillFromSegment` is likely worth more than widening the core.

## Hardware dependence, stated plainly

Every headline in this project before today came from an Apple M2, which has
unusually good NEON throughput. The same NEON code measured **3.06x** at the
kernel on the M2 and **1.54x** on a hosted arm64 runner. Users on ordinary
server silicon should expect the lower end of any range quoted here.

## What is accelerated, precisely

Accelerated: unsalted, fixed-length **MD5** brute and mask attacks on arm64
(NEON, 20-way) and on amd64 with AVX2 (24-way); plus **MD4 and NTLM on arm64
only**, with NTLM further restricted to ASCII-only charsets.

Not accelerated, and running exactly the code they always did: the other ~460
formats; every salted target; dictionary attacks; session-resume runs;
Markov, hybrid and combinator modes; MD4 and NTLM on x86; and any platform
without NEON or AVX2.

## Open follow-ups

- An AVX2 MD4 core would bring NTLM — the Active Directory case — to x86.
- `fillFromSegment` is now the dominant cost; see above.
- End-to-end figures here are single-run best-of-3 on shared CI runners.
  Absolute MH/s will drift between runs; the ratios are same-run and hold.
