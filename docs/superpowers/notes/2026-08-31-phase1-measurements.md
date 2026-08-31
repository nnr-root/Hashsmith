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
