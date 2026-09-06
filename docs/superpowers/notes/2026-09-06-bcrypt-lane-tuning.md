# bcrypt lane-width tuning and speedup ratchet (Task 5)

Measured on this machine (Apple M2, darwin/arm64, 8 physical/8 logical
cores), 2026-09-06.

## Benchmark fixes applied before measuring

The Task 4 review flagged two defects in `BenchmarkWidth1/2/4/8`
(`internal/bcryptlane/eks_lanes_test.go`) that made the benchmark unfit
to set a ratchet against. Both were fixed before any measurement in this
note was taken:

1. Every lane was given the identical candidate `"candidate"`, so every
   lane hit the same S-box access offsets — not how a real wordlist
   behaves, and a plausible source of a flattering or distorting result.
   Fixed: each lane now gets a distinct, equal-length candidate
   (`fmt.Sprintf("candidate%02d", i)`), so lane counts stay comparable
   (no lane does more block encryptions than another) while access
   patterns differ.
2. `crypt, _ := bcrypt.GenerateFromPassword(...)` and `h, _ :=
   NewHasher(...)` discarded errors, so a setup failure would surface as
   a nil-pointer panic instead of a clear message. Fixed: both now use
   `b.Fatal(err)`.

## Machine load at measurement time

This machine was heavily and unevenly loaded for this whole task. An
initial benchmark attempt was run in the background and completed
successfully (176.972s wall, exit 0), but per a controller correction it
was discarded in favor of a foreground run bracketed by `uptime`
immediately before and after, which is the run reported below. The
discarded run's best-of-5 ns/candidate, recomputed from its own printed
numbers, is:

| width | discarded run | authoritative run |
|---|---|---|
| 1 | 3,458,999 | 3,386,037 |
| 2 | 2,067,628 | 1,861,100 |
| 4 | 3,002,555 | **1,535,169** |
| 8 | **1,669,500** | 1,662,749 |

**This does NOT corroborate the width-4 choice — it contradicts it.** In
the discarded run, width 8 is fastest and width 4 comes in third, behind
both width 2 and width 8. It is excluded purely on procedural grounds
(run in the background, not bracketed by `uptime`, load at the time not
recorded), not because its ranking happened to agree with the
authoritative run — it does not. Its disagreement is itself useful
evidence: it shows how far this machine's uncontrolled load can distort
which width even *looks* fastest, which is exactly why the brief
requires the bracketed, foreground, best-of-5 protocol rather than a
single convenient sample. The Lanes=4 decision below rests solely on the
authoritative bracketed run, not on any agreement with this discarded
one.

```
$ uptime
22:00  up 53 days,  6:49, 1 user, load averages: 7.34 13.12 8.70
$ go test ./internal/bcryptlane/ -bench=Width -benchtime=5s -run='^$' -count=5
[... see full output below ...]
$ uptime
22:02  up 53 days,  6:51, 1 user, load averages: 4.94 10.09 8.21
```

Load dropped during the run (30.67/16.85/8.42 at task dispatch time down
to single digits by the time this benchmark ran), which is the opposite
direction of the earlier bottleneck note's session. As stated in that
note and repeated here: **the absolute c/s figures below are still
subject to whatever contention was present during each individual
sample: session load only ever adds time, never removes it, so best-of
is the correct statistic, not mean.** The ratio between widths, and the
ratio against `x/crypto/bcrypt` measured in the same process
(`TestSpeedupOverXCrypto` below), are far more robust than any single
absolute ns/op number, because both the bcryptlane side and the
x/crypto side of that ratio suffer the same contention in the same
process at the same time.

## Raw results — all five runs per width, verbatim

```
goos: darwin
goarch: arm64
pkg: hashsmith-go/internal/bcryptlane
cpu: Apple M2
BenchmarkWidth1-8   	    1744	   3423800 ns/op	   3423799 ns/candidate
BenchmarkWidth1-8   	    1830	   3386107 ns/op	   3386037 ns/candidate
BenchmarkWidth1-8   	    1837	   3638352 ns/op	   3638352 ns/candidate
BenchmarkWidth1-8   	    1778	   3679749 ns/op	   3679748 ns/candidate
BenchmarkWidth1-8   	    1776	   3424881 ns/op	   3424880 ns/candidate
BenchmarkWidth2-8   	    1629	   3822781 ns/op	   1911389 ns/candidate
BenchmarkWidth2-8   	    1690	   3722200 ns/op	   1861100 ns/candidate
BenchmarkWidth2-8   	    1686	   4295870 ns/op	   2147935 ns/candidate
BenchmarkWidth2-8   	    1648	   4026013 ns/op	   2013006 ns/candidate
BenchmarkWidth2-8   	     916	   5686356 ns/op	   2843177 ns/candidate
BenchmarkWidth4-8   	     888	   6140679 ns/op	   1535169 ns/candidate
BenchmarkWidth4-8   	     979	   6336282 ns/op	   1584070 ns/candidate
BenchmarkWidth4-8   	     973	   6244193 ns/op	   1561048 ns/candidate
BenchmarkWidth4-8   	     970	   6168251 ns/op	   1542062 ns/candidate
BenchmarkWidth4-8   	     974	   6343386 ns/op	   1585846 ns/candidate
BenchmarkWidth8-8   	     450	  13802164 ns/op	   1725267 ns/candidate
BenchmarkWidth8-8   	     366	  14681745 ns/op	   1835218 ns/candidate
BenchmarkWidth8-8   	     400	  13302000 ns/op	   1662749 ns/candidate
BenchmarkWidth8-8   	     386	  14565827 ns/op	   1820726 ns/candidate
BenchmarkWidth8-8   	     440	  13419833 ns/op	   1677477 ns/candidate
PASS
ok  	hashsmith-go/internal/bcryptlane	154.444s
```

Intra-session spread per width (max/min of the five best-column
`ns/candidate` samples): width1 1.08x, width2 1.53x, width4 1.03x,
width8 1.10x. This machine's load average was 30.67 at this task's
dispatch time and 17.99 at this Task 5 dispatch as reported by the
controller (dropping to 7.34/4.94 by the time the bracketed benchmark
above actually ran); the bottleneck note separately recorded a 34.98
load average and up to a 1.80x ns/op spread on its own (unrelated)
cipher-loop benchmark under that heavier load. The spread observed here
is smaller than that 1.80x figure, consistent with the lower load this
run happened to see.

## Best-of-5 per width

| width | best ns/candidate |
|---|---|
| 1 | 3,386,037 |
| 2 | 1,861,100 |
| **4** | **1,535,169** |
| 8 | 1,662,749 |

Width 4 has the lowest best-of ns/candidate. Width 8 is 8.31% slower
than width 4 ((1,662,749 − 1,535,169) / 1,535,169 = 8.31%), which is well
outside the brief's 3% tie-break band, so width 4 wins outright — no
tie-break judgment call was needed. This also confirms both prior
signals cited in the task brief: the planning-session cipher-level
measurement (4 lanes 2.15x, the best of 2/4/8) and Task 4's own
ns/candidate figures (w4 lowest of the four). All three measurements —
planning, Task 4, and this task's re-measurement with the corrected
benchmark — agree on width 4.

**Chosen: `Lanes = 4`.**

## Speedup ratchet

`internal/bcryptlane/speed_test.go` adds `TestSpeedupOverXCrypto`, which
measures `h.Run` at `Lanes` width against `bcrypt.CompareHashAndPassword`
in the same process at cost 5, so both sides of the ratio absorb the
same contention.

Step 3 (single run, floor still the `0.0` placeholder):

```
=== RUN   TestSpeedupOverXCrypto
    speed_test.go:53: x/crypto 3297365 ns/op, bcryptlane 1714311 ns/candidate at 4 lanes, speedup 1.92x
--- PASS: TestSpeedupOverXCrypto (3.45s)
```

Floor set to `1.92 * 0.85 = 1.632` (written as the visible computed
expression `const bcryptSpeedupFloor = 1.92 * 0.85` in
`speed_test.go`), per the brief's 15% margin below the single observed
value.

Step 4 (`-count=3`, floor now live):

```
=== RUN   TestSpeedupOverXCrypto
    speed_test.go:53: x/crypto 3885927 ns/op, bcryptlane 1560767 ns/candidate at 4 lanes, speedup 2.49x
--- PASS: TestSpeedupOverXCrypto (3.55s)
=== RUN   TestSpeedupOverXCrypto
    speed_test.go:53: x/crypto 3388947 ns/op, bcryptlane 1564841 ns/candidate at 4 lanes, speedup 2.17x
--- PASS: TestSpeedupOverXCrypto (3.38s)
=== RUN   TestSpeedupOverXCrypto
    speed_test.go:53: x/crypto 3353483 ns/op, bcryptlane 1680756 ns/candidate at 4 lanes, speedup 2.00x
--- PASS: TestSpeedupOverXCrypto (3.40s)
```

All three passed with headroom (2.00x-2.49x observed against a 1.632x
floor); a fourth sample taken during the full-suite verification run
below logged 2.10x. No flake was observed across five total samples
(1.92, 2.49, 2.17, 2.00, 2.10x), so the 15% margin was not widened. The
per-sample speedup swings by up to 30% relative (1.92x to 2.49x) run to
run under this machine's load, which is exactly why the floor is set
15% below the single lowest-effort sample rather than an average — an
average would have produced a tighter, less safe floor.

## Derived single-thread c/s at cost 5

Using the best-of-5 width-4 figure from the width benchmark
(1,535,169 ns/candidate, not the ratchet test's own per-sample numbers,
since the width benchmark is the controlled, dedicated measurement):

```
1e9 / 1,535,169 = 651.4 c/s
```

## Does this clear the 887 c/s target?

**No.** 651.4 c/s is below the project's target of **>= 887 c/s
single-thread at cost 5** (spec `2026-09-06-bcrypt-lanes-design.md`
line 31, "1.5x John's 591"). It is, however, above John the Ripper's own
591 c/s reference figure (651.4 / 591 = 1.10x), so the work in this plan
does clear "faster than John" while falling short of the stricter 1.5x
bar.

The plan itself (`docs/superpowers/plans/2026-09-06-bcrypt-lanes.md`)
records a projected 649 c/s at 4 lanes, derived from the planning
session's 2.15x cipher-level measurement. This measurement's 651.4 c/s
is a 0.4% agreement with that projection ((651.4 − 649) / 649 = 0.37%),
tight enough to be a real cross-check rather than a coincidence dressed
up as one. A second, lower projection of roughly 630 c/s also exists,
derived from Task 4's own 2.06x ns/candidate measurement rather than the
plan's 2.15x cipher-level figure; 651.4 is 3.4% above that number. Both
projections are legitimate, from different data; the plan's own 649 c/s
figure is the more relevant one to cite as "the projection," and this
measurement lands almost exactly on it.

Per spec `2026-09-06-bcrypt-lanes-design.md` line 253, this is recorded
as a **bar decision for the project's author**, not an engineering
failure: "If the core lands short of 887 c/s, that is a bar decision to
be made, not a defect in this design." This note takes no position on
what that decision should be; it only reports the number without
rounding in Hashsmith's favor. Restated as required by the task
instructions: the measured single-thread c/s at cost 5 with `Lanes = 4`
is 651.4, which does not clear 887.

## Ratchet floor is validated on Apple M2 only

The `bcryptSpeedupFloor = 1.92 * 0.85 = 1.632` floor above was derived
entirely from measurements on this Apple M2 (darwin/arm64) machine. CI
(`.github/workflows/ci.yml`) runs the normal (non-race) test lanes on
`ubuntu-latest` (amd64) and `ubuntu-24.04-arm` (arm64), neither of which
has been measured for this ratio. Different codegen and different,
unpredictable noisy-neighbour contention on shared cloud runners could
plausibly produce a lower margin than the 15% measured here. If CI shows
this test flaking on either cloud runner, **the correct response is to
widen the margin using a real measured cross-architecture number, not to
delete or silently weaken the test** — consistent with this repository's
existing race-lane precedent for `TestBenchTypeRespectsBudgetForSlowKDF`/
`TestFastVectorsStayWithinBudget`. The margin is deliberately left at
15% here rather than pre-emptively widened, because no cross-arch data
exists yet and an invented number would itself be an unmeasured claim of
exactly the kind this project's documentation standard exists to
prevent. `TestSpeedupOverXCrypto` is excluded from the `-race` lane
(see the CI workflow's `race` job comment) because race instrumentation
is per-memory-access and the 4-lane path touches four independent cipher
states versus the x/crypto reference's one, so the two sides of the
ratio are not instrumented symmetrically and the ratio itself would be
distorted under `-race`, not merely slowed down.

## A caveat on measurement order (inherited from the brief, not fixed here)

`TestSpeedupOverXCrypto` (`speed_test.go`) always benchmarks the
bcryptlane lane path first, then the x/crypto reference second, rather
than interleaving the two. Any monotonic drift across the ~7 seconds the
test takes to run — CPU thermal throttling kicking in partway through
being the obvious candidate on a laptop-class chip under sustained load
— would bias whichever side runs second, and therefore bias the
reported ratio in one consistent direction rather than adding
zero-mean noise. This ordering is inherited verbatim from the task
brief's specified test code and was not something this task's
measurements could correct without deviating from the brief. It is
flagged here as a reason the exact ratchet-test speedup numbers (1.92x-
2.49x) should be read as directionally trustworthy rather than
precise to two decimal places; it does not affect the width-benchmark
numbers used for the Lanes choice or the 651.4 c/s figure, which do not
compare two different code paths within one test run.

## Observed flake under load (Task 6 fix round 1)

During Task 6's code review, `go test ./internal/bcryptlane/` was run on
this same tuning machine while under contention from the review's own
concurrent test execution, and `TestSpeedupOverXCrypto` **failed**:
reported speedup 1.18x, below the 1.632 floor derived above. `uptime` at
that time showed a load average of 30 on this machine's 8 cores. All ten
correctness tests in the package passed in that same run; only this
single wall-clock ratio gate failed. This is exactly the scenario this
note's "Ratchet floor is validated on Apple M2 only" section anticipated
in the abstract (noisy-neighbour contention producing a lower margin than
the 15% measured here) — the difference is this is now a measured
occurrence on the tuning machine itself, not only a risk flagged for
other CI runners.

Per the controller's Task 5 ruling, a flake is answered with measured
data, not by deleting or weakening the test. The response implemented in
Task 6 fix round 1 (`speed_test.go`):

1. Both sides of the ratio (the lane hasher and the x/crypto reference)
   now take the **minimum of 5 samples** via a `bestOfN` helper, rather
   than one `testing.Benchmark` call each — load only ever adds time to a
   wall-clock sample, so the minimum is the closest available estimate of
   the unloaded cost.
2. A **load guard**: `refQuietBaselineNs` (~3.3ms) records this same
   machine's quiet-machine best-of-5 for `bcrypt.CompareHashAndPassword`
   at cost 5 (see `docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md`,
   which measured 3,305,662 ns/op library-wrapped / 3,291,526 ns/op raw
   under low load). If the reference side's best-of-5 exceeds 2x that
   baseline, the test now calls `t.Skipf` with a message naming the
   observed value, the baseline, and stating explicitly that a skip means
   "not measured here" — never "passed".
3. The `1.632` floor itself is **unchanged**. The floor is correct for a
   quiet machine; the defect this fixes is that the test could not tell a
   loaded machine apart from a real regression, not that the floor was
   wrong.

This section is deliberately not softened: it records that the ratchet
was observed to fail (not skip, not pass) at 1.18x under load average 30
on the tuning machine, as evidence about the measurement environment, per
the controller's explicit instruction not to present this as anything
gentler than what was measured.

## Summary

| Quantity | Value |
|---|---|
| Chosen `Lanes` | 4 |
| Best-of-5 ns/candidate at chosen width | 1,535,169 |
| Derived c/s at cost 5 | 651.4 |
| Speedup over x/crypto/bcrypt (single sample used for floor) | 1.92x |
| Speedup over x/crypto/bcrypt (range across 5 samples) | 1.92x-2.49x |
| Ratchet floor (`bcryptSpeedupFloor`) | 1.92 * 0.85 = 1.632 |
| Clears John the Ripper (591 c/s)? | Yes, 1.10x |
| Clears project target (887 c/s)? | **No** |
| Observed flake (Task 6 review, load avg 30) | 1.18x FAIL — see "Observed flake under load" above |
| Fix | best-of-5 sampling + 2x-baseline load guard (`t.Skipf`, not a floor change) |
