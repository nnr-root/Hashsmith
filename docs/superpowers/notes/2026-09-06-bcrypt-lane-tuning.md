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
discarded background run's numbers were broadly consistent with the ones
below (same ordering, same width-4 winner) but are not used for the
Lanes decision or the note's figures, since it was not bracketed the way
this task requires.

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
width8 1.10x. This is smaller than the 1.80x spread the bottleneck note
recorded for the raw cipher loop under much heavier load (17.99-34.98
range there vs 7.34-4.94 here), consistent with the lower load average
during this run.

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

This matches the "prior evidence projects roughly 630 c/s" orientation
given in the task brief — this measurement lands close to that
projection (651 vs ~630), on the high side but in the same
neighborhood, not a large upward or downward surprise.

Per spec `2026-09-06-bcrypt-lanes-design.md` line 253, this is recorded
as a **bar decision for the project's author**, not an engineering
failure: "If the core lands short of 887 c/s, that is a bar decision to
be made, not a defect in this design." This note takes no position on
what that decision should be; it only reports the number without
rounding in Hashsmith's favor. Restated as required by the task
instructions: the measured single-thread c/s at cost 5 with `Lanes = 4`
is 651.4, which does not clear 887.

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
