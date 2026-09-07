# bcrypt lane core — measured against John and Hashcat (Task 8)

Date: 2026-09-07. Machine: Apple M2 (8-core, 4P+4E), darwin/arm64, same
machine as every earlier measurement in this project. `hashsmith` binary
built from this branch (`bcrypt-lanes`) at
`go build -o /tmp/hashsmith-lanes ./cmd/hashsmith`. `john` is
john-jumbo, `hashcat` is v7.1.2, both on `PATH`. Fixtures: bcrypt cost 5,
target password `notinlist` absent from every wordlist so all three tools
exhaust the full keyspace — the same discipline every earlier measurement
in this project used.

```
$2a$05$yyfw09MYDWmWagysVnNeQ.Q0B/pZZgImT/JWoBv9keGxxXReQ65iq
```

**This session shared the machine with unrelated, uncontrolled load for
its entire duration**, and that load got dramatically worse as the
session went on — worse than anything previously documented in this
project. At dispatch the machine was reported at 3.99/15.97/19.27 (the
quietest point in this project's history). By the end of the 40k block
it was 14.42/15.87/16.66. By the 400k block it reached **86.19/80.32/56.90**
— nearly 3x the load-30 spike that this plan's Task 6 review previously
called out as the worst seen so far. `ps aux` at that point showed the
load coming from entirely unrelated processes on this shared machine: an
`ffmpeg` transcode, a `pytest` run, a `midas-research audit` process, a
`Virtualization.framework` VM, and multiple other Claude Code sessions —
nothing to do with this task. Every number below is reported with the
`uptime` readings that bracket it, per the task's measurement discipline,
and the 400,000-candidate three-way comparison was dropped for reasons
explained in its own section below.

Every run below is verbatim. First run at each new size for each tool is
explicitly marked DISCARDED and excluded from best-of; it is still shown
in full so nothing is hidden. Exit code 1 / "Not found" from Hashsmith
runs is expected — the password is absent by construction.

## Part A — single-thread, the headline number

`uptime` before block: `8:07  load averages: 7.28 12.85 17.58`
`uptime` after block: `8:09  load averages: 5.18 10.10 15.78`

Command: `/tmp/hashsmith-lanes crack -t bcrypt "$H" -w wl4000.txt -p 1 -N --no-pot`

```
$ /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl4000.txt -p 1 -N --no-pot   [DISCARDED — warm-up, untimed]
Attempts: 4000 | Elapsed: 6.26s | Rate: 639.22 H/s
Not found

$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl4000.txt -p 1 -N --no-pot   [kept, run 1]
Attempts: 4000 | Elapsed: 6.51s | Rate: 614.06 H/s
Not found
...6.26s user 0.06s system 96% cpu 6.560 total

$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl4000.txt -p 1 -N --no-pot   [kept, run 2]
Attempts: 4000 | Elapsed: 8.08s | Rate: 495.05 H/s
Not found
...7.37s user 0.08s system 91% cpu 8.103 total

$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl4000.txt -p 1 -N --no-pot   [kept, run 3]
Attempts: 4000 | Elapsed: 8.47s | Rate: 472.32 H/s
Not found
...7.47s user 0.11s system 88% cpu 8.523 total
```

Best-of-kept wall clock: **6.560 s** (kept run 1). Single-thread c/s =
4000 / 6.560 = **609.76 c/s**.

```
$ john --test=10 --format=bcrypt    [DISCARDED — warm-up]
Benchmarking: bcrypt ("$2a$05", 32 iterations) [Blowfish 32/64 X2]...
Raw:	349 c/s real, 513 c/s virtual

$ john --test=10 --format=bcrypt    [kept, run 1]
Raw:	514 c/s real, 521 c/s virtual

$ john --test=10 --format=bcrypt    [kept, run 2]
Raw:	494 c/s real, 499 c/s virtual
```

Best-of-kept John real c/s: **514 c/s**.

### Single-thread table

| | c/s (best-of-kept) |
|---|---|
| Hashsmith (this measurement) | 609.76 |
| Task 5's isolated core measurement (`docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md`) | 651.4 |
| John the Ripper (`--test=10`, this measurement) | 514 |
| John the Ripper (design-doc reference, quiet machine) | 591 |
| Project target | 887 |

The end-to-end CLI number (609.76 c/s) is 93.6% of Task 5's isolated
651.4 c/s figure, which is the expected direction: the CLI path pays
wordlist I/O, flag parsing and reporting overhead the isolated benchmark
does not. It is **not** a contradiction of Task 5's figure; it is a
lower, CLI-inclusive number on the same core, measured under today's
higher load. 609.76 / 514 = **1.19x** today's John `--test=10` reading.

**Correction, made in this fix round:** this paragraph originally argued
that 514 c/s was itself load-depressed against John's 591 c/s
quiet-machine reference, and that the 1.19x ratio should therefore not be
read as a widened margin. That argument does not reconcile with this
session's own data and is withdrawn. In the same session, John's
`--fork=8` runs sustained 560-576 candidates per CPU-second per worker
(see "Candidates per CPU-second" below) — *above* the 514 c/s `--test`
figure, not below it — and John's 40,000-candidate wall clock (13.669s)
was 1.216x *faster* than its own pre-lane 16.61s reference (see the
before/after table below). A machine uniformly depressing John's
performance should depress the single-thread self-report and the
forked, sustained rate together; it did not. The likelier explanation is
that `john --test=10` simply is not a reliable single-thread number on
this machine, under any load — not that today's reading was suppressed
relative to a "true" 591 c/s. The withdrawn argument erred
conservatively — it withheld credit from Hashsmith rather than inflating
it — but it was still wrong, and stands corrected here rather than left
standing uncorrected.

Read against the sustained per-CPU-second figure instead of `--test`,
Hashsmith's 609.76 c/s is **1.06x-1.09x** John (609.76/576 to 609.76/560),
not 1.19x. Against the 887 c/s target, 609.76 c/s is **68.7%** of the bar
regardless of which John comparator is used. Against Task 5's own
651.4 c/s (measured on a quieter machine), that number was already
**73.4%** of 887 and **1.10x** John's quiet-machine 591 c/s reference —
both this session's and Task 5's numbers land well short of 887 c/s and
only modestly ahead of John by any comparator used. This is stated
without softening.

## Part B — multi-threaded wall clock

Hashsmith and Hashcat use all cores by default; John is given
`--fork=8` to match (8 physical cores on this machine), so every tool is
given the whole machine, per the task's requirement not to time an
8-core tool against a 1-core one.

### N = 4,000

`uptime` before block: `8:09  load averages: 4.22 9.48 15.39`
`uptime` after block: `8:11  load averages: 7.46 9.46 14.77`

```
$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl4000.txt -N --no-pot   [DISCARDED]
...6.81s user 0.08s system 580% cpu 1.188 total

$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl4000.txt -N --no-pot   [kept, run 1]
...7.02s user 0.18s system 264% cpu 2.725 total

$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl4000.txt -N --no-pot   [kept, run 2]
...6.92s user 0.18s system 381% cpu 1.860 total
```
Hashsmith best-of-kept: **1.860 s**.

```
$ time john --format=bcrypt --wordlist=/tmp/wl4000.txt --fork=8 --pot=/tmp/j4000a.pot --session=j4000a /tmp/bc.txt   [DISCARDED]
...6.92s user 0.59s system 274% cpu 2.737 total

$ time john --format=bcrypt --wordlist=/tmp/wl4000.txt --fork=8 --pot=/tmp/j4000b.pot --session=j4000b /tmp/bc.txt   [kept, run 1]
...7.09s user 0.63s system 211% cpu 3.642 total

$ time john --format=bcrypt --wordlist=/tmp/wl4000.txt --fork=8 --pot=/tmp/j4000c.pot --session=j4000c /tmp/bc.txt   [kept, run 2]
...6.98s user 0.56s system 326% cpu 2.310 total
```
John best-of-kept: **2.310 s**.

```
$ time hashcat -m 3200 -a 0 --potfile-disable --quiet --session=h4000a /tmp/bc.txt /tmp/wl4000.txt   [DISCARDED — kernel-cache warm-up]
...0.21s user 0.69s system 3% cpu 28.508 total

$ time hashcat -m 3200 -a 0 --potfile-disable --quiet --session=h4000b /tmp/bc.txt /tmp/wl4000.txt   [kept, run 1]
...0.22s user 0.71s system 10% cpu 8.451 total

$ time hashcat -m 3200 -a 0 --potfile-disable --quiet --session=h4000c /tmp/bc.txt /tmp/wl4000.txt   [kept, run 2]
...0.18s user 0.59s system 10% cpu 7.219 total
```
Hashcat best-of-kept: **7.219 s**. The discarded run (28.508 s) vs. the
kept runs (8.451 s, 7.219 s) is the same kernel-cache-warming effect this
project's earlier measurements documented (37.90s → 22.32s) — discarding
it is not optional.

At 4,000: **Hashsmith (1.860 s) is faster than John (2.310 s)** — a
1.24x margin. That margin is smaller than the run-to-run spread within
each tool's own kept runs at this size (Hashsmith 1.860s-2.725s, a
1.47x spread; John 2.310s-3.642s, a 1.58x spread), so — per the standard
this project set in `2026-09-06-bcrypt-bottleneck.md`, "the spread here
is large and must be stated plainly, not averaged away" — this margin
should be read as directional, not as a precise, reproducible 1.24x.

### N = 40,000

`uptime` before block: `8:11  load averages: 7.46 9.46 14.77`
`uptime` mid-block (before Hashsmith kept run 1): `8:12  load averages: 39.36 16.89 17.07` — a real spike, not a typo; noted here because it directly explains the outlier below.
`uptime` after block: `8:15  load averages: 14.42 15.87 16.66`

```
$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl40000.txt -N --no-pot   [DISCARDED]
...87.29s user 1.20s system 524% cpu 16.875 total

$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl40000.txt -N --no-pot   [kept, run 1]
...89.20s user 1.62s system 260% cpu 34.922 total

$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl40000.txt -N --no-pot   [kept, run 2]
...85.04s user 1.20s system 525% cpu 16.411 total
```
Hashsmith best-of-kept: **16.411 s**. Kept run 1 (34.922 s) landed during
the 39.36 load spike above and is more than double kept run 2 — this is
exactly the kind of session-level contention this project's earlier notes
describe, kept in the record rather than dropped, with best-of correctly
discarding it in favour of the faster, less-contended sample.

```
$ time john --format=bcrypt --wordlist=/tmp/wl40000.txt --fork=8 --pot=/tmp/j40000a.pot --session=j40000a /tmp/bc.txt   [DISCARDED]
...71.39s user 1.82s system 421% cpu 17.377 total

$ time john --format=bcrypt --wordlist=/tmp/wl40000.txt --fork=8 --pot=/tmp/j40000b.pot --session=j40000b /tmp/bc.txt   [kept, run 1]
...69.73s user 1.49s system 521% cpu 13.669 total

$ time john --format=bcrypt --wordlist=/tmp/wl40000.txt --fork=8 --pot=/tmp/j40000c.pot --session=j40000c /tmp/bc.txt   [kept, run 2]
...69.44s user 1.75s system 353% cpu 20.155 total
```
John best-of-kept: **13.669 s**.

```
$ time hashcat -m 3200 -a 0 --potfile-disable --quiet --session=h40000a /tmp/bc.txt /tmp/wl40000.txt   [DISCARDED]
...0.23s user 0.71s system 4% cpu 23.359 total

$ time hashcat -m 3200 -a 0 --potfile-disable --quiet --session=h40000b /tmp/bc.txt /tmp/wl40000.txt   [kept, run 1]
...0.23s user 0.69s system 3% cpu 23.419 total

$ time hashcat -m 3200 -a 0 --potfile-disable --quiet --session=h40000c /tmp/bc.txt /tmp/wl40000.txt   [kept, run 2]
...0.25s user 0.76s system 3% cpu 25.504 total
```
Hashcat best-of-kept: **23.419 s**.

At 40,000: **John (13.669 s) is faster than Hashsmith (16.411 s)** — John
wins by 1.20x. This is stated plainly: the wall-clock half of the target
is **not** met at this size. As at 4,000, this margin sits inside the
recorded run-to-run spread — Hashsmith's kept runs span 16.411s-34.922s
(2.13x) and John's span 13.669s-20.155s (1.47x) — so the same caveat
applies: directional, not a precise 1.20x.

### N = 400,000 — dropped from the three-way comparison

`uptime` before this block: `8:15  load averages: 23.65 18.04 17.43`

```
$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl400000.txt -N --no-pot   [attempt 1, discard-equivalent]
Attempts: 400000 | Elapsed: 475.66s | Rate: 840.94 H/s
Not found
...892.38s user 20.81s system 191% cpu 7:55.73 total   (= 475.73 s)
```
`uptime` immediately after: `8:23  load averages: 67.76 52.51 35.85`.
`ps aux` at that point showed the load coming from unrelated processes
sharing this machine: an `ffmpeg` transcode at 171% CPU, a `pytest` run,
a `midas-research audit` process, and a long-running
`Virtualization.framework` VM, none of which belong to this task.

```
$ time /tmp/hashsmith-lanes crack -t bcrypt '$2a$05$...' -w /tmp/wl400000.txt -N --no-pot   [attempt 2]
Attempts: 400000 | Elapsed: 578.59s | Rate: 691.34 H/s
Not found
...897.68s user 26.61s system 159% cpu 9:38.87 total   (= 578.87 s)
```
`uptime` immediately after: `8:33  load averages: 86.19 80.32 56.90`.
A further check one minute later still showed `8:34  69.80 77.00 56.12`.

Between the two Hashsmith-only attempts above, wall clock got **worse**
(475.66s → 578.59s) while load climbed (23-67 → 67-86), and `cpu%`
utilization *fell* (191% → 159%) even though the tool asks for all
cores — direct evidence the process was starved of CPU by unrelated
work, not that the algorithm regressed. Load average 86 on an 8-core
machine is more than triple the load-30 flake this project's Task 6
review previously called the worst seen, and nearly 4x the 23.65 reading
this 400k block started at only minutes earlier.

**Decision: 400,000 is dropped from the three-way wall-clock comparison.**
This decision stands on its own evidence — load 86, and `cpu%` falling
from 191% to 159% while wall clock rose between the two attempts above —
and does not need a citation to authorize it, but for the record: the
controller's dispatch instruction for this task allowed dropping a size
"if it proves too slow to complete within your timeouts" and instructed
saying so explicitly rather than silently omitting it (that sentence is
in the controller's dispatch message for this task, not in
`task-8-brief.md` itself — misattributed to the brief in an earlier
version of this note; corrected here). Both individual Hashsmith runs
above did complete inside the 15-minute Bash timeout, so this is not a
timeout in the literal sense, but running
John (which forks 8 processes) and Hashcat at this size, several times
each, under a load average that hit 86 and was still climbing, would
have taken an unknown and possibly very long time to produce numbers
that measure this machine's unrelated contention far more than they
measure any of the three tools. No John or Hashcat run was attempted at
400,000. The two Hashsmith-only numbers above are reported for
completeness and honesty about what was attempted, not as part of any
tool-vs-tool comparison.

### Wall-clock comparison table

| candidates | Hashsmith | John `--fork=8` | Hashcat | Hashsmith vs. John |
|---|---|---|---|---|
| 4,000 | 1.860 s | 2.310 s | 7.219 s | **Hashsmith faster, 1.24x** |
| 40,000 | 16.411 s | 13.669 s | 23.419 s | **John faster, 1.20x** |
| 400,000 | not compared — dropped, see above | not run | not run | — |

**This table contradicts Part A, and the contradiction is the most
interesting fact in this measurement.** Part A's single-thread numbers
say Hashsmith is modestly *ahead* of John per core (1.06x-1.19x
depending on comparator). Both tools are then given the whole machine.
A per-thread lead that turns into a wall-clock *loss* at 40,000 is not
"consistent with" the per-thread table — a per-thread win times 8 cores
should not become a wall-clock loss unless something is eating
Hashsmith's per-core advantage specifically as the run scales from 4,000
to 40,000 candidates. That something is not identified by this note; the
section below shows where it is visible and what is ruled out.

### Candidates per CPU-second

Every `time` block above reports `user` CPU-seconds, which — unlike wall
clock — are not distorted by the warm-up effects that motivate
discarding a tool's first run at a new size, so all three runs at each
size (including the discarded one) are used here:

| | Hashsmith c/s per CPU-sec | John c/s per CPU-sec |
|---|---|---|
| 4,000 (discard, kept 1, kept 2) | 587, 570, 578 | 578, 564, 573 |
| 40,000 (discard, kept 1, kept 2) | 458, 448, 470 | 560, 574, 576 |

(4,000: Hashsmith = 4000 / {6.81, 7.02, 6.92}; John = 4000 / {6.92, 7.09,
6.98}. 40,000: Hashsmith = 40000 / {87.29, 89.20, 85.04}; John = 40000 /
{71.39, 69.73, 69.44}, all user-CPU-second denominators taken verbatim
from Part B above.)

At 4,000 the two tools are level (Hashsmith 570-587, John 564-578,
overlapping). At 40,000 John pulls **~1.2x ahead, consistently across
all six 40,000-candidate runs** (Hashsmith 448-470 vs. John 560-576):
taking the best (highest) per-CPU-second figure at each size — the same
best-of discipline used throughout this note, and the most favourable
comparison available to Hashsmith — Hashsmith's own best falls from 587
to 470, a **19.9% drop**, while John's best barely moves, 578 to 576, a
0.3% change indistinguishable from flat. This is the shape behind the
wall-clock contradiction above:
Hashsmith is not doing less useful work per candidate as the run scales
up — its total CPU-seconds spent per candidate produced is going *up*,
specifically between 4,000 and 40,000, in a way John's is not.

**Hypothesis, not conclusion: heterogeneous cores.** One candidate
explanation — L1 cache contention among the 8 lane workers — was
proposed during this fix round and checked, then ruled out: the M2's L1D
is private per physical core (128 KB per P-core, 64 KB per E-core), so
eight concurrent lane workers do not share one cache; each worker's
working set (~16.7 KB derived from the lane state) fits easily even in
an E-core's smaller L1D, and the aggregate ~267 KB across all workers
only reaches the shared L2 (16 MB/4 MB), well under 2% occupancy. That
explanation does not fit the data and is not used here.

What the data does support: Apple M2 is 4 performance cores (P-cores)
plus 4 efficiency cores (E-cores), and effective core occupancy — total
(user+system) CPU-seconds divided by total wall-seconds, summed across
runs, which is more robust than averaging the reported CPU% column — in
this session rises from roughly **3.7** at 4,000 candidates
((6.89+7.20+7.10) CPU-sec / (1.188+2.725+1.860) wall-sec = 21.19/5.773 =
3.67, all three Hashsmith runs at that size) to roughly **5.2** at
40,000 ((88.49+86.24) / (16.875+16.411) = 174.73/33.286 = 5.25, using
the discarded run and kept run 2 only — kept run 1 at this size
(34.922s) is excluded from this specific calculation because it landed
during the documented 39.36 load spike, where its CPU% is spuriously
*depressed* by contention for cores rather than informative about this
binary's own steady-state core usage). The rise from ~3.7 to ~5.2
suggests the E-cores only really engage once the run is large enough
and long enough for the scheduler to spread work onto them, which is
precisely the 40,000-candidate block where Hashsmith's per-CPU-second
rate collapses and John's does not. Lane interleaving is an instruction-level-parallelism
technique — it wins by keeping more independent operations in flight per
cycle — and ILP gains scale with a core's issue width and out-of-order
resources; M2's E-cores are substantially narrower than its P-cores in
both respects. John's approach (one scalar bcrypt computation per forked
process) has no comparable dependency on issue width, so it would not be
expected to lose ground on an E-core the way an ILP-dependent lane core
would. If this is right, roughly half of this 8-core machine (the 4
E-cores) does not deliver the lane speedup the P-cores do, and an 8-way
wall-clock comparison blends a strong P-core result with a weaker
E-core one in a way a single-thread (`-p 1`, P-core-scheduled) benchmark
never sees.

This is supported by six pairs of runs and a plausible mechanism, not
proven. Machine contention during this session (documented throughout
this note, up to load 86) is an uncontrolled confound that could produce
a similar-looking pattern for unrelated reasons, and this note cannot
separate the two. **Settling it needs a quiet-machine comparison this
session could not perform:** run the Hashsmith binary pinned or limited
to `-p 4` (P-cores only, if the four fastest cores can be identified and
pinned to) against `-p 8` (all cores) at a fixed candidate count, on an
otherwise-idle machine, and compare per-CPU-second throughput between
the two. If the P-core-only run sustains close to the 4,000-candidate
rate while the 8-core run degrades toward the 40,000-candidate rate,
that is direct evidence for the heterogeneous-core explanation; if both
degrade equally, it is not.

**The single-thread core speedup does not carry through to the
end-to-end wall-clock gain.** Task 5 measured the lane core at 2.15x-
2.49x faster than `x/crypto/bcrypt` in isolation. End to end, this
measurement's 609.76 c/s single-thread against Task 1's pre-lane 302 c/s
baseline (`docs/superpowers/specs/2026-09-06-bcrypt-lanes-design.md`,
line 13: `bcrypt.CompareHashAndPassword` today, 302 c/s) is
**609.76 / 302 = 2.02x** — close to the isolated core figure. At 40,000
candidates wall clock, the before/after gain (next section) is only
**1.14x**. That gap between 2.02x single-thread and 1.14x at 40k wall
clock, not either number alone, is this measurement's central finding.

### Before/after comparison at 40,000 (the plan's own reference point)

The design doc (`docs/superpowers/specs/2026-09-06-bcrypt-lanes-design.md`,
measured before this plan's lane work) recorded, at 40,000 candidates,
best of two, on this same machine: Hashsmith 18.74 s, John `--fork=8`
16.61 s, Hashcat 22.32 s. That measurement's own `uptime` conditions are
not recorded in the design doc, so this is not a perfectly clean A/B —
only today's own conditions are known and stated above.

| | before (design doc) | after (this measurement) | change |
|---|---|---|---|
| Hashsmith | 18.74 s | 16.411 s | **1.142x faster** |
| John `--fork=8` | 16.61 s | 13.669 s | 1.216x faster |
| Hashcat | 22.32 s | 23.419 s | 1.049x slower |

Hashsmith did get faster at 40k — 18.74s to 16.411s is a real, measured
**12.4% wall-clock reduction** ((18.74 − 16.411) / 18.74 = 0.1243),
equivalently a **1.142x rate gain** (18.74 / 16.411 = 1.142, matching
the table's "1.142x faster" — that factor is a rate ratio, not a
percentage reduction; the two quantities are not the same number, and
an earlier version of this note conflated them by quoting "14.2%" for
the wall-clock reduction, which is wrong and errs in Hashsmith's favour).
12.4% is the clearest single statement of what the lane work in this
plan bought at this size. But John also got faster over the
same interval (16.61s to 13.669s, a larger relative improvement), so
Hashsmith's position relative to John did not improve — it was already
behind John at this size before this plan's lane work (18.74s vs
16.61s), and it is still behind John after it (16.411s vs 13.669s).
Whether John's own improvement here reflects real machine variance,
today's specific load pattern, or something else is not established by
this note.

## Verdict against the two-part target

Spec (`docs/superpowers/specs/2026-09-06-bcrypt-lanes-design.md:31`):
**>= 887 c/s single-thread at cost 5, AND faster wall clock than
`john --fork=8` at every size tested.**

- **Single-thread half: NOT MET.** 609.76 c/s (this measurement) and
  651.4 c/s (Task 5's isolated, quieter-machine measurement) are both
  below 887 c/s — 68.7% and 73.4% of the bar respectively. Task 5's own
  figure is 1.10x John's quiet-machine reference (591 c/s), well short of
  the 1.5x the target requires.
- **Wall-clock half: NOT MET.** Hashsmith is faster than John at 4,000
  (1.24x) but slower than John at 40,000 (John 1.20x faster) — and, per
  the caveat above, both margins sit inside this session's own
  run-to-run spread and should be read as directional. "Faster at every
  size tested" fails at the second size tested regardless; 400,000 was
  not tested for this comparison (see above), so it cannot count toward
  either meeting or failing the bar.

**Neither half of the target is met.** Per the design doc's own §8
("Risks and decisions taken"), this is recorded as **a bar decision for
the project's author, not an engineering failure** — the design doc
states this in advance: "If the core lands short of 887 c/s, that is a
bar decision to revisit, not rework." This note takes the same position
Task 5's note took and does not soften it: the numbers are what they
are, and they do not clear the bar as written. Equally, they are not
spun as a win — Hashsmith remains ahead of John's *sustained,
per-CPU-second* rate by a modest margin (1.06x-1.09x, superseding the
unreliable `--test=10` self-report; see "Candidates per CPU-second"
above), and ahead of John's wall clock at the smallest size tested, but
behind it at the next size up.

That size-dependence is not a minor wrinkle to note in passing: per-
thread, Hashsmith leads John modestly at every candidate count measured;
at the machine level, that lead **inverts** between 4,000 and 40,000
candidates, and the isolated core's 2.15x-2.49x speedup over
`x/crypto/bcrypt` shows up end to end as 2.02x single-thread but only
1.14x at 40,000 wall clock. "Candidates per CPU-second" above lays out
what evidence exists for *why* — a heterogeneous P-core/E-core
hypothesis, not proven, with contention as an uncontrolled confound and
a specific quiet-machine `-p 4` vs. `-p 8` experiment named as the way to
settle it. This is the scenario the design doc's own §1 warned about in
the abstract (near-parity or narrow wins at small scale do not reliably
hold as scale changes) but the specific mechanism — a per-thread win
inverting at machine scale, not merely narrowing — is more than that
warning anticipated, and is not explained by anything measured in this
task.

## Full verification (Step 7)

Run from `hashsmith/go_hashsmith`:

```
$ go build ./...
(clean)

$ go vet ./...
(clean)
```

`go test ./...` **failed on its first run** under the same extreme load
documented above:

```
--- FAIL: TestSpeedupOverXCrypto (15.16s)
    speed_test.go:101: x/crypto 4025286 ns/op (best of 5), bcryptlane 3055982 ns/candidate (best of 5) at 4 lanes, speedup 1.32x
    speed_test.go:104: speedup 1.32x is below the 1.63x floor
FAIL
FAIL	hashsmith-go/internal/bcryptlane	31.560s
```

`uptime` at the time: load average in the 32-86 range documented above.
This test's own load guard (`speed_test.go`) only skips when the
reference benchmark's best-of-5 exceeds 2x its quiet-machine baseline
(6.6ms); the reference side's best-of-5 here was 4.03ms — under that
skip threshold despite the machine being extraordinarily loaded — so the
test ran for real and failed for real rather than skipping. This is
reported as a **FAIL**, not softened into a skip it did not report.

Re-run once, per this project's established practice
(`2026-09-06-bcrypt-lane-tuning.md`, "Observed flake under load") of
answering a load-induced flake with more measured data rather than by
deleting or weakening the test:

```
$ go test ./internal/bcryptlane/... -run TestSpeedupOverXCrypto -v
=== RUN   TestSpeedupOverXCrypto
    speed_test.go:101: x/crypto 3442039 ns/op (best of 5), bcryptlane 1580746 ns/candidate (best of 5) at 4 lanes, speedup 2.18x
--- PASS: TestSpeedupOverXCrypto (18.54s)
PASS
```

`uptime` at that point: `26.55 56.17 52.07` — still elevated, but this
particular best-of-5 window landed clean. Full suite re-run afterward:

```
$ go test ./...
ok  	hashsmith-go/cmd/hashsmith	(cached)
?   	hashsmith-go/internal/argon2d	[no test files]
ok  	hashsmith-go/internal/bcryptlane	25.898s
?   	hashsmith-go/internal/gpubackend	[no test files]
ok  	hashsmith-go/internal/hashid	(cached)
```

`go run ./cmd/hashsmith selftest -slow`:

```
Self-test: 502/502 vectors passed
  published      371
  cross-checked  112
  regression     19

  457 of 457 crackable formats carry a vector; 0 do not.
```

502/502 passed on the slow selftest (every KDF vector included, not a
`-short` run). `TestSpeedupOverXCrypto` is recorded here as: **FAILED
once at 1.32x under a documented 32-86 load average, then PASSED at
2.18x on immediate re-run under still-elevated but lower load (26-56)**.
This is not presented as an unqualified pass — the failure happened and
is on the record, exactly as this project's practice requires for a
load-sensitive test under contention this severe.
