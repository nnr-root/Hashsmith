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
higher load. 609.76 / 514 = **1.19x** today's John reading, but that
reading of John (514 c/s) is itself well below the design doc's own
quiet-machine reference for John (591 c/s) — today's John number is
almost certainly load-depressed too, so the 1.19x ratio should not be
read as evidence the margin over John widened; it is two numbers each
measured under contention, not a clean comparison. Against the 887 c/s
target, 609.76 c/s is **68.7%** of the bar. Against Task 5's own
651.4 c/s (measured on a quieter machine), that number was already
**73.4%** of 887 and **1.10x** John's quiet-machine 591 — if today's
end-to-end figure agrees with that shape, it is because it does: both
numbers land well short of 887 c/s and only modestly ahead of John,
exactly as Task 5 reported. This is stated without softening.

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
1.24x margin.

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
is **not** met at this size.

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
The brief for this task explicitly allows dropping a size "if it proves
too slow to complete within your timeouts" and instructs saying so
explicitly rather than silently omitting it — this is that case. Both
individual Hashsmith runs above did complete inside the 15-minute Bash
timeout, so this is not a timeout in the literal sense, but running
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
14.2% wall-clock reduction, and is the clearest single statement of what
the lane work in this plan bought. But John also got faster over the
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
  (1.24x) but slower than John at 40,000 (John 1.20x faster). "Faster at
  every size tested" fails at the second size tested; 400,000 was not
  tested for this comparison (see above), so it cannot count toward
  either meeting or failing the bar.

**Neither half of the target is met.** Per the design doc's own §8
("Risks and decisions taken"), this is recorded as **a bar decision for
the project's author, not an engineering failure** — the design doc
states this in advance: "If the core lands short of 887 c/s, that is a
bar decision to revisit, not rework." This note takes the same position
Task 5's note took and does not soften it: the numbers are what they
are, and they do not clear the bar as written. Equally, they are not
spun as a win — Hashsmith remains ahead of John's *own single-thread
self-report* by a modest margin (609.76 vs. 514 c/s today, and 651.4 vs.
591 c/s on Task 5's quieter measurement), and ahead of John's wall clock
at the smallest size tested, but behind it at the next size up, which is
the scenario the design doc's own §1 warned about: near-parity or
narrow wins at small scale do not reliably hold as scale (or here,
contention) changes.

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
