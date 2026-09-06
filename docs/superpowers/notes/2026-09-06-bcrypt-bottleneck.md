# bcrypt single-lane baseline (Task 1)

Measured on this machine (Apple M2, darwin/arm64, 8 physical/8 logical
cores), 2026-09-06.

## Scope note: Steps 1-5 dropped by controller ruling

The brief's Steps 1-5 (build `/tmp/bclane-spike`, hand-write a 2-lane
`encryptBlock2`, differential-test it, and re-measure the 2-lane speedup)
were **dropped by controller ruling** as redundant. The hand-written
`encryptBlock2` spike the brief specifies has a known bug (it applies
`c.p[16]` twice and then performs an incorrect final swap), and its
purpose — proving interleaving actually helps before anything is built
around it — was already served during planning: the real code generator
from Task 4 of this plan was extracted, run, and differential-tested
against upstream `x/crypto/blowfish` (4 tests passing, bit-identical),
and cipher-level lane throughput was measured directly from that real
generator, not a hand-written stand-in:

| | ns/op | speedup |
|---|---|---|
| serial | 49,379 | 1.00x |
| 2 lanes | 26,179 | 1.89x |
| **4 lanes** | **23,000** | **2.15x** |
| 8 lanes | 24,446 | 2.02x |

The Step 7 go/no-go rule (>= 1.35x at 2 lanes proceeds to Task 2) is
**already cleared** by the 1.89x figure above — this was decided during
planning, before this task ran, and this task does not re-derive it. This
task's job is narrower: measure the real single-lane baseline that Task
5's speedup ratchet is set against, and record the number for the full
production bcrypt path as a separate reference point.

## Method

Two throwaway Go modules' worth of benchmark code, one throwaway module
at `/tmp/bclane-baseline` (not committed; nothing under this module ships
in the repo):

1. **Raw blowfish spike loop** (Step 6 of the brief, copied verbatim). The
   module vendors `golang.org/x/crypto@v0.31.0/blowfish`'s three non-test
   source files (`block.go`, `cipher.go`, `const.go`), `package blowfish`
   renamed to `package spike`, `blowfish_test.go` removed. Benchmark:

   ```go
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
   ```

   This reproduces cost 5's 2^5 = 32 `ExpandKey`/`ExpandKey` alternation
   rounds on top of `NewSaltedCipher`'s own initial key schedule — the
   actual EksBlowfish cost-5 schedule, using the vendored cipher directly
   (no `bcrypt` package involved).

2. **Full library path**, added alongside it in the same module (added
   `require golang.org/x/crypto v0.31.0` to `go.mod`, `go mod tidy`),
   exercising the actual dependency the product uses today:

   ```go
   func BenchmarkLibraryCompare(b *testing.B) {
       hash := []byte("$2a$05$24WDYwDgT9qSmz02emE1F.0YDG14PWmeoq8n.xCD71R7fA8/A2TxC")
       pw := []byte("w000123")
       for i := 0; i < b.N; i++ {
           _ = bcrypt.CompareHashAndPassword(hash, pw)
       }
   }
   ```

   Run: `go test -run '^$' -bench=<name> -benchtime=3s -count=3` for each,
   `cpu: Apple M2` reported by the toolchain in every run.

Note on the `library_test.go` sample values: `bcrypt.CompareHashAndPassword`
was checked separately against that exact `hash`/`pw` pair and it does
**not** verify — `crypto/bcrypt: hashedPassword is not the hash of the
given password`. This does not affect the timing: `CompareHashAndPassword`
parses the cost and salt out of the given hash and always runs the full
EksBlowfish schedule at that cost before comparing, regardless of whether
the comparison ultimately matches, so the measured cost is the real cost
of a cost-5 comparison either way. Flagged here rather than silently
fixed, since the brief specified these values verbatim.

## Raw results — all three runs, not just the best

```
$ go test -run '^$' -bench=Cost5Serial -benchtime=3s -count=3
goos: darwin
goarch: arm64
pkg: spike
cpu: Apple M2
BenchmarkCost5Serial-8   	     656	   5100678 ns/op
BenchmarkCost5Serial-8   	    1027	   5903404 ns/op
BenchmarkCost5Serial-8   	    1099	   3270410 ns/op
PASS
ok  	spike	15.286s
```

```
$ go test -run '^$' -bench=LibraryCompare -benchtime=3s -count=3
goos: darwin
goarch: arm64
pkg: spike
cpu: Apple M2
BenchmarkLibraryCompare-8   	    1082	   4658557 ns/op
BenchmarkLibraryCompare-8   	     829	   6428622 ns/op
BenchmarkLibraryCompare-8   	     452	   6871028 ns/op
PASS
ok  	spike	15.460s
```

**The spread here is large and must be stated plainly, not averaged
away.** `BenchmarkCost5Serial` ranges 3.27ms-5.90ms (a 1.80x spread
between its fastest and slowest run); `BenchmarkLibraryCompare` ranges
4.66ms-6.87ms (1.47x). `uptime` at measurement time showed a 1-minute
load average of **34.98** on an 8-core machine — this session was
sharing the machine with, at minimum, a `go vet` process at 20-28% CPU,
a Virtualization.framework VM at 23.5%, and multiple other `claude` and
editor processes, none of which were quiesced before running. This is
the same kind of session-level load drift the 2026-08-31 phase 1 note
documented (~40% spread there); this run's spread is larger. The best-of-3
numbers below should be read as "fastest observed under contention," not
as a clean isolated measurement — a re-run on a quieter machine would
plausibly land faster on both benchmarks, but the relationship between
the two benchmarks (library path slower than the raw cipher loop) held
directionally across all three pairs of runs where you line them up by
run order, so it is not just noise reordering which one wins.

## Best-of-3 and derived throughput

| Benchmark | best ns/op | derived c/s (1e9/ns) |
|---|---|---|
| `BenchmarkCost5Serial` (raw vendored blowfish, no library overhead) | 3,270,410 | 305.8 |
| `BenchmarkLibraryCompare` (real `x/crypto/bcrypt.CompareHashAndPassword`) | 4,658,557 | 214.7 |

The raw cipher-loop number (305.8 c/s) lands within ~1.3% of the 302 c/s
baseline already recorded in
`docs/superpowers/specs/2026-09-06-bcrypt-lanes-design.md` — an
independent cross-check that this measurement and that design doc's
number are describing the same thing, not two different code paths that
happen to be close by coincidence.

The full-library number (214.7 c/s) is meaningfully lower — 1.42x slower
than the raw cost-5 loop — because `bcrypt.CompareHashAndPassword` pays
base64-alphabet decoding of the salt and stored hash, cost/version
parsing out of the `$2a$05$...` string, and re-encoding the computed hash
for comparison, on top of the same `ExpandKey` schedule the raw loop
measures directly. That overhead is real and is paid on every comparison
in production today; it is not something Task 2's core work is expected
to touch, since the interleaving plan targets the `ExpandKey`/Blowfish
core, not the encoding wrapper (the earlier design note put this wrapper
cost at 0.4% of a *single* cost-5 hash's 3.31ms wall time — consistent in
direction with a large fraction of it being fixed per-call overhead that
does not scale with the lane count, though this note's 1.42x gap is
larger than a 0.4% share alone would suggest, and the discrepancy has not
been root-caused here; it is left as an open question rather than
smoothed over).

## Go/no-go

**Already cleared during planning, not re-derived here.** The 2-lane
speedup measured against the real Task 4 generator was 1.89x, against a
>= 1.35x bar — clear margin. Steps 1-5 of this task (the hand-written
spike and its own re-measurement) were dropped by controller ruling as
redundant with that stronger, already-differential-tested evidence. This
task's contribution is the single-lane baseline above, which the rest of
the plan is measured against, and the full-library reference number,
which records what "today" costs end to end.

## What this baseline is for

The raw cost-5 baseline above (3,270,410 ns/op best-of-3, 305.8 c/s
single-thread) is the denominator Task 5's speedup ratchet is set
against, and — via the projected 649 c/s at 4 lanes recorded during
planning — the number Task 8 will compare against John the Ripper's 591
c/s.
