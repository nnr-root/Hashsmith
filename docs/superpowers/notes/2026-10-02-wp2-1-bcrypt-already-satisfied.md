# WP2.1 (bcrypt multi-lane CPU core) — already satisfied, closed without new code

## What was asked

The pasted "Work Package 2" roadmap's Task 1 asked for: "Adapt the multi-lane
SIMD / register packing pattern used in `descrypt` to `bcrypt`. Implement the
vectorized core in Go/Assembly/Cgo... Benchmark against standard Go
stdlib/x/crypto bcrypt and record throughput deltas."

## What's actually in the repo (checked before writing any code)

`internal/bcryptlane` already is that work — built, tuned, differentially
tested, and wired into real cracking paths (`internal/smith/crack_bcrypt_signext.go`,
`internal/smith/crack_wbb4.go`, `internal/smith/lanes.go`). Git history:
`5871c70` (vendor Blowfish) through `5982301` (fourteen formats), with two
dedicated investigation notes already on record:
`docs/superpowers/notes/2026-09-06-bcrypt-bottleneck.md` and
`docs/superpowers/notes/2026-09-06-bcrypt-lane-tuning.md`.

**The technique is software-pipelined interleaving (2/4/8 independent Blowfish
states advanced in lockstep), not AVX2 SIMD lanes** — and that choice is
deliberate, not an oversight. bcrypt's EksBlowfish key schedule does a
data-dependent S-box lookup every round (4 S-boxes × 256 32-bit entries,
indexed by a byte that depends on the previous round's output). That is a
gather-style access pattern, not an arithmetic one — the same shape of problem
that made this project's own scrypt-AVX2 spike
(`docs/superpowers/plans/...` / the `hashsmith-phase2-reach-markov` session
notes) come back with a clean negative result. Interleaving independent
states hides memory/round latency via instruction-level parallelism instead
of trying to pack four S-box lookups into one SIMD gather, which modern
AVX2 gather instructions handle no better than four scalar loads when the
indices are unrelated per lane.

## Fresh measurements, this session (2026-10-02, same Apple M2 dev machine)

Re-ran the existing ratchet and width benchmarks rather than trusting old
numbers:

```
$ go test ./internal/bcryptlane/... -run TestSpeedupOverXCrypto -v
x/crypto 3278547 ns/op (best of 5), bcryptlane 1535032 ns/candidate (best of 5)
at 4 lanes, speedup 2.14x
```

```
$ go test ./internal/bcryptlane/... -bench=BenchmarkWidth -benchtime=3x -run='^$'
BenchmarkWidth1-8   3266556 ns/candidate   (serial, 1.00x)
BenchmarkWidth2-8   1791021 ns/candidate   (1.82x)
BenchmarkWidth4-8   1539184 ns/candidate   (2.12x)  <- current production choice
BenchmarkWidth8-8   1645052 ns/candidate   (1.99x)
```

Lanes=4 is still the right choice on this machine — confirms the existing
tuning, no regression, nothing to retune. The project's committed ratchet
floors (1.39x portable / 1.92x calibrated-machine) are comfortably cleared
(2.14x measured here, same as the floor's own calibration machine).

## Disposition

**WP2.1 is satisfied by existing work.** No new code was written. If a
literal AVX2 bcrypt core is wanted later as a research spike (not a
commitment), the right next step is the same discipline the scrypt spike
used: a throwaway, byte-correct prototype measuring ONE representative
lane-width before building anything production-shaped — not assumed from
this note's S-box reasoning alone, even though that reasoning is the same
shape as a result this project has already proven out once.
