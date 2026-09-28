# PBKDF2 AVX2 multi-buffer core — design

Date: 2026-09-24. Goal: push slow-hash CPU cracking, following the same lane
technique that got descrypt 2.3x and bcrypt its own dedicated core — but
scoped honestly to the one hardware class where that technique actually pays
off for PBKDF2-HMAC, after two spikes ruled out the two easier options.

## 1. The measurements this exists to move — and the two that killed easier options

This design exists because two cheaper approaches were tried first and both
failed on evidence, not guesswork.

**Per-candidate overhead: nothing to remove.** Go's stdlib PBKDF2
(`crypto/internal/fips140/hmac`) already precomputes the HMAC inner/outer
state after the padded key is absorbed once, and restores it on every
`Reset`/`Sum` via `MarshalBinary`/`UnmarshalBinary` rather than rehashing the
key. Every iteration already costs the theoretical minimum: two hash
compressions (one inner-finalize, one outer-finalize). There is no
unoptimized baseline to beat here, unlike the redundant-string-allocation
gaps this session's earlier NTLM and descrypt fixes found.

**Interleaving multiple independent chains: does not work for SHA-256, on
this machine.** descrypt and bcrypt win from lane interleaving because DES
and Blowfish's round functions do data-dependent table lookups, which stall
on load latency round-to-round — independent lanes hide that stall. SHA-256's
round function is pure ALU/bitwise work, with no such stall to hide. Measured
directly (Apple M2, throwaway spike, not kept): a hand-written Go
compression loop with the round loop as the outer loop (chains interleaved)
topped out around 3-4 million compressions/second across chain widths 2/4/8.
Go's stdlib `crypto/sha256`, calling the real hardware-accelerated
implementation sequentially, hit **11-12 million compressions/second on a
quiet run** — 3-4x faster than the best interleaved number, not slower.
Building a custom interleaved SHA-256 core on this class of hardware would be
a straightforward regression.

**Why hardware wins here and didn't for DES/Blowfish.** Dedicated hash
acceleration instructions (Intel SHA Extensions, the ARMv8 Crypto Extensions
this M2 already has) exist specifically because they beat generic vector
SIMD approaches to the same hash function — that is the reason they were
designed. Neither DES nor Blowfish has an equivalent hardware fast path on
mainstream CPUs, which is exactly the gap descrypt-lanes and bcrypt-lanes
exploited. SHA-1/256/512 do have one, on any CPU built in roughly the last
decade.

**The one place a real gap remains: x86-64 without SHA Extensions.** Go's
stdlib SHA-1/256/512 fall back to a generic, non-accelerated path when the
CPU lacks SHA-NI (still common on older or budget x86-64 hardware; SHA-NI
became mainstream roughly 2019 onward, and Hashsmith cannot assume every
user's machine has it). On exactly that hardware class, an 8-way (SHA-1/256)
or 4-way (SHA-512) AVX2 multi-buffer core is a well-established technique —
the same category of win OpenSSL's and Intel ISA-L's multi-buffer SHA
implementations exist for. This design targets that class specifically, and
nothing else.

## 2. Target

**Beat `crypto/sha1`/`sha256`/`sha512`'s generic (non-hardware-accelerated)
sequential path, on x86-64 without SHA-NI, for each of the three hash
variants.** Not the SHA-NI-accelerated path (nothing legitimately beats
that with software), not ARM64 (hardware SHA extensions already win there —
see §3), and not a hashcat/John parity claim, which the earlier
`benchmark --compare` fix already demonstrated is not a fair small-scale
comparison to make (see `internal/smith/benchmark_compare.go`'s
`startupUnmeasurableThreshold` and its own commit message).

The reachability argument is the same shape as bcrypt-lanes' §1/§2, adapted:
generic (table-based) SHA-256 on amd64 without SHA-NI runs at roughly the
same order of magnitude as descrypt's original scalar cost, since it too has
no hardware assist — an 8-way AVX2 multi-buffer core processing 8 independent
messages per instruction, at AVX2 throughput, is the same kind of multiple
this project's own MD5 AVX2 core already demonstrated (6x on `ubuntu-latest`
x86-64 CI per the README's own CI table) against non-accelerated Go MD5. The
actual multiple for SHA-1/256/512 must be measured during implementation,
not assumed — CI's `ubuntu-latest` runner is the concrete stand-in for "x86-64
without SHA-NI, or with it disabled for measurement," since this project's
own hardware (Apple Silicon) cannot validate any of this at all (see §7).

## 3. Scope

**In:** three new AVX2 multi-buffer compression cores (SHA-1, SHA-256,
SHA-512), each following `md5avx2_gen.py`'s generator pattern; one
`pbkdf2LaneHasher` per variant, implementing the existing `laneHasher`
interface (`internal/smith/lanes.go`); wired into `newLaneHasher`'s dispatch
for the generic `-t pbkdf2` crack type only (`crack_pbkdf2.go`'s
`algo:iter:salt:dk` record format).

**Out, deliberately:**

- **NEON/ARM64.** §1's hardware-acceleration argument applies identically to
  ARMv8 Crypto Extensions. Building a NEON multi-buffer core would be pure
  cost with no demonstrated benefit anywhere in the ARM64 install base.
- **Wiring into the 81 format-specific `crack_*.go` files** (1Password,
  Bitwarden, Dashlane, Django, and the rest) that call `pbkdf2.Key` directly.
  Each is a small, low-risk addition once this core exists and is proven —
  exactly how `newDescryptLaneHasher` was a small addition once
  `descrypt_fast.go`'s table work already existed — but is a separate,
  later pass, not this one. Doing all 81 in the same design that builds the
  core risks conflating "does the core work" with "was every call site wired
  correctly," which are different questions with different risk profiles.
- **`dkLen > hashLen`.** Requesting more derived-key bytes than one hash
  output requires multiple parallel output blocks per candidate (PBKDF2's
  `T_1 || T_2 || ...` block construction). Rare for password-derivation KDFs
  (common for key-stretching toward a cipher key, less so for the password
  hashes this project cracks). Falls back to stdlib explicitly, not silently
  mishandled.
- **MD5-based generic PBKDF2.** Already fast via the existing vector core
  (`dictVectorCore`) for the parts of its computation that touch MD5 directly;
  in any case MD5 has no widely-deployed hardware acceleration to route
  around, so the same §1 argument that justifies SHA-1/256/512 here does not
  apply to it the same way, and it is out of scope for this pass.

## 4. Architecture

### 4.1 Per-hash register budget (estimates; confirmed per generator during implementation)

| Hash | Working registers | AVX2 lanes/register | Rounds | Expected chains (N) |
|---|---|---|---|---|
| SHA-1 | 5 (a-e) | 8 (32-bit words) | 80 | ~2 (between MD5's 4-register/N=3 and SHA-256's 8-register/N=1) |
| SHA-256 | 8 (a-h) | 8 (32-bit words) | 64 | 1 |
| SHA-512 | 8 (a-h) | 4 (64-bit words — AVX2's 256-bit register holds half as many 64-bit lanes as 32-bit ones) | 80 | 1 |

This table fixes the *pattern* each generator follows — state registers,
lane width, and a starting hypothesis for chain count — not the final
numbers. `md5avx2_gen.py`'s own docstring derives MD5's 5-register/N=3 budget
live, step by step, as part of writing that generator; each of the three
generators here does the same derivation for its own round function during
implementation, and may land on a different N than the estimate above once
the round function's actual scratch-register needs (Σ0/Σ1/Ch/Maj for
SHA-256/512, the four round-dependent functions for SHA-1) are worked out
in practice.

SHA-512's halved lane width is a real, load-bearing difference from
SHA-1/256, not a rounding error: the win from an N=1, 4-lane AVX2 core is
inherently a 4x multiple over one non-accelerated scalar stream, where
SHA-1/256 get up to 8x. The target in §2 still applies — "beats generic
scalar" — but the margin will legitimately be smaller for SHA-512, and that
should not be read as a weaker implementation.

### 4.2 Message schedule expansion stays in Go

MD5's message schedule is a fixed permutation of the original 16 words —
trivial, needing no computation. SHA-1/256/512 all need a real expansion:
`w[16..N]` computed from earlier words via σ-functions (SHA-256/512) or a
single XOR-rotate (SHA-1). Doing this inside the hot per-round assembly loop
would materially complicate all three generators relative to MD5's.

Instead, the schedule is expanded once per message block on the Go side into
a plain `[N][lanes]uint32` (or `uint64` for SHA-512) array, and the assembly
core consumes it exactly as MD5's core already consumes precomputed message
words and round constants — via memory operands, the same pattern
`md5avx2_gen.py`'s docstring documents for K and M. This keeps all three new
generators structurally close to the proven one, and confines the one
genuinely new piece of logic (schedule expansion) to ordinary, easily-tested
Go rather than assembly.

### 4.3 The `pbkdf2LaneHasher` and the PBKDF2 iteration loop

Each hash variant's `Run(pw [][]byte, out []bool)` — matching the existing
`laneHasher` contract exactly, including "must not retain pw or its elements
beyond the call" — does the following per invocation:

1. **Per-lane HMAC setup**, once per `Run` call: build each lane's ipad/opad
   key blocks (a cheap, per-lane XOR — no hashing) and absorb them into
   inner/outer state via one SIMD compression each, across all lanes at
   once. This is the same "precompute once, restore per iteration" state
   stdlib already keeps (see §1), just computed for `lanes` different
   passwords simultaneously instead of Go's stdlib doing it for one.
2. **U₁ — one-time, variable length.** `salt || INT(block)` can span more
   than one block depending on salt length (the target record's salt is
   attacker-controlled-length base64, per `crack_pbkdf2.go`'s
   `algo:iter:salt:dk` format). This is deliberately *not* vectorized: at
   any realistic iteration count the hot loop below dominates by many
   orders of magnitude, so U₁ is computed via a straightforward per-lane
   scalar call into the same underlying compression primitive, sized for
   correctness over speed.
3. **The hot loop, n = 2..iter.** Every `U_n` is exactly one hash-output
   block — fixed length, no schedule surprises. Two SIMD compressions per
   lane per iteration (inner continue, outer continue), XOR-accumulated into
   each lane's running `T`, all lanes advancing together. This loop is where
   essentially all of the work lives for any realistic password-hash
   iteration count (thousands to low millions), and is the only part that
   needs to be fast.
4. **Compare.** Each lane's final `T`, truncated to the target's `dkLen`
   bytes, against the target's stored derived key — `out[i]` set
   accordingly, same shape as every other `laneHasher`.

### 4.4 Runtime gating

**Checked against the actual dependency, not assumed**: `golang.org/x/sys/cpu`
(pinned at v0.48.0 in `go.mod`) exposes `cpu.X86.HasAVX2` — real, confirmed
present in the vendored source — but its `X86` struct has **no SHA-NI field
at all** in any checked version up to and including 0.48.0. Go's own stdlib
detects SHA-NI internally via `internal/cpu.X86.HasSHA`
(`sha256block_amd64.go`: `useSHANI = cpu.X86HasAVX && cpu.X86HasSHA && ...`),
but `internal/cpu` is exactly that — internal — and not importable outside
the standard library. An earlier draft of this section assumed `x/sys/cpu`
already exposed an equivalent public field; it does not, and this was caught
by checking the vendored source rather than recalling it, which is the
reason to record the correction rather than silently fix it.

Two real options, either viable, to be decided during implementation rather
than in this spec:

1. **A small custom CPUID query.** SHA-NI support is `CPUID.(EAX=7,ECX=0):EBX`
   bit 29 — a well-defined, standard check, and a trivial addition for a
   project that already ships 12,786 lines of hand-written AVX2/NEON
   assembly (§8). Gives a static, unambiguous answer with no runtime cost.
2. **A one-time runtime comparison instead of feature detection.** Time a
   small fixed amount of work through both the new core and
   `crypto/sha1`/`sha256`/`sha512` once, at first use, and keep whichever
   wins. More robust to cases a static bit doesn't capture (SHA-NI present
   but disabled or slow under virtualization, for instance), at the cost of
   a small one-time measurement — the same shape of tradeoff the feasibility
   guard already makes (`benchVerifyPath`'s own doc: a cold call is
   "dominated by cache misses and branch mispredicts," so any such probe
   must warm up before it is trusted).

Whichever is chosen, the gate itself is unchanged: the new path engages only
on amd64, AVX2 present, hardware SHA acceleration absent (by whichever
method decides that). Every other platform and CPU combination — including
100% of ARM64 — takes the existing `pbkdf2.Key` path unchanged, exactly as
it does today.

## 5. What does not change

`verifyCandidate`'s generic dispatch stays exactly as it is for every other
PBKDF2-consuming format (the 81 `crack_*.go` files — see §3's non-goal).
Multi-hash mode, the potfile, session resume, `--keyspace`/`--skip`/`--limit`
slicing, and the feasibility guard are untouched; the feasibility probe
already times the real dispatch (per `runBruteOrMaskLayout`'s own comment on
why `verifyFn` is built before the feasibility check), so it picks up
whichever path — new core or stdlib fallback — actually runs, with no
separate wiring.

## 6. Correctness

Differential testing against `crypto/pbkdf2` (this project's own dependency,
confirmed in §1 to already be a correct, near-optimal reference) is the
backbone, at two layers:

1. **Compression core, differential and randomized.** Each of the three new
   cores tested against `crypto/sha1`/`sha256`/`sha512` directly, across a
   table of hand-picked block boundary cases plus randomized fuzzing —
   the same structure this session's own `utf16le_test.go` used
   (`utf16leReference`, a table plus 2000 randomized inputs).
2. **`pbkdf2LaneHasher`, differential against `crypto/pbkdf2`.** Varied salt
   lengths spanning the one-block/multi-block U₁ boundary from §4.3, varied
   iteration counts, and — critically — batch sizes straddling the lane
   width in both directions, the exact pattern
   `TestDescryptLaneHasherMatchesVerify` already uses ("11 candidates at 11
   batch sizes... deliberately straddling the lane width because a PARTIAL
   group is where a laned implementation goes wrong").
3. **Staleness.** One test per hash variant, matching
   `TestDescryptLaneHasherIsStateless`: a full group containing the right
   password, then a shorter batch, must not let a lane's leftover key
   schedule or running `T` from the previous call leak into the new one and
   report a false hit.
4. **Lane invariance.** Where chain count N ends up being tunable (§7),
   different N must produce identical results for the same inputs — the
   same property bcrypt-lanes' §6 establishes for its own width tuning.

## 7. Tuning and the performance gate

As with bcrypt-lanes: chain count N (where the register budget in §4.1 turns
out to allow more than one) is chosen by measurement, not the estimate in
the table — build and benchmark each candidate width, ship the winner.

**The target hardware problem is this design's central risk, not an
afterthought.** This project's only development machine is Apple Silicon,
which cannot run or validate any part of this — not the AVX2 assembly (wrong
architecture), and not even a meaningful "does this help" measurement (no
non-SHA-NI x86-64 available locally). The implementation plan must establish,
as an early task and before any generator is written in earnest, a concrete
non-SHA-NI (or SHA-NI-disabled) x86-64 measurement environment — a specific
CI runner confirmed to lack SHA-NI, a cloud instance, or an equivalent — the
same way bcrypt-lanes' Task 1 established its measurement baseline before
committing to a lane count. Writing three generators against an assumption
about hardware this project cannot observe would repeat exactly the mistake
the spikes in §1 were run to avoid.

The CI gate, once that environment exists, is a ratio against
`crypto/sha1`/`sha256`/`sha512`'s generic path in the same process on the
same machine — never an absolute c/s floor, for the same flakiness reason
bcrypt-lanes' §7 gives.

## 8. Risks and decisions taken

**The target machine class may be smaller than it once was.** SHA-NI has
been mainstream on new x86-64 hardware since roughly 2019; this design's
value is real but shrinks over time as that hardware ages out of service.
That is a reason to keep the scope narrow (§3), not a reason not to build
it — the affected hardware class is still large today, and the runtime gate
(§4.4) means the cost of being wrong about its size is zero: every other
machine is unaffected.

**Three generators, not one.** This is a materially bigger project than
bcrypt-lanes or descrypt-lanes, each of which shipped one core — and bigger
again than either in absolute terms: the existing MD5/MD4 AVX2 and NEON
cores this pattern follows already total 12,786 lines of hand-written,
generated assembly across both architectures, for two hash functions. Three
more generators, even amd64-only, is a comparable-or-larger addition. SHA-1
and SHA-256 are structurally close to each other and to the existing MD5
generator; SHA-512's halved lane width (§4.1) and 64-bit arithmetic make it
the most different of the three and the one most likely to reveal an
unforeseen register-budget or throughput problem. The implementation plan
should sequence SHA-256 first (the dominant real-world PBKDF2 variant —
WPA2, most password managers, Django), treat it as the pattern-setter the
same way MD5's AVX2 core was itself originally a spike, and let SHA-1 and
SHA-512 each confirm or revise that pattern rather than assuming all three
proceed identically.

**Scope creep toward the 81 format-specific files is the likely pull once
the core works**, exactly as bcrypt-lanes flagged crypt(3) variants as its
own likely pull. Resisted here on the same grounds: §3 records why that is a
better, smaller *second* project once this one's core is proven, not part of
proving it.
