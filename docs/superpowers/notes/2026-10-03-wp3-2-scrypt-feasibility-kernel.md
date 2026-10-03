# WP3.2 (GPU scrypt feasibility) — kernel written and algorithm-verified, NOT benchmarked

## What this is, and what it explicitly is not

An experimental, minimalist OpenCL kernel for scrypt(N, r=1, p=1), at
`internal/gpubackend/opencl_scrypt_experimental.cl`. Not wired into
`opencl.go`/`opencl_host.c`/the production dispatch — standalone, unreferenced
by any Go code, purely a feasibility artifact.

**It has not been compiled or run.** Not on NVIDIA/AMD (no such hardware was
reachable this session — see the WP3.1 note for the confirmed absence of
self-hosted or GPU-tier CI runners), and not even on this machine's own
(deprecated but real) Apple OpenCL implementation, because **this machine's
CGO toolchain is broken independently of OpenCL**: a trivial `#include
<stdio.h>` CGO program fails to link with the same `tapi error: malformed
file` / "unknown architecture" errors from `/Library/Developer/
CommandLineTools/SDKs/MacOSX27.0.sdk`'s `.tbd` stubs. Confirmed general, not
OpenCL-specific, before writing anything — see WP3.1's note for the exact
repro. No performance number exists, was estimated, or is implied anywhere
in this note or the kernel file's comments.

## What was actually verified, and how

Every piece of non-OpenCL-specific logic the kernel needs was written first
in plain Go (no CGO, compiles and runs natively on this machine) and checked
against trusted references before being translated:

1. **Salsa20/8 core + BlockMix(r=1) + ROMix/smix** — checked against the
   real RFC 7914 §12 published test vector (`scrypt(P="", S="", N=16, r=1,
   p=1, dkLen=64)`, byte-for-byte match), then cross-checked against
   `golang.org/x/crypto/scrypt` itself (configured for r=1) across 5 varied
   password/salt/N cases, **including N=16384 — the exact parameter Cisco
   $9$ uses**, the same format this project's earlier CPU-side scrypt-AVX2
   spike measured. All 5 matched exactly.
2. **A Davies-Meyer, multi-block, continuation-capable SHA-256 compressor**
   (needed because HMAC must chain across however many blocks a message
   needs, unlike `opencl_kernels.cl`'s own `sha256_compress`, which always
   starts from the fixed IV because every existing caller there hashes
   exactly one block) — checked against `crypto/hmac` + stdlib `sha256`
   across 4 cases, including a deliberately 4-SHA-256-block HMAC message
   (64+132 bytes) — the exact worst-case shape this kernel's own B_final
   step produces. All matched.
3. **PBKDF2-HMAC-SHA256 with exactly 1 iteration**, multi-block output —
   checked against `golang.org/x/crypto/pbkdf2` at dkLen 32/64/128. All
   matched.

Only once every piece above was independently proven correct was it
transcribed into OpenCL C, as close to 1:1 as the language difference
allows (same variable roles, same macro-based unrolling style this
project's existing kernels already use). **This proves the algorithm is
right. It does not prove the OpenCL C transcription compiles or executes
identically on any real compiler** — that step needs a real OpenCL
compiler, which was not reachable.

**The reference test earned its keep immediately, not hypothetically.**
The committed test (`internal/gpubackend/scrypt_r1_reference_test.go`) is
kept permanently rather than thrown away after one interactive check
specifically because of what happened while writing it the first time:
a "cleaned up" rewrite of the scratch verification script conflated two
genuinely independent endianness conventions — PBKDF2-HMAC-SHA256's
output is a byte string in SHA-256's own big-endian word order (not a
choice, just how SHA-256 works), and RFC 7914 §3 separately requires that
byte string be reinterpreted as scrypt's internal 32-bit words using
LITTLE-ENDIAN octet-to-integer conversion for every Salsa20/BlockMix step
— a completely different, scrypt-specific convention. The rewrite skipped
the byte-string round trip for both B_init and B_final, copying words
directly across the boundary. The committed test caught this immediately
(every case failed against both the RFC vector and `x/crypto/scrypt`,
while the already-separately-verified HMAC and PBKDF2 pieces kept
passing, which is what pointed at the B-array conversion specifically as
the fault line). Both the test and the kernel were fixed the same way:
serialize to bytes in the producing step's own convention, then
reinterpret those bytes in the consuming step's convention — never copy
words directly across an endianness boundary. This is exactly the kind of
subtle, silent-wrong-answer bug that a GPU debugging session would have
burned real time on, discovered instead for free by writing the
verification first.

## Design choices, and why

- **r fixed at 1, not generalized.** Deliberate, not a shortcut born of
  laziness: r=1 is scrypt's simplest real case, has a published RFC test
  vector to verify against, and matches the one real-world format (Cisco
  `$9$`) this project's CPU-side investigation already measured — so any
  future GPU-vs-CPU comparison has a real, already-measured CPU baseline to
  compare against on the same format.
- **Candidates supplied as plaintext from the host, not generated in-kernel
  from a mask/charset.** The production kernels already solve in-kernel
  candidate generation correctly; reusing that machinery here would add
  complexity orthogonal to the one question this kernel exists to answer
  (does GPU memory bandwidth help scrypt's smix scale), and risks
  obscuring a real measurement behind an unrelated bug.
- **V (the large per-candidate scratch array) lives in `__global` memory,
  not `__private`.** This was never a candidate for the "no runtime-indexed
  private array" rule the other kernels follow — V's whole purpose is
  large, unpredictable random access (N*128 bytes per thread, far larger
  than any private/local memory budget at realistic N), so `__global` is
  both the only feasible choice and the algorithmically correct one.
- **The small, fixed-size working arrays (`B[32]`, Salsa20's 16 words, the
  SHA-256 schedule window) are fully unrolled**, matching this project's
  own house style for `__private` arrays, even in places a real compiler
  would likely unroll a small constant-trip-count loop anyway — kept
  explicit because no compiler was available this session to confirm
  either way, and this project's own history (the Metal/OpenCL defect
  audit) found real bugs from assuming unrolling would happen.
- **`j = B[16] & (N-1)` instead of a 64-bit modulo.** Correct because scrypt
  requires N to be a power of 2 (RFC 7914 §6) — same reasoning the existing
  `MIX_DIGIT` macro already applies to avoid 64-bit division, which this
  project's own kernel comments call out as software-emulated and
  expensive on every current GPU vendor.

## Known open question only real hardware can answer

Each thread's private memory footprint here (`pw[55]`, `saltBuf[59]`,
`B[32]` words, `bFinalBytes[132]`, the HMAC scratch buffers, `V`'s *pointer*
though not its backing storage) is far larger than the fast-hash kernels'
handful of words. On real GPU architectures, per-thread private/register
budget directly caps how many threads can be resident per compute unit —
this kernel may simply not achieve enough occupancy to test the memory-
bandwidth hypothesis it exists to test. That is exactly the kind of
occupancy question this note cannot answer from source reading alone, and
is the first thing to measure once real hardware is reachable, before
drawing any conclusion about scrypt's GPU viability either way.

## Disposition

Task 2's "measure performance against the CPU baseline, then decide" step
could not run — no measurement exists, so no viable/non-viable call is made
here. What exists instead: a real kernel, its non-OpenCL-specific logic
independently proven correct against three different trusted references,
and the one occupancy question that needs real hardware before the actual
feasibility question (does GPU memory bandwidth help) can even be asked.
