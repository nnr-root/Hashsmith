# WP3.1 (OpenCL kernel validation on non-Apple hardware) — static audit only

## Why this is static-only, and why that's weaker than it sounds

Two independent blockers, confirmed directly rather than assumed:

1. **No real NVIDIA/AMD GPU hardware is reachable this session.** Confirmed: no
   self-hosted GitHub Actions runners registered for this repo
   (`gh api repos/nnr-root/Hashsmith/actions/runners` → `total_count: 0`), and
   GitHub's free hosted runners carry no GPU tier at all — unlike WP2's CPU
   work, there is no free-tier escape hatch here.
2. **CGO itself cannot build on this machine right now, at all.** Not an
   OpenCL-specific problem: a trivial CGO program (`#include <stdio.h>`,
   nothing else) fails the same way —
   `ld: multiple errors: tapi error: malformed file`, every Apple-framework
   `.tbd` stub under `/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk`
   reporting "unknown architecture" for the installed linker. This is a
   Command Line Tools / SDK version mismatch on this specific machine (it
   runs a very recent macOS, Darwin 27.0.0), unrelated to Hashsmith. It means
   even Apple's own OpenCL framework — deprecated, but a real, working OpenCL
   implementation the project's own earlier Metal/OpenCL passes successfully
   built and ran self-tests against — cannot be reached either. No system
   files were touched to try to fix this; reinstalling Command Line Tools is
   a real, invasive change outside this session's authorization.

So unlike the prior Metal/OpenCL passes (which built and ran a real self-test
binary — `/tmp/hs_ocl gpu` — getting genuine, if Apple-only, pass/fail
signal), this pass has **zero compile-and-run evidence of any kind**. Every
finding below comes from reading `internal/gpubackend/opencl_kernels.cl`
(518 lines) and `opencl_host.c` (154 lines) end to end, cross-checked against
the four defect patterns the task named, not from executing anything.

## The four named defect patterns, checked by inspection

1. **`__private` array indexed by a runtime value.** Checked every `m[...]`,
   `W[...]`, `H5[...]`, `H8[...]` access across all five compress functions
   and all three mask builders. Every index into a private array is a
   compile-time literal at its call site — `M[0]` through `M[15]` in the
   MD5/MD4 round macros (hardcoded per invocation), `W[(i)&15]` in SHA-1/256
   (`i` is always a literal 0-79/0-63 passed at each unrolled macro call, so
   `(i)&15` folds to a constant), `m[(p)>>2]` in the mask builders (`p` is
   always one of the literal `POS_LE(55)...POS_LE(0)` call-site arguments).
   No violation found. (`sets[...]`, `targets[...]` are `__global`, not
   `__private` — runtime-indexing those is fine and is what global memory is
   for; they were never the concern.)
2. **64-bit division.** `MIX_DIGIT` (line 321-324) only divides in `ulong`
   while `_big` is true, and flips to 32-bit arithmetic the moment the
   remaining index fits — matches the stated design exactly. No violation.
3. **Memory zeroing.** `MZERO` (line 325) is a flat, fully-unrolled
   16-word zero — no loop, no runtime-indexed write. No violation.
4. **Alignment faults.** Nothing in the kernel source does a raw pointer
   cast across types (all buffer accesses go through typed `__global`
   pointers matching their declared element type — `uchar*`, `uint*`,
   `ulong*`), so there's no obvious misalignment construction to find by
   reading. This is the weakest-confidence item of the four: alignment
   bugs are frequently *driver-specific* (a vendor's compiler assuming a
   stricter natural alignment than the spec requires) and that category is,
   by definition, not visible from source alone. Named here as unverified,
   not cleared.

**Honest limit:** "driver-specific compiler panics" cannot be checked by
reading source at all, on principle — that's exactly the category only real
hardware (or at minimum a second, independent OpenCL compiler) can surface.
Nothing here should be read as clearing that risk.

## One real bug found and fixed, by inspection, unverified

`opencl_host.c:149` (`hs_ocl_free`):

```c
for (int i = 0; i < 9; i++) if (h->kernels[i]) clReleaseKernel(h->kernels[i]);
```

`h->kernels` is declared `cl_kernel kernels[10]` (line 24) and `hs_ocl_init`
creates all 10 (`kNames[10]`, loop bound `i < 10`, line 53) — but the free
loop's bound was `9`, one short, so kernel index 9 (`md4maskmulti`, last
entry in `kNames`) was never released. A real resource leak: one OpenCL
kernel object leaked every time a context is torn down. Fixed to `i < 10`,
matching the array size declared two lines above it and the creation loop's
own bound. The fix is a one-character bound correction with an unambiguous
array-size argument behind it, but **it has not been compiled or run this
session** — CGO is broken here (see above). Flagging that plainly rather
than implying any test coverage exists for it.

## One real limitation found, not fixed (needs hardware to validate a fix)

`hs_ocl_init` (`opencl_host.c:29-35`) queries exactly one platform
(`clGetPlatformIDs(1, &plat, NULL)`, first result only) and one device on
it (GPU type, falling back to any type). On a machine with multiple OpenCL
platforms — common on real NVIDIA/AMD validation targets, e.g. a Linux
workstation exposing separate NVIDIA and Intel/Mesa platforms — this will
silently pick whichever platform the runtime happens to enumerate first,
with no way to request a specific one. `internal/gpubackend/opencl.go` has
no override for this either (grepped: no `platform`/`device`/env-var
selection anywhere in that file). This is exactly the kind of gap that
matters most for the real validation this work package is about — a
default device pick that works by luck for whichever single-GPU dev machine
built it, but is unverified on a multi-platform box — and it is NOT fixed
here, because a platform-selection change is unverifiable without a
multi-platform machine to test it against; guessing at one would be worse
than naming the gap.

## Disposition

Task 1 (compile/build validation, throughput baselines) could not be
performed this session for either named reason (no GPU hardware, broken
local CGO toolchain). What was done instead: a complete, fresh static
re-read of both kernel files against the four named defect patterns (one
new finding: cleared with caveats on three, explicitly not-clearable by
source-reading alone on the fourth), one real bug found and fixed by
inspection (kernel-release off-by-one), and one real limitation identified
and left unfixed because fixing it blind would be worse than naming it. No
throughput numbers exist, were estimated, or are implied anywhere in this
note.
