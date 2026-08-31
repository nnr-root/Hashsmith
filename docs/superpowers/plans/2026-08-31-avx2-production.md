# AVX2 Production Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the vector fast path to x86-64, so the speedup reaches the majority of Hashsmith users rather than only Apple Silicon.

**Architecture:** The fast path is currently welded to a 4-lane NEON shape — `neonChains`/`neonLanes`/`neonGroup` are compile-time constants, and the group function's *type* is `func(*transposedBatch, *[neonGroup][16]byte)`, which cannot express AVX2's 24 candidates per call. Task 1 generalises the shape to runtime data without changing NEON behaviour by one bit. Task 2 ports the proven AVX2 core from the spike. Task 3 wires it in behind runtime CPU detection. Task 4 measures on CI and reports.

**Tech Stack:** Go 1.25+, hand-generated amd64 AVX2 assembly (Plan 9 syntax) from a committed Python generator, `golang.org/x/sys/cpu` for runtime feature detection. No cgo.

**Spec:** `docs/superpowers/specs/2026-08-31-hashsmith-throughput-and-reach-design.md` §5.4 priorities 3–5 note the amd64 direction. **Read its ERRATUM box** — several original claims were disproven and the measured record lives in `docs/superpowers/notes/2026-08-31-phase1-measurements.md`.

## The measured result this plan builds on

The spike (branch `avx2-spike`, commit `49a4993`) is **already written, correctness-verified, and benchmarked on real x86**. Measured on a GitHub Actions runner (AMD EPYC 9V74), single core, best-of-5 in one invocation:

| | best | spread |
|---|---|---|
| AVX2 N=3 (24-lane) core | **93.28 MH/s/candidate** | 92.99–93.28 |
| `crypto/md5` scalar | **7.605 MH/s** | 7.596–7.605 |
| **ratio** | **12.3×** | — |

Under 0.4% variance — the CI runner is a far better measurement environment than the development Mac, which swings ~40%. That 12.3× cleared the spike's 3× GO bar decisively.

**Do not re-derive the core.** Port it.

## Global Constraints

- **No cgo.** `CGO_ENABLED=0 go build` must keep working.
- **Cross-compilation** for linux/amd64, linux/arm64, windows/amd64, darwin/arm64. Every target must BUILD and PASS the suite.
- **No format's observable result may change.**
- **NEON behaviour must be bit-identical after Task 1.** It is measured, reviewed and shipped; this plan extends the mechanism, it does not alter arm64 results.
- All work in `hashsmith/go_hashsmith/cmd/hashsmith/` (package `main`), one flat package. No subpackages. (The spike lives in `internal/avx2spike/`; it is source material, not the destination.)
- Test command: `cd hashsmith/go_hashsmith && go test ./cmd/hashsmith`
- **Benchmarks are measured on CI, not locally.** This Mac's Rosetta exposes no AVX (`AVX=false, AVX2=false, AVX512F=false`), and Docker's amd64 emulation is QEMU/TCG, which executes vector instructions lane-by-lane and is therefore *biased against* SIMD. Docker is for correctness only.

## Two hazards this plan must not reintroduce

Both were found the hard way earlier in this project, both cause **silently wrong answers** rather than failures, and both live in code Task 1 refactors:

1. **The padding-lane guard.** `runLayoutFast` bounds hit detection by the number of lanes actually filled (`i < used`), not the group size. Unused lanes hash the empty string, so a wrong bound reports a hit for a candidate never tried whenever the target is `md5("")`. Proven by mutation: with the bound widened, a 14-candidate keyspace returned `got "\x80"` at `attempts = 2`.
2. **The stale-lane invariant.** `fillFromSegment` — not `reset` — clears lanes beyond the fill, because the calling convention is "reset once, fill repeatedly". Without it, a shrinking final fill leaves the previous group's candidates in unused lanes as valid-looking blocks.

Task 1 requires re-proving **both** by mutation after the refactor, on both architectures.

---

## Task 1: Generalise the vector shape from constants to data

**Files:**
- Modify: `transposed.go`, `keyspace.go`, `md5neon_arm64.go`, `md4neon_arm64.go`, `md5neon_generic.go`, `md4neon_generic.go`
- Modify: `transposed_test.go`, `md5neon_test.go`, `md4neon_test.go`, `fastpath_test.go` (call-shape only)

**Interfaces:**
- Produces:
  - `type vecShape struct{ chains, lanes int }`, with `(vecShape) group() int` returning `chains*lanes`
  - `neonShape = vecShape{chains: 5, lanes: 4}` (group 20) — the existing constants become this
  - `transposedBatch` gains a `shape vecShape` field; `newTransposedBatch(shape vecShape) *transposedBatch`
  - `(*transposedBatch) wordIndex(i, w int) int` becomes a **method** using `tb.shape.lanes` (was a package-level func on the `neonLanes` constant)
  - `fastAlgo` gains `shape vecShape`; its `group` becomes `func(*transposedBatch, [][16]byte)` — **a slice, not a fixed array**, so the group size is no longer part of the type

**Why the signature must change:** `group func(*transposedBatch, *[neonGroup][16]byte)` hardcodes 20 outputs in the *type*. AVX2 produces 24 per call. A slice decouples size from type; the runner allocates `make([][16]byte, algo.shape.group())` once per worker, so there is no per-call allocation.

- [ ] **Step 1: Write the failing test**

Add to `transposed_test.go`:

```go
// The batch must lay out correctly for any shape, not just NEON's 5x4.
// Chain c, word w, lane l lives at c*64 + w*lanes + l.
func TestTransposedShapeLayout(t *testing.T) {
	for _, sh := range []vecShape{{chains: 5, lanes: 4}, {chains: 3, lanes: 8}, {chains: 2, lanes: 8}} {
		tb := newTransposedBatch(sh)
		if got := len(tb.words); got != sh.chains*16*sh.lanes {
			t.Fatalf("shape %+v: words len %d, want %d", sh, got, sh.chains*16*sh.lanes)
		}
		seen := map[int]bool{}
		for i := 0; i < sh.group(); i++ {
			for w := 0; w < 16; w++ {
				idx := tb.wordIndex(i, w)
				if idx < 0 || idx >= len(tb.words) {
					t.Fatalf("shape %+v: wordIndex(%d,%d) = %d out of range", sh, i, w, idx)
				}
				if seen[idx] {
					t.Fatalf("shape %+v: wordIndex(%d,%d) = %d collides", sh, i, w, idx)
				}
				seen[idx] = true
			}
		}
		if len(seen) != sh.chains*16*sh.lanes {
			t.Errorf("shape %+v: covered %d slots, want %d", sh, len(seen), sh.chains*16*sh.lanes)
		}
	}
}

// An 8-lane shape must produce the same MD5 blocks a 4-lane shape does for
// the same candidates — the shape changes the interleave, never the message.
func TestTransposedShapeAgnosticBlocks(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de"), []byte("fg")}
	read := func(sh vecShape) []string {
		tb := newTransposedBatch(sh)
		if err := tb.reset(len(sets), encRaw); err != nil {
			t.Fatal(err)
		}
		n := tb.fillFromSegment(sets, 0)
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			var blk [64]byte
			for w := 0; w < 16; w++ {
				binary.LittleEndian.PutUint32(blk[w*4:], tb.words[tb.wordIndex(i, w)])
			}
			out = append(out, string(blk[:]))
		}
		return out
	}
	four := read(vecShape{chains: 5, lanes: 4})
	eight := read(vecShape{chains: 3, lanes: 8})
	n := len(four)
	if len(eight) < n {
		n = len(eight)
	}
	if n == 0 {
		t.Fatal("no candidates produced")
	}
	for i := 0; i < n; i++ {
		if four[i] != eight[i] {
			t.Errorf("candidate %d: 4-lane and 8-lane blocks differ", i)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd hashsmith/go_hashsmith && go test -run TestTransposedShape ./cmd/hashsmith`
Expected: compile failure — `vecShape` undefined, `newTransposedBatch` takes no argument. That is the signature change landing.

- [ ] **Step 3: Implement**

Thread `vecShape` through. `neonChains`/`neonLanes`/`neonGroup` become `neonShape`; keep them as derived constants only if that genuinely aids readability, otherwise remove them so nothing silently keeps the old assumption. Convert `wordIndex` to a method. Change `fastAlgo.group` to take `[][16]byte` and add `shape`. In `runLayoutFast`, allocate the output slice once per worker from `algo.shape.group()`, and derive `fastCtxCheckEvery` from the shape rather than the constant.

**Do not restructure `runLayoutFast` beyond this.** Its chunk allocator, watermark, attempt accounting, cancellation, segment-boundary resets and the `i < used` hit-detection bound are adversarially reviewed. Change only what the shape parameterisation requires.

- [ ] **Step 4: Verify NEON is bit-identical**

```bash
cd hashsmith/go_hashsmith
go test -count=1 -timeout 300s ./cmd/hashsmith
GOARCH=amd64 GOOS=darwin go test -count=1 -timeout 300s ./cmd/hashsmith
go test -race -count=1 -timeout 900s -run 'TestFastPath|TestTransposed|TestMD5|TestMD4' ./cmd/hashsmith
go vet ./cmd/hashsmith
go build -o /tmp/hs ./cmd/hashsmith
for a in md5 md4 ntlm; do h=$(/tmp/hs hash -t $a cafe -N 2>/dev/null|tail -1); /tmp/hs crack -t $a -M brute -C abcdefghijklmnopqrstuvwxyz -n 1 -x 4 "$h" -N --no-pot 2>&1 | grep -oE 'Found: .*|Not found'; done
```
Expected: suite green on both builds, race clean, and all three algorithms still find `cafe`.

- [ ] **Step 5: Re-prove BOTH hazard guards by mutation**

This is the step that matters most in this task. Report the output you see for each.

(a) **Padding-lane guard**: change the hit-detection bound in `runLayoutFast` from `i < used` to the full group size. Run `go test -run TestFastPath ./cmd/hashsmith` on native arm64 AND `GOARCH=amd64 GOOS=darwin`. **Both must FAIL.** Restore; confirm `git diff` empty and both pass.

(b) **Stale-lane invariant**: remove the leftover-lane cleaning loop at the end of `fillFromSegment`. Run `go test -run TestTransposed ./cmd/hashsmith`. **`TestTransposedReuseClearsStaleLanes` must FAIL.** Restore; confirm clean.

If either mutation does NOT produce a failure, stop and report — the refactor has silently voided a guard against wrong answers.

- [ ] **Step 6: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/
git commit -m "refactor: make the vector fast path shape-parameterised

neonChains/neonLanes/neonGroup were compile-time constants, and the group
function's type hardcoded 20 outputs, which cannot express AVX2's 24
candidates per call. Shape becomes runtime data on transposedBatch and
fastAlgo, and the group function takes a slice so its size is no longer
part of its type.

NEON behaviour is unchanged: same blocks, same digests, same results.
Both silent-wrong-answer guards re-proven by mutation after the refactor
— the padding-lane hit-detection bound and fillFromSegment's stale-lane
cleaning."
```

---

## Task 2: Port the AVX2 MD5 core

**Files:**
- Create: `md5avx2_gen.py`, `md5avx2_amd64.s`, `md5avx2_amd64.go`, `md5avx2_generic.go`, `md5avx2_test.go` — all in `cmd/hashsmith/`
- Source material: `internal/avx2spike/` on branch `avx2-spike` (commit `49a4993`)

**Interfaces:**
- Produces: `md5GroupAVX2(tb *transposedBatch, out [][16]byte)`, `avx2Shape = vecShape{chains: 3, lanes: 8}` (group 24), `hasAVX2() bool`

- [ ] **Step 1: Bring the spike across**

`git show avx2-spike:hashsmith/go_hashsmith/internal/avx2spike/<file>` for each. Adapt to `package main` and to `transposedBatch`'s layout (chain c's block at `&tb.words[c*64]`, exactly as the NEON wrappers do — the spike used its own equivalent layout, so this should be wiring, not rework).

Keep the generator committed and have the `.s` header name it, matching `md5neon_gen.py`/`md4neon_gen.py`. Verify the generator reproduces the committed `.s` byte-for-byte (snapshot, regenerate, diff, restore — the naive `> file` redirect does not work for these generators, they write to a hardcoded path).

- [ ] **Step 2: Runtime detection**

`hasAVX2()` uses `golang.org/x/sys/cpu`'s `cpu.X86.HasAVX2`. **`golang.org/x/sys` is currently an indirect dependency (`go.mod:30`) — promote it to direct** with `go get golang.org/x/sys` and confirm `go mod tidy` keeps it. Guard the file `//go:build amd64`; `md5avx2_generic.go` (`//go:build !amd64`) returns false and provides a scalar `md5GroupAVX2` so nothing references a missing symbol.

- [ ] **Step 3: Correctness tests, runnable under Docker**

Mirror `md5neon_test.go`: bit-exact against `crypto/md5` for every length 0..55 across all 24 lanes in both encoding modes, plus cross-chain lane independence. Run them on real AVX2 semantics via emulation:

```bash
cd hashsmith/go_hashsmith
GOOS=linux GOARCH=amd64 go test -c -o /tmp/hs.test ./cmd/hashsmith/
docker run --rm --platform linux/amd64 -v /tmp/hs.test:/t:ro alpine:3 /t -test.run 'TestMD5AVX2|TestTransposed|TestFastPath' -test.v 2>&1 | tail -30
```

**Correctness only — never benchmark under Docker.** TCG emulates vector ops lane-by-lane and is biased against SIMD.

- [ ] **Step 4: Verify**

```bash
cd hashsmith/go_hashsmith
go test -count=1 -timeout 300s ./cmd/hashsmith          # arm64: AVX2 path is the !amd64 stub
go vet ./cmd/hashsmith
GOOS=linux GOARCH=amd64 go vet ./cmd/hashsmith          # asmdecl checks the AVX2 declarations
for t in linux/amd64 linux/arm64 windows/amd64 darwin/arm64; do GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go build -o /dev/null ./cmd/hashsmith; done
```

- [ ] **Step 5: Commit**

```bash
git add hashsmith/go_hashsmith/
git commit -m "feat: pipelined 24-way AVX2 MD5 core

Three chains of 8 lanes, ported from the avx2-spike branch where it
measured 93.28 MH/s/candidate against crypto/md5's 7.605 on a GitHub
x86 runner — 12.3x, best-of-5, under 0.4% spread.

Fits 16 YMM registers by streaming K, the message word and the I-round
constant from memory rather than holding them in registers, and by using
a bit-select XOR identity for F/G (one scratch register instead of two).
Verified bit-exact against crypto/md5 at every length on all 24 lanes."
```

---

## Task 3: Select the backend at runtime

**Files:** Modify `keyspace.go` (`fastAlgoFor`, `fastPathEligible`), `fastpath_test.go`

**Interfaces:**
- Produces: `vectorBackendName() string` — `"neon"`, `"avx2"` or `""` — replacing `md5GroupAccelerated()` as the gate

- [ ] **Step 1: Write the failing test**

```go
// Exactly one backend may be active, and eligibility must agree with it.
func TestVectorBackendSelection(t *testing.T) {
	b := vectorBackendName()
	switch b {
	case "neon", "avx2", "":
	default:
		t.Fatalf("unexpected backend %q", b)
	}
	l := bruteLayout("abc", 3, 3)
	algo, ok := fastPathEligible("md5", "", l)
	if b == "" && ok {
		t.Error("no backend, yet md5 was eligible")
	}
	if b != "" {
		if !ok {
			t.Fatal("a backend is active, yet md5 was not eligible")
		}
		if algo.shape.group() != algo.shape.chains*algo.shape.lanes {
			t.Errorf("shape %+v inconsistent", algo.shape)
		}
		switch b {
		case "neon":
			if algo.shape.lanes != 4 {
				t.Errorf("neon backend with %d lanes", algo.shape.lanes)
			}
		case "avx2":
			if algo.shape.lanes != 8 {
				t.Errorf("avx2 backend with %d lanes", algo.shape.lanes)
			}
		}
	}
}
```

- [ ] **Step 2: Implement**

`fastAlgoFor` returns the descriptor for the active backend: on arm64 the NEON group functions with `neonShape`; on amd64 with `hasAVX2()` the AVX2 group function with `avx2Shape`; otherwise no backend. **MD4/NTLM have no AVX2 core yet — on amd64 they must return not-eligible and keep the scalar path.** Do not silently route them to the MD5 core.

Keep every existing eligibility condition: salt, `gen` override, per-segment length ceiling under the algorithm's encoding mode, and the NTLM ASCII guard.

- [ ] **Step 3: Verify, including under Docker**

```bash
cd hashsmith/go_hashsmith
go test -count=1 -timeout 300s ./cmd/hashsmith
go test -race -count=1 -timeout 900s -run 'TestFastPath|TestVectorBackend' ./cmd/hashsmith
GOOS=linux GOARCH=amd64 go test -c -o /tmp/hs.test ./cmd/hashsmith/
docker run --rm --platform linux/amd64 -v /tmp/hs.test:/t:ro alpine:3 /t -test.run 'Test' 2>&1 | tail -15
```
The Docker run is the first time the AVX2 path is exercised end to end through eligibility — expect it to be slow under emulation, and do not read timings from it.

- [ ] **Step 4: Commit**

```bash
git add hashsmith/go_hashsmith/cmd/hashsmith/
git commit -m "feat: select the vector backend at runtime (NEON or AVX2)

md5GroupAccelerated becomes vectorBackendName: NEON on arm64, AVX2 on
amd64 where the CPU supports it, scalar otherwise. MD4 and NTLM have no
AVX2 core yet and correctly stay scalar on amd64 rather than being
routed to the MD5 group function."
```

---

## Task 4: Measure on CI and report

- [ ] **Step 1: Add a benchmark job**

Extend `.github/workflows/ci.yml` with a job that runs the kernel benchmarks on `ubuntu-latest` (x86, AVX2 — the spike run confirmed `avx avx2 avx512` and an AMD EPYC 9V74) and on `ubuntu-24.04-arm`, printing results plainly. Best-of-5, `-benchtime 2s -count 5`, `-cpu 1`, all in one invocation per arch so the ratio is same-run.

- [ ] **Step 2: Push and read**

Push the branch, let CI run, and read the numbers from the job log. **Do not report a locally-measured x86 figure — there is no way to produce a valid one on this machine.**

- [ ] **Step 3: Report**

Append to `docs/superpowers/notes/2026-08-31-phase1-measurements.md`: the AVX2 kernel numbers from CI with methodology, the arm64 numbers confirming NEON did not regress, and **a precise statement of coverage** — after this plan the fast path is unsalted fixed-length MD5 on **both** arm64 (NEON, 20-way) and amd64-with-AVX2 (24-way), plus MD4/NTLM on arm64 only; and still not the other ~460 formats, salted targets, dictionary attacks, session resumes, or Markov/hybrid/combinator.

Record the open follow-ups: an AVX2 MD4 core (NTLM on x86 is the obvious next prize, and CI runners expose AVX-512 so a 16-lane ZMM core is now measurable too), and that end-to-end x86 throughput is unmeasured — only the kernel is.

- [ ] **Step 4: Commit and stop.** Hard checkpoint.

---

## Self-Review Notes

**Spec coverage:** §5.4's amd64 direction → Tasks 2–3. §5.5's correctness strategy → Task 2 Step 3 (differential across every length and lane on both builds) and Task 1 Step 5 (both guards re-proven by mutation).

**Deliberate scope limits:**
- MD4/NTLM get no AVX2 core here. Task 3 must make them fall back rather than misroute.
- AVX-512 is out of scope, but Task 4 records that CI runners expose it, making a 16-lane core measurable later.
- End-to-end x86 throughput is not measured; only the kernel. Stated rather than implied.

**Type consistency:** `vecShape` (with `chains`, `lanes`, `group()`), `neonShape`, `avx2Shape`, `newTransposedBatch(vecShape)`, `(*transposedBatch).wordIndex`, `fastAlgo{name, enc, shape, group}` with `group func(*transposedBatch, [][16]byte)`, `md5GroupAVX2`, `hasAVX2`, `vectorBackendName` — each defined once, used consistently. `md5GroupAccelerated` and the package-level `wordIndex` function are removed by Tasks 1 and 3 and must not survive.
