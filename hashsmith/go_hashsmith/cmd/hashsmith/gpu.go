package main

// GPU acceleration seam.
//
// Cracking throughput on the GPU is the one lever left for out-pacing CPU-only
// tools, but it is a categorical change: it requires cgo + a platform GPU API
// (Metal on Apple Silicon, OpenCL/Vulkan elsewhere) and hand-written kernels per
// hash type. To keep the shipped binary pure-Go, statically linked, and
// cross-platform by default, all of that lives behind the `gpu` build tag.
//
//   go build              → pure Go, no GPU, no cgo (the default everyone gets)
//   go build -tags gpu    → compiles the Metal backend (gpu_metal.go), cgo on
//
// The default build links gpu_stub.go, whose newGPUBackend reports why GPU is
// unavailable. This file is the always-present interface and CPU-side wiring, so
// the backend can be filled in without touching the attack engine.

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// gpuBackend accelerates raw-digest hashing on the GPU. A batch of candidates is
// hashed in one dispatch; the CPU then checks the digests against the target set
// (the same map used by multi-hash mode). Implementations must be safe to Close.
type gpuBackend interface {
	// name identifies the backend and device (e.g. "Metal (Apple M2)").
	name() string
	// md5 writes the 16-byte MD5 digest of each candidate into out[i].
	// len(out) must equal len(candidates). It is the first kernel; further
	// digests (sha1/sha256/ntlm…) extend this interface as kernels are added.
	md5(candidates []string, out [][16]byte) error
	// md5Brute searches indices [start, start+count) of the fixed-length brute
	// keyspace over charset (candidates generated in-kernel — no transfer) for
	// one whose MD5 equals target. Returns (matchedIndex, found, error).
	md5Brute(charset string, wordLen int, target [16]byte, start uint64, count uint32) (uint64, bool, error)
	// md5Mask is like md5Brute but with a per-position charset (a parsed mask):
	// candidates are generated in-kernel over the mixed-radix mask keyspace.
	md5Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	// md5MaskMulti searches for candidates matching ANY of the sorted targets in
	// one dispatch (multi-hash on the GPU). foundFlag/foundIdx accumulate across
	// dispatches.
	md5MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	// ntlmMask / ntlmMaskMulti are the NTLM (MD4 of UTF-16LE) equivalents.
	ntlmMask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	ntlmMaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	sha256Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	sha256MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	sha1Mask(sets [][]byte, target []byte, start uint64, count uint32) (uint64, bool, error)
	sha1MaskMulti(sets [][]byte, targets []uint32, start uint64, count uint32, foundFlag []uint32, foundIdx []uint64) error
	// maskSweepMulti runs a pipelined multi-target sweep (several dispatches in
	// flight) over [start, start+span).
	maskSweepMulti(algo int, sets [][]byte, targetWords int, targets []uint32, start, span uint64, chunk uint32, foundFlag []uint32, foundIdx []uint64) error
	// close releases GPU resources.
	close()
}

// bruteIndexToString decodes a keyspace index back to its candidate (mixed
// radix, last position fastest — matching the kernel's generation).
func bruteIndexToString(idx uint64, wordLen int, charset string) string {
	out := make([]byte, wordLen)
	b := uint64(len(charset))
	for p := wordLen - 1; p >= 0; p-- {
		out[p] = charset[idx%b]
		idx /= b
	}
	return string(out)
}

// detectGPU returns an initialized backend, or (nil, reason) explaining why GPU
// acceleration is not available. newGPUBackend is provided by exactly one of
// gpu_stub.go (default) or gpu_metal.go (-tags gpu).
func detectGPU() (gpuBackend, string) {
	return newGPUBackend()
}

// A process cracks then exits, so the GPU backend (which compiles the shader on
// init) is created once and reused for the whole run rather than per target.
var (
	gpuOnce    sync.Once
	gpuCached  gpuBackend
	gpuReasonC string
)

func activeGPUBackend() (gpuBackend, string) {
	gpuOnce.Do(func() { gpuCached, gpuReasonC = detectGPU() })
	return gpuCached, gpuReasonC
}

// gpuBruteHash runs a single-target GPU brute-force for md5 or ntlm, using the
// mask kernel with per-position uniform charsets (candidates generated in-kernel).
func gpuBruteHash(targetHex, typ, charset string, minLen, maxLen int, atomicAttempts *int64) (pw string, found, usedGPU bool) {
	b, _ := activeGPUBackend()
	if b == nil {
		return "", false, false
	}
	fn := gpuMaskMethod(b, typ)
	if fn == nil || maxLen > maxGPUWordLen(typ) {
		return "", false, false
	}
	target, err := hex.DecodeString(strings.TrimSpace(targetHex))
	if err != nil || len(target) != digestWords(typ)*4 {
		return "", false, false
	}
	cs := []byte(charset)
	const chunk = uint64(1) << 27
	for L := minLen; L <= maxLen; L++ {
		sets := make([][]byte, L)
		for i := range sets {
			sets[i] = cs
		}
		total := uint64(maskKeyspace(sets))
		var done uint64
		for done < total {
			cnt := chunk
			if done+cnt > total {
				cnt = total - done
			}
			idx, ok, e := fn(sets, target, done, uint32(cnt))
			if e != nil {
				return "", false, true
			}
			atomic.AddInt64(atomicAttempts, int64(cnt))
			done += cnt
			if ok {
				return maskIdxToStr(int64(idx), sets), true, true
			}
		}
	}
	return "", false, true
}

// gpuMaskMD5 runs a single-target MD5 mask attack on the GPU with in-kernel
// candidate generation, honouring increment mode. Same (pw, found, usedGPU)
// contract as gpuBruteMD5.
func gpuMaskHash(targetHex, typ string, mc *maskConfig, atomicAttempts *int64) (pw string, found, usedGPU bool) {
	if mc == nil {
		return "", false, false
	}
	b, _ := activeGPUBackend()
	if b == nil {
		return "", false, false
	}
	fn := gpuMaskMethod(b, typ)
	if fn == nil {
		return "", false, false
	}
	target, err := hex.DecodeString(strings.TrimSpace(targetHex))
	if err != nil || len(target) != digestWords(typ)*4 {
		return "", false, false
	}
	fullSets, err := parseMask(mc)
	if err != nil || len(fullSets) > maxGPUWordLen(typ) {
		return "", false, false
	}

	search := func(sets [][]byte) (string, bool) {
		total := uint64(maskKeyspace(sets))
		const chunk = uint64(1) << 27
		var done uint64
		for done < total {
			cnt := chunk
			if done+cnt > total {
				cnt = total - done
			}
			idx, ok, e := fn(sets, target, done, uint32(cnt))
			if e != nil {
				return "", false
			}
			atomic.AddInt64(atomicAttempts, int64(cnt))
			done += cnt
			if ok {
				return maskIdxToStr(int64(idx), sets), true
			}
		}
		return "", false
	}

	if !mc.increment {
		p, ok := search(fullSets)
		return p, ok, true
	}
	lo := mc.incMin
	if lo < 1 {
		lo = 1
	}
	for l := lo; l <= len(fullSets); l++ {
		if p, ok := search(fullSets[:l]); ok {
			return p, true, true
		}
	}
	return "", false, true
}

// gpuMaskMethod returns the single-target mask kernel for a hash type, or nil.
func gpuMaskMethod(b gpuBackend, typ string) func([][]byte, []byte, uint64, uint32) (uint64, bool, error) {
	switch strings.ToLower(typ) {
	case "md5":
		return b.md5Mask
	case "ntlm":
		return b.ntlmMask
	case "sha256":
		return b.sha256Mask
	case "sha1":
		return b.sha1Mask
	}
	return nil
}

// gpuMultiMethod returns the multi-target mask kernel for a hash type, or nil.
func gpuMultiMethod(b gpuBackend, typ string) func([][]byte, []uint32, uint64, uint32, []uint32, []uint64) error {
	switch strings.ToLower(typ) {
	case "md5":
		return b.md5MaskMulti
	case "ntlm":
		return b.ntlmMaskMulti
	case "sha256":
		return b.sha256MaskMulti
	case "sha1":
		return b.sha1MaskMulti
	}
	return nil
}

// digestWords is the number of 32-bit words in a hash type's digest.
func digestWords(typ string) int {
	switch strings.ToLower(typ) {
	case "sha256":
		return 8
	case "sha1":
		return 5
	}
	return 4
}

// maxGPUWordLen is the longest candidate a single-block kernel handles for a
// type (NTLM doubles length via UTF-16LE).
func maxGPUWordLen(typ string) int {
	if strings.EqualFold(typ, "ntlm") {
		return 27
	}
	return 55
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// packWord reads one digest word in the endianness the kernel compares against
// (SHA-256 state is big-endian; MD5/MD4 little-endian).
func packWord(typ string, b []byte) uint32 {
	switch strings.ToLower(typ) {
	case "sha256", "sha1":
		return be32(b)
	}
	return le32(b)
}

// gpuAlgo maps a hash type to the kernel selector used by the pipelined sweep.
func gpuAlgo(typ string) int {
	switch strings.ToLower(typ) {
	case "ntlm":
		return 1
	case "sha256":
		return 2
	case "sha1":
		return 3
	}
	return 0
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// gpuBatchMaskMD5 runs a multi-target MD5 brute/mask search on the GPU for the
// given batch entries (each entry's .norm is its md5 hex). It marks matched
// entries (.flag/.password) in place. Returns false — leaving the caller to use
// the CPU path — when the request is ineligible or no GPU is present.
func gpuBatchMaskHash(typ, mode string, mc *maskConfig, charset string, minLen, maxLen int,
	entries []*batchTarget) bool {

	b, _ := activeGPUBackend()
	if b == nil || len(entries) == 0 {
		return false
	}
	multi := gpuMultiMethod(b, typ)
	if multi == nil {
		return false
	}
	words := digestWords(typ)
	byteLen := words * 4

	// Decode every target md5 to 4 words, then sort (with a back-map to entries)
	// so the kernel can binary-search.
	type ti struct {
		w     []uint32
		entry int
	}
	ts := make([]ti, 0, len(entries))
	for i, e := range entries {
		tb, err := hex.DecodeString(strings.TrimSpace(e.norm))
		if err != nil || len(tb) != byteLen {
			return false // not all this type → let the CPU path handle it
		}
		w := make([]uint32, words)
		for j := 0; j < words; j++ {
			w[j] = packWord(typ, tb[j*4:])
		}
		ts = append(ts, ti{w, i})
	}
	sort.Slice(ts, func(i, j int) bool {
		for k := 0; k < words; k++ {
			if ts[i].w[k] != ts[j].w[k] {
				return ts[i].w[k] < ts[j].w[k]
			}
		}
		return false
	})
	nT := len(ts)
	targets := make([]uint32, nT*words)
	for k := range ts {
		copy(targets[k*words:], ts[k].w)
	}

	// Build the list of set-lists to sweep: mask (optionally per increment
	// length) or brute (uniform sets, one per length in the range).
	var sweeps [][][]byte
	if mode == "mask" {
		sets, err := parseMask(mc)
		if err != nil || len(sets) > maxGPUWordLen(typ) {
			return false
		}
		if mc.increment {
			lo := mc.incMin
			if lo < 1 {
				lo = 1
			}
			for l := lo; l <= len(sets); l++ {
				sweeps = append(sweeps, sets[:l])
			}
		} else {
			sweeps = append(sweeps, sets)
		}
	} else { // brute
		cs := []byte(charset)
		for L := minLen; L <= maxLen; L++ {
			if L > maxGPUWordLen(typ) {
				return false
			}
			seg := make([][]byte, L)
			for i := range seg {
				seg[i] = cs
			}
			sweeps = append(sweeps, seg)
		}
	}

	// All eligibility passed — set up the progress bar and time the run.
	color.New(themeAttr, color.Bold).Fprintf(os.Stderr, "\n→ Testing as %s (GPU)\n", typ)
	var total int64
	for _, sets := range sweeps {
		total += maskKeyspace(sets)
	}
	var gpuAttempts int64
	bar := newCrackBar(total)
	tickCtx, tickCancel := context.WithCancel(context.Background())
	defer tickCancel()
	go progressTicker(tickCtx, bar, &gpuAttempts)
	start := time.Now()

	foundFlag := make([]uint32, nT)
	foundIdx := make([]uint64, nT)
	collected := make([]bool, nT)
	remaining := nT
	algo := gpuAlgo(typ)
	const chunk = uint32(1) << 27       // per-dispatch batch (saturates the integrated GPU)
	const superSpan = uint64(chunk) * 4 // pipeline several dispatches, then collect
	for _, sets := range sweeps {
		total := uint64(maskKeyspace(sets))
		var done uint64
		for done < total && remaining > 0 {
			span := superSpan
			if done+span > total {
				span = total - done
			}
			if err := b.maskSweepMulti(algo, sets, words, targets, done, span, chunk, foundFlag, foundIdx); err != nil {
				return true
			}
			atomic.AddInt64(&gpuAttempts, int64(span))
			done += span
			for k := 0; k < nT; k++ {
				if !collected[k] && foundFlag[k] == 1 {
					e := entries[ts[k].entry]
					e.password = maskIdxToStr(int64(foundIdx[k]), sets)
					atomic.StoreInt32(&e.flag, 1)
					collected[k] = true
					remaining--
				}
			}
		}
		if remaining == 0 {
			break
		}
	}
	_ = multi // single-dispatch method retained for reference/fallback
	tickCancel()
	_ = bar.Finish()
	fmt.Fprintln(os.Stderr)
	elapsed := time.Since(start).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(atomic.LoadInt64(&gpuAttempts)) / elapsed
	}
	color.New(themeAttr).Fprintf(os.Stderr,
		"Attempts: %d | Elapsed: %.2fs | Rate: %s\n", atomic.LoadInt64(&gpuAttempts), elapsed, formatRate(rate))
	return true
}

// runGPUInfo powers the `gpu` command: report acceleration status and, when
// unavailable, exactly why and how to enable it.
func runGPUInfo(_ []string) error {
	b, reason := detectGPU()
	if b == nil {
		clrYellow.Fprintln(stderr(), "GPU acceleration: unavailable")
		fmt.Fprintf(stderr(), "  reason: %s\n", reason)
		fmt.Fprintln(stderr(), "  Hashsmith runs fully on the CPU; GPU support is opt-in and in progress.")
		return nil
	}
	defer b.close()
	clrGreen.Fprintf(stderr(), "GPU acceleration: available — %s\n", b.name())
	return gpuSelfTest(b)
}

// gpuSelfTest verifies the GPU MD5 kernel against the CPU across known vectors —
// GPU crypto is only trustworthy once proven bit-identical to the reference.
func gpuSelfTest(b gpuBackend) error {
	tests := []string{"", "a", "abc", "password", "hashsmith", "The quick brown fox jumps"}
	out := make([][16]byte, len(tests))
	if err := b.md5(tests, out); err != nil {
		return err
	}
	bad := 0
	for i, s := range tests {
		if out[i] != md5.Sum([]byte(s)) {
			bad++
			clrRed.Fprintf(stderr(), "  MISMATCH %q: gpu=%x cpu=%x\n", s, out[i], md5.Sum([]byte(s)))
		}
	}
	if bad == 0 {
		clrGreen.Fprintf(stderr(), "  self-test: MD5 matches CPU across %d vectors ✓\n", len(tests))
	} else {
		clrRed.Fprintf(stderr(), "  self-test: %d/%d vectors WRONG\n", bad, len(tests))
		return nil
	}
	gpuBench(b)
	gpuBruteDemo(b)
	return nil
}

// gpuBench measures GPU MD5 throughput with a large per-dispatch batch.
func gpuBench(b gpuBackend) {
	const batch = 1 << 20 // 1M candidates per dispatch
	cands := make([]string, batch)
	buf := make([]byte, 8)
	for i := range cands {
		buf[0] = byte(i)
		buf[1] = byte(i >> 8)
		buf[2] = byte(i >> 16)
		cands[i] = "pw" + string(buf)
	}
	out := make([][16]byte, batch)
	// warm up
	_ = b.md5(cands, out)
	start := time.Now()
	var total int64
	for time.Since(start) < time.Second {
		if err := b.md5(cands, out); err != nil {
			return
		}
		total += batch
	}
	rate := float64(total) / time.Since(start).Seconds()
	clrGreen.Fprintf(stderr(), "  throughput: %s (MD5, %d/dispatch)\n", formatRate(rate), batch)
}

// gpuFallbackNotice prints the outcome of a --gpu request and always returns
// (the run continues on the CPU until kernel execution is wired into the engine).
func gpuFallbackNotice() {
	b, reason := detectGPU()
	if b == nil {
		clrYellow.Fprintf(stderr(), "GPU requested but unavailable: %s — using CPU\n", reason)
		return
	}
	defer b.close()
	clrYellow.Fprintf(stderr(),
		"GPU backend detected (%s); kernel dispatch not yet wired into the attack loop — using CPU\n",
		b.name())
}

// gpuBruteDemo cracks a known target with in-kernel candidate generation,
// proving correctness and measuring the transfer-free throughput.
func gpuBruteDemo(b gpuBackend) {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	const wordLen = 5
	target := md5.Sum([]byte("zzzzz")) // worst case: the final index
	var total uint64 = 1
	for i := 0; i < wordLen; i++ {
		total *= uint64(len(charset))
	}
	const chunk = uint64(1) << 27 // 16M candidates/dispatch
	start := time.Now()
	var done uint64
	found := ""
	for done < total {
		cnt := chunk
		if done+cnt > total {
			cnt = total - done
		}
		idx, ok, err := b.md5Brute(charset, wordLen, target, done, uint32(cnt))
		if err != nil {
			clrRed.Fprintf(stderr(), "  brute: %v\n", err)
			return
		}
		done += cnt
		if ok {
			found = bruteIndexToString(idx, wordLen, charset)
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	rate := float64(done) / elapsed
	if found == "zzzzz" {
		clrGreen.Fprintf(stderr(), "  in-kernel brute: cracked \"zzzzz\" in %.2fs — %s (candidate gen on GPU)\n",
			elapsed, formatRate(rate))
	} else {
		clrRed.Fprintf(stderr(), "  in-kernel brute: FAILED (got %q)\n", found)
	}
}

// gpuReasonOrType explains why a --gpu brute fell back: the backend reason when
// there is no GPU, else that only md5 is GPU-accelerated so far.
func gpuReasonOrType(reason, typ string) string {
	if reason != "" {
		return reason
	}
	return "GPU acceleration currently supports only -t md5 / -t ntlm, got " + typ
}
