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
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hashsmith-go/internal/gpubackend"
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
// gpuBackend aliases the backend interface, which lives in internal/gpubackend
// together with the cgo implementations: Go forbids one package from holding
// both cgo and the Go assembly of our vector cores. See that package's doc.
type gpuBackend = gpubackend.Backend

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

// gpuMD5Batcher is deliberately narrower than gpuBackend so the streaming
// dictionary engine can be tested without mocking every mask operation.
type gpuMD5Batcher interface {
	MD5(candidates []string, out [][16]byte) error
}

// One million candidates amortizes Metal/OpenCL buffer creation and command
// submission. At the 55-byte kernel limit the working set remains comfortably
// below 100 MiB (strings, packed input, offsets, labels, and 16-byte digests).
const gpuDictBatchSize = 1 << 20

// gpuDictAttack streams an MD5 wordlist through the GPU batch kernel. Rules are
// expanded on the CPU, then their resulting candidates join the same large GPU
// dispatches. Candidates longer than a one-block MD5 message are verified on
// the CPU (after flushing earlier work) so --gpu never changes correctness or
// first-match ordering.
func gpuDictAttack(ctx context.Context, wordlistPath, targetHex string, rules *ruleEngine,
	atomicAttempts *int64) (crackedResult, error, bool) {
	b, _ := activeGPUBackend()
	if b == nil {
		return crackedResult{}, nil, false
	}
	result, err := gpuDictAttackWithBackend(ctx, b, wordlistPath, targetHex, rules, atomicAttempts)
	return result, err, true
}

func gpuDictAttackWithBackend(ctx context.Context, b gpuMD5Batcher, wordlistPath, targetHex string,
	rules *ruleEngine, atomicAttempts *int64) (crackedResult, error) {
	targetBytes, err := hex.DecodeString(strings.TrimSpace(targetHex))
	if err != nil || len(targetBytes) != md5.Size {
		return crackedResult{}, errors.New("invalid MD5 target for GPU dictionary attack")
	}
	var target [md5.Size]byte
	copy(target[:], targetBytes)

	// The source line ("Wordlist: ...") is announced once per run at the CLI
	// entry point (resolveWordlistForMode), not once per target here.
	f, _, err := openWordlist(wordlistPath)
	if err != nil {
		return crackedResult{}, err
	}
	defer f.Close()

	candidates := make([]string, 0, gpuDictBatchSize)
	labels := make([]string, 0, gpuDictBatchSize)
	flush := func() (crackedResult, bool, error) {
		if len(candidates) == 0 {
			return crackedResult{}, false, nil
		}
		out := make([][md5.Size]byte, len(candidates))
		if err := b.MD5(candidates, out); err != nil {
			return crackedResult{}, false, err
		}
		atomic.AddInt64(atomicAttempts, int64(len(candidates)))
		for i := range out {
			if out[i] == target {
				return crackedResult{password: candidates[i], ruleLabel: labels[i]}, true, nil
			}
		}
		candidates = candidates[:0]
		labels = labels[:0]
		return crackedResult{}, false, nil
	}
	add := func(candidate, ruleLabel string) (crackedResult, bool, error) {
		select {
		case <-ctx.Done():
			return crackedResult{}, false, ctx.Err()
		default:
		}
		if len(candidate) > maxGPUWordLen("md5") {
			if result, found, err := flush(); found || err != nil {
				return result, found, err
			}
			atomic.AddInt64(atomicAttempts, 1)
			if md5.Sum([]byte(candidate)) == target {
				return crackedResult{password: candidate, ruleLabel: ruleLabel}, true, nil
			}
			return crackedResult{}, false, nil
		}
		candidates = append(candidates, candidate)
		labels = append(labels, ruleLabel)
		if len(candidates) == gpuDictBatchSize {
			return flush()
		}
		return crackedResult{}, false, nil
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}
		if result, found, err := add(word, ""); found || err != nil {
			return result, err
		}
		if rules != nil {
			for _, mangled := range rules.expand(word) {
				if result, found, err := add(mangled.password, mangled.ruleLabel); found || err != nil {
					return result, err
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return crackedResult{}, err
	}
	result, _, err := flush()
	return result, err
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
		return b.MD5Mask
	case "ntlm":
		return b.NTLMMask
	case "md4":
		return b.MD4Mask
	case "sha256":
		return b.SHA256Mask
	case "sha1":
		return b.SHA1Mask
	}
	return nil
}

// gpuMultiMethod returns the multi-target mask kernel for a hash type, or nil.
func gpuMultiMethod(b gpuBackend, typ string) func([][]byte, []uint32, uint64, uint32, []uint32, []uint64) error {
	switch strings.ToLower(typ) {
	case "md5":
		return b.MD5MaskMulti
	case "ntlm":
		return b.NTLMMaskMulti
	case "md4":
		return b.MD4MaskMulti
	case "sha256":
		return b.SHA256MaskMulti
	case "sha1":
		return b.SHA1MaskMulti
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
	case "md4":
		return 4
	}
	return 0
}

// le32 delegates to gpubackend.LE32 so the byte order the kernels expect is
// defined in exactly one place, on the same side of the boundary as the
// kernels themselves.
func le32(b []byte) uint32 { return gpubackend.LE32(b) }

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
		total = satAdd(total, maskKeyspace(sets))
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
			if err := b.MaskSweepMulti(algo, sets, words, targets, done, span, chunk, foundFlag, foundIdx); err != nil {
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
	defer b.Close()
	clrGreen.Fprintf(stderr(), "GPU acceleration: available — %s\n", b.Name())
	return gpuSelfTest(b)
}

// gpuSelfTest verifies the batch kernel and every in-kernel mask algorithm
// against CPU results before reporting the backend as healthy.
func gpuSelfTest(b gpuBackend) error {
	tests := []string{"", "a", "abc", "password", "hashsmith", "The quick brown fox jumps"}
	out := make([][16]byte, len(tests))
	if err := b.MD5(tests, out); err != nil {
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
	sets := [][]byte{[]byte("abc"), []byte("abc"), []byte("abc")}
	const candidate = "cab"
	for _, typ := range []string{"md5", "md4", "ntlm", "sha1", "sha256"} {
		targetHex, err := hashText(candidate, typ, "", "prefix")
		if err != nil {
			return err
		}
		target, _ := hex.DecodeString(targetHex)
		idx, found, err := gpuMaskMethod(b, typ)(sets, target, 0, 27)
		if err != nil || !found || maskIdxToStr(int64(idx), sets) != candidate {
			return fmt.Errorf("GPU %s mask self-test failed: found=%v index=%d error=%v", typ, found, idx, err)
		}
	}
	clrGreen.Fprintln(stderr(), "  self-test: MD5, MD4, NTLM, SHA-1 and SHA-256 mask kernels match CPU ✓")
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
	_ = b.MD5(cands, out)
	start := time.Now()
	var total int64
	for time.Since(start) < time.Second {
		if err := b.MD5(cands, out); err != nil {
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
	defer b.Close()
	clrYellow.Fprintf(stderr(),
		"GPU backend detected (%s); kernel dispatch not yet wired into the attack loop — using CPU\n",
		b.Name())
}

// gpuBruteDemo cracks a known target with in-kernel candidate generation,
// proving correctness and measuring the transfer-free throughput.
func gpuBruteDemo(b gpuBackend) {
	target := md5.Sum([]byte("zzzzz")) // worst case: final index of a-z^5
	th := hex.EncodeToString(target[:])
	var n int64
	start := time.Now()
	pw, found, _ := gpuBruteHash(th, "md5", "abcdefghijklmnopqrstuvwxyz", 5, 5, &n)
	elapsed := time.Since(start).Seconds()
	rate := float64(n) / elapsed
	if found && pw == "zzzzz" {
		clrGreen.Fprintf(stderr(), "  in-kernel brute: cracked \"zzzzz\" in %.2fs — %s (candidate gen on GPU)\n",
			elapsed, formatRate(rate))
	} else {
		clrRed.Fprintf(stderr(), "  in-kernel brute: FAILED (got %q)\n", pw)
	}
}

// gpuReasonOrType explains why a --gpu brute fell back: the backend reason when
// there is no GPU, else list the accelerated raw formats.
func gpuReasonOrType(reason, typ string) string {
	if reason != "" {
		return reason
	}
	return "GPU acceleration supports -t md5/md4/ntlm/sha1/sha256, got " + typ
}
