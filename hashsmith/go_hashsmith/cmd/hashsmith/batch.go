package main

// Multi-hash mode. When several targets of the same salt-independent raw-digest
// type are cracked together, each candidate is hashed once and looked up against
// a map of every target — instead of re-running the whole attack per target.
// For N targets this turns O(N · keyspace) work into O(keyspace), the standard
// "crack a whole dump at once" acceleration.
//
// Only salt-independent raw digests qualify (the digest is a pure function of
// the candidate). Salted / expensive types (crypt, bcrypt, PBKDF2, containers,
// network captures …) still run per target, where per-target salts make shared
// work impossible.

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// batchBannerPrefix is the distinguishing text of the multi-hash banner below.
// It is a named constant because a test depends on it to tell "an attack ran"
// from "no attack ran" — asserting on the leftover target set cannot separate
// those, since an unfindable hash looks identical either way. Sharing the
// constant means rewording the banner updates the test with it, rather than
// silently making the assertion match nothing in BOTH worlds and quietly
// ceasing to guard anything.
const batchBannerPrefix = "Multi-hash mode"

// batchableTypes are the raw digests whose value depends only on the candidate.
var batchableTypes = map[string]bool{
	"md2": true, "md4": true, "md5": true, "sha0": true, "sha1": true,
	"sha224": true, "sha256": true,
	"sha384": true, "sha512": true, "sha3_224": true, "sha3_256": true,
	"sha3_384": true, "sha3_512": true, "ripemd160": true, "whirlpool": true,
	"streebog256": true, "streebog512": true, "blake2b": true, "blake2s": true,
	"sha512_224": true, "sha512_256": true, "keccak256": true, "keccak512": true,
	"shake128-256": true, "shake256-512": true, "blake2b256": true, "blake2b384": true,
	"ntlm": true, "lm": true, "crc32": true, "crc32c": true, "crc64": true,
	"adler32": true, "fnv1a32": true, "fnv1a64": true, "sm3": true,
	"xxhash32": true, "xxhash64": true, "murmur3-32": true,
	"mysql323": true, "mysql41": true, "mssql2000": true,
	"md5-md5": true, "sha1-sha1": true, "sha256-sha256": true,
	"sha512-sha512": true, "sha3_256-sha3_256": true,
}

// rawDigest returns a candidate→lowercase-hex function for a batchable type.
func rawDigest(typ string) func(string) string {
	algo := canonicalHashType(typ)
	return func(c string) string {
		h, err := hashText(c, algo, "", "prefix")
		if err != nil {
			return ""
		}
		return strings.ToLower(h)
	}
}

// batchTarget is one hash in a multi-hash run.
type batchTarget struct {
	norm       string   // normalized target (potfile key / display)
	key        string   // lower(norm) — the digest-map key
	orig       string   // pre-normalization input key — matches cc's --username/--left bookkeeping
	candidates []string // batchable candidate types for this target
	flag       int32    // 0 = unfound, 1 = found (CAS-guarded)
	password   string   // set once by the CAS winner
}

// allBatchable reports the batchable candidate types for a target, and whether
// *every* candidate is batchable (so the target can be handled entirely here).
func allBatchable(typ, target string) ([]string, bool) {
	var cands []string
	if typ != "" && !strings.EqualFold(typ, "auto") {
		cands = []string{canonicalHashType(typ)}
	} else {
		cands = detectHashTypes(target)
	}
	if len(cands) == 0 {
		return nil, false
	}
	for _, c := range cands {
		if !batchableTypes[canonicalHashType(c)] {
			return nil, false
		}
	}
	return cands, true
}

// runBatch handles every purely-batchable target as a group and returns the
// targets it did NOT handle (to be cracked individually by the caller). It
// reports and records results for the ones it does handle.
// runBatch returns the targets it could not handle (for per-hash cracking), the
// number it attacked and did not crack, and — when the run feasibility guard
// refused the attack (see checkFeasibility) — that refusal. A refusal stops the
// remaining passes but still reports whatever earlier passes already cracked,
// so nothing found is thrown away on the way out.
func runBatch(targets []string, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int, saltMode, outFile string, copyResult bool,
	rules *ruleEngine, mc *maskConfig, cc *crackCtx) ([]string, int, error) {

	var batch []*batchTarget
	var leftover []string
	typeOrder := []string{}
	seenType := map[string]bool{}

	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		// origKey is captured before any of the transformations below, so it
		// exactly matches the hash string cc's --username/--left bookkeeping
		// (built in runCrack from the same gathered input) is keyed by.
		origKey := target
		if stripped := stripShadowUsername(target); stripped != target {
			target = stripped
		}
		if normalized, enc := normalizeHashInput(target); enc != "" {
			target = normalized
		}
		// Potfile hits are reported immediately and never re-attacked.
		if cc != nil {
			if pw, ok := cc.pot.lookup(target); ok {
				clrGreen.Fprintf(os.Stderr, "  %s  =>  %s  (potfile)\n", target, pw)
				if u := cc.usernameFor(origKey); u != "" {
					clrGreen.Fprintf(os.Stderr, "    user: %s\n", u)
				}
				cc.markFound(origKey)
				continue
			}
		}
		cands, ok := allBatchable(typ, target)
		if !ok {
			leftover = append(leftover, raw)
			continue
		}
		batch = append(batch, &batchTarget{norm: target, key: strings.ToLower(target), orig: origKey, candidates: cands})
		for _, c := range cands {
			if lc := strings.ToLower(c); !seenType[lc] {
				seenType[lc] = true
				typeOrder = append(typeOrder, lc)
			}
		}
	}

	if len(batch) == 0 {
		return leftover, 0, nil
	}

	color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
		"\n⚡ "+batchBannerPrefix+": %d target(s), hashing each candidate once against all\n", len(batch))
	if len(typeOrder) > 1 {
		clrYellow.Fprintf(os.Stderr, "  candidate types: %s\n", strings.Join(typeOrder, ", "))
	}

	remaining := int64(len(batch))
	var refusal error
	for _, t := range typeOrder {
		if atomic.LoadInt64(&remaining) == 0 {
			break
		}
		// Collect still-unfound targets that list type t.
		var active []int
		for i, e := range batch {
			if atomic.LoadInt32(&e.flag) == 1 {
				continue
			}
			for _, c := range e.candidates {
				if strings.EqualFold(c, t) {
					active = append(active, i)
					break
				}
			}
		}
		if len(active) == 0 {
			continue
		}
		if len(typeOrder) > 1 {
			color.New(themeAttr, color.Bold).Fprintf(os.Stderr, "\n→ Testing as %s\n", t)
		}
		wl2 := ""
		if cc != nil {
			wl2 = cc.wordlist2
		}
		// Multi-target on the GPU: hash-and-match every candidate against all
		// still-unfound md5 targets in one dispatch. Falls through to the CPU
		// batch engine when ineligible or no GPU is present.
		if cc != nil && cc.useGPU && (t == "md5" || t == "md4" || t == "ntlm" || t == "sha256" || t == "sha1") && (mode == "brute" || mode == "mask") {
			entries := make([]*batchTarget, len(active))
			for i, idx := range active {
				entries[i] = batch[idx]
			}
			if gpuBatchMaskHash(t, mode, mc, charset, minLen, maxLen, entries) {
				for _, e := range entries {
					if atomic.LoadInt32(&e.flag) == 1 {
						atomic.AddInt64(&remaining, -1)
					}
				}
				continue
			}
		}
		if err := batchRunType(t, mode, active, batch, &remaining,
			wordlist, wl2, charset, minLen, maxLen, princeElemsFor(cc), workers, rules, mc,
			cc != nil && cc.force); err != nil {
			// Stop, but fall through to the reporting loop below so anything an
			// earlier pass cracked is still reported and recorded.
			refusal = err
			break
		}
	}

	// Report and record.
	var founds []string // default-format fallback lines (see below)
	uncracked := 0
	foundCount := 0
	for _, e := range batch {
		if atomic.LoadInt32(&e.flag) == 1 {
			foundCount++
			clrGreen.Fprintf(os.Stderr, "  %s  =>  %s\n", e.norm, e.password)
			if u := cc.usernameFor(e.orig); u != "" {
				clrGreen.Fprintf(os.Stderr, "    user: %s\n", u)
			}
			if cc != nil {
				cc.pot.add(e.norm, e.password)
				cc.recordPlain(e.password)
				cc.markFound(e.orig)
			}
			// Default line (--outfile-format unset): unchanged from before —
			// "hash:password". --outfile-format overrides it with the
			// selected, hashcat-style fields.
			line := e.norm + ":" + e.password
			if fmted, ok, err := cc.resultLine(e.orig, e.norm, e.password); err == nil && ok {
				line = fmted
			}
			// Under --left, -o is repurposed entirely as the leftover-target
			// destination (written once, after the whole run) — see doCrack's
			// identical guard for the reasoning — so results aren't also
			// written here.
			leftMode := cc != nil && cc.left
			if !leftMode {
				if cc != nil && cc.outW != nil {
					_ = cc.outW.writeLine(line)
				} else {
					founds = append(founds, line)
				}
			}
		} else {
			clrYellow.Fprintf(os.Stderr, "  %s  =>  (not found)\n", e.norm)
			uncracked++
		}
	}
	// cc.outW (opened once for the whole run, appended to as results come in —
	// see newOutWriter) is what actually persists results when it's set. This
	// single-shot write only remains as a fallback for a caller that never
	// wired up cc.outW (nothing in this codebase does that today, but it keeps
	// runBatch usable standalone without cc.outW's truncation fix).
	if outFile != "" && len(founds) > 0 && (cc == nil || cc.outW == nil) {
		if err := os.WriteFile(outFile, []byte(strings.Join(founds, "\n")+"\n"), 0644); err == nil {
			clrGreen.Fprintf(os.Stderr, "Saved %d result(s) to %s\n", len(founds), outFile)
		}
	} else if outFile != "" && cc != nil && cc.outW != nil && foundCount > 0 {
		clrGreen.Fprintf(os.Stderr, "Saved %d result(s) to %s\n", foundCount, outFile)
	}
	return leftover, uncracked, refusal
}

// batchRunType runs one attack pass for a single type against all unfound
// targets in digestToIdx, wrapping the shared engines with a progress bar.
func batchRunType(typ, mode string, active []int, batch []*batchTarget,
	remaining *int64, wordlist, wordlist2, charset string, minLen, maxLen, princeElems, workers int,
	rules *ruleEngine, mc *maskConfig, force bool) error {

	start := time.Now()
	var atomicAttempts int64

	// record marks every matching target (CAS-guarded); it returns true only
	// once all targets in the run are found, signalling the engine to stop.
	record := func(candidate string, idxs []int) bool {
		for _, idx := range idxs {
			if atomic.CompareAndSwapInt32(&batch[idx].flag, 0, 1) {
				batch[idx].password = candidate
				if atomic.AddInt64(remaining, -1) == 0 {
					return true
				}
			}
		}
		return false
	}

	// Prefer the zero-allocation raw-byte path: hash into a stack buffer and key
	// the target map by fixed [64]byte digests (no hex encode, no map-key alloc).
	// Types without a fast hasher fall back to the hex-string digest.
	var verify func(string) bool
	if h, ok := rawHasher(typ); ok {
		m := make(map[[64]byte][]int, len(active))
		for _, idx := range active {
			tb, err := hex.DecodeString(strings.TrimSpace(batch[idx].norm))
			if err != nil || len(tb) > 64 {
				continue
			}
			var k [64]byte
			copy(k[:], tb)
			m[k] = append(m[k], idx)
		}
		verify = func(candidate string) bool {
			var buf [64]byte
			h(buf[:], candidate)
			idxs, ok := m[buf]
			if !ok {
				return false
			}
			return record(candidate, idxs)
		}
	} else {
		digestFn := rawDigest(typ)
		m := make(map[string][]int, len(active))
		for _, idx := range active {
			m[batch[idx].key] = append(m[batch[idx].key], idx)
		}
		verify = func(candidate string) bool {
			idxs, ok := m[digestFn(candidate)]
			if !ok {
				return false
			}
			return record(candidate, idxs)
		}
	}

	// PRINCE's chain table is built once here and reused for both the progress
	// bar total and the run itself (see doCrack for the same shape). A refusal
	// leaves princeLay nil, which the run switch treats as "nothing to do" —
	// the same way the other modes' setup errors are handled in this function.
	m := strings.ToLower(mode)
	var princeLay *keyspaceLayout
	if m == "prince" {
		if elems, _, err := loadWordlistSlice(wordlist); err == nil {
			if lay, ex, e := princeLayout(elems, minLen, maxLen, princeElems); e == nil {
				princeLay = lay
				if ex.Cmp(maxInt64Big) > 0 {
					warnKeyspaceNotExhaustive(ex)
				}
			} else {
				clrRed.Fprintf(os.Stderr, "  prince error: %v\n", e)
			}
		} else {
			clrRed.Fprintf(os.Stderr, "  element list error: %v\n", err)
		}
	}

	// progress bar total
	var total int64 = -1
	switch m {
	case "dict":
		if n, err := countWordlistLines(wordlist); err == nil {
			total = n
			if rules != nil {
				total = satMul(total, int64(1+rules.count()))
			}
		}
	case "brute", "markov":
		total = calcBruteTotal(charset, minLen, maxLen)
		if exact, overflowed := calcBruteTotalExact(charset, minLen, maxLen); overflowed {
			warnKeyspaceNotExhaustive(exact)
		}
	case "mask":
		if mc != nil {
			total = calcMaskTotal(mc)
			if exact, overflowed := calcMaskTotalExact(mc); overflowed {
				warnKeyspaceNotExhaustive(exact)
			}
		}
	case "hybrid":
		if mc != nil {
			if n, err := countWordlistLines(wordlist); err == nil {
				if sets, e := parseMask(mc); e == nil {
					total = satMul(n, maskKeyspace(sets))
				}
			}
		}
	case "combinator":
		if a, e1 := countWordlistLines(wordlist); e1 == nil {
			if b, e2 := countWordlistLines(wordlist2); e2 == nil {
				total = satMul(a, b)
			}
		}
	case "prince":
		if princeLay != nil {
			total = princeLay.total
		}
	}
	// Run feasibility guard — same estimate the per-hash path makes in doCrack,
	// over the same number that sizes the progress bar. Multi-hash mode is only
	// ever entered with no --skip/--limit (crackTargets sends a bounded run
	// down the per-target path instead), so this run is never a slice: bounded
	// is false. The probe times the first still-unfound target of this type,
	// which is representative — every target in this pass is the same type, and
	// multi-hash mode hashes each candidate ONCE for all of them, so the rate
	// does not scale with the target count.
	if err := checkFeasibility(total, false, typ, batch[active[0]].norm, "", "prefix", workers, force); err != nil {
		return err
	}

	bar := newCrackBar(total)
	tickCtx, tickCancel := context.WithCancel(context.Background())
	go progressTicker(tickCtx, bar, &atomicAttempts)

	switch m {
	case "brute":
		_, _ = runLayout(context.Background(), bruteLayout(charset, minLen, maxLen),
			0, 0, workers, &atomicAttempts, nil, verify)
	case "mask":
		if mc != nil {
			if layout, err := maskLayout(mc); err == nil {
				_, _ = runLayout(context.Background(), layout, 0, 0, workers, &atomicAttempts, nil, verify)
			}
		}
	case "hybrid":
		if mc != nil {
			if sets, err := parseMask(mc); err == nil {
				if words, _, e := loadWordlistSlice(wordlist); e == nil {
					_, _ = runLayout(context.Background(), hybridLayout(words, sets, mc.maskFirst), 0, 0, workers, &atomicAttempts, nil, verify)
				}
			}
		}
	case "markov":
		if model, err := trainMarkov(charset, wordlist); err == nil {
			_, _ = runLayout(context.Background(), markovLayout(model, minLen, maxLen), 0, 0, workers, &atomicAttempts, nil, verify)
		}
	case "combinator":
		if wordlist2 != "" {
			if left, _, e1 := loadWordlistSlice(wordlist); e1 == nil {
				if right, _, e2 := loadWordlistSlice(wordlist2); e2 == nil {
					_, _ = runLayout(context.Background(), combinatorLayout(left, right), 0, 0, workers, &atomicAttempts, nil, verify)
				}
			}
		}
	case "prince":
		if princeLay != nil {
			_, _ = runLayout(context.Background(), princeLay, 0, 0, workers, &atomicAttempts, nil, verify)
		}
	default: // dict
		batchDictAttack(wordlist, verify, workers, rules, &atomicAttempts)
	}

	tickCancel()
	_ = bar.Finish()
	fmt.Fprintln(os.Stderr)
	elapsed := time.Since(start).Seconds()
	attempts := atomic.LoadInt64(&atomicAttempts)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(attempts) / elapsed
	}
	color.New(themeAttr).Fprintf(os.Stderr,
		"Attempts: %d | Elapsed: %.2fs | Rate: %s\n", attempts, elapsed, formatRate(rate))
	return nil
}

// batchDictAttack is the dictionary engine for multi-hash mode: it never stops
// on the first match, running until verify signals all targets found or the
// wordlist is exhausted.
func batchDictAttack(wordlistPath string, verify func(string) bool, workers int,
	rules *ruleEngine, atomicAttempts *int64) {

	f, label, err := openWordlist(wordlistPath)
	if err != nil {
		clrRed.Fprintf(os.Stderr, "  wordlist error: %v\n", err)
		return
	}
	defer f.Close()
	if label == defaultWordlistLabel {
		clrYellow.Fprintf(os.Stderr, "No wordlist supplied — using %s\n", label)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	batchCh := make(chan []string, workers*4)
	go func() {
		defer close(batchCh)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		cur := make([]string, 0, dictBatchSize)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
			}
			cur = append(cur, word)
			if len(cur) >= dictBatchSize {
				select {
				case batchCh <- cur:
					cur = make([]string, 0, dictBatchSize)
				case <-ctx.Done():
					return
				}
			}
		}
		if len(cur) > 0 {
			select {
			case batchCh <- cur:
			case <-ctx.Done():
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			var localAttempts int64
			defer func() {
				atomic.AddInt64(atomicAttempts, localAttempts)
				wg.Done()
			}()
			try := func(pw string) bool {
				localAttempts++
				if localAttempts >= 1024 {
					atomic.AddInt64(atomicAttempts, localAttempts)
					localAttempts = 0
				}
				if verify(pw) {
					cancel()
					return true
				}
				return false
			}
			for {
				select {
				case <-ctx.Done():
					return
				case words, ok := <-batchCh:
					if !ok {
						return
					}
					for _, word := range words {
						select {
						case <-ctx.Done():
							return
						default:
						}
						if try(word) {
							return
						}
						if rules != nil {
							for _, mw := range rules.expand(word) {
								if try(mw.password) {
									return
								}
							}
						}
					}
				}
			}
		}()
	}
	wg.Wait()
}
