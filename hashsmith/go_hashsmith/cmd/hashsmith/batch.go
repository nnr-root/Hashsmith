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

// batchableTypes are the raw digests whose value depends only on the candidate.
var batchableTypes = map[string]bool{
	"md4": true, "md5": true, "sha1": true, "sha224": true, "sha256": true,
	"sha384": true, "sha512": true, "sha3_224": true, "sha3_256": true,
	"sha3_384": true, "sha3_512": true, "ripemd160": true, "whirlpool": true,
	"streebog256": true, "streebog512": true, "blake2b": true, "blake2s": true,
	"ntlm": true, "mysql323": true, "mysql41": true, "mssql2000": true,
	"md5-md5": true, "sha1-sha1": true, "sha256-sha256": true,
}

// rawDigest returns a candidate→lowercase-hex function for a batchable type.
func rawDigest(typ string) func(string) string {
	algo := strings.ToLower(typ)
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
	candidates []string // batchable candidate types for this target
	flag       int32    // 0 = unfound, 1 = found (CAS-guarded)
	password   string   // set once by the CAS winner
}

// allBatchable reports the batchable candidate types for a target, and whether
// *every* candidate is batchable (so the target can be handled entirely here).
func allBatchable(typ, target string) ([]string, bool) {
	var cands []string
	if typ != "" && !strings.EqualFold(typ, "auto") {
		cands = []string{strings.ToLower(typ)}
	} else {
		cands = detectHashTypes(target)
	}
	if len(cands) == 0 {
		return nil, false
	}
	for _, c := range cands {
		if !batchableTypes[strings.ToLower(c)] {
			return nil, false
		}
	}
	return cands, true
}

// runBatch handles every purely-batchable target as a group and returns the
// targets it did NOT handle (to be cracked individually by the caller). It
// reports and records results for the ones it does handle.
func runBatch(targets []string, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int, saltMode, outFile string, copyResult bool,
	rules *ruleEngine, mc *maskConfig, cc *crackCtx) []string {

	var batch []*batchTarget
	var leftover []string
	typeOrder := []string{}
	seenType := map[string]bool{}

	for _, raw := range targets {
		target := strings.TrimSpace(raw)
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
				continue
			}
		}
		cands, ok := allBatchable(typ, target)
		if !ok {
			leftover = append(leftover, raw)
			continue
		}
		batch = append(batch, &batchTarget{norm: target, key: strings.ToLower(target), candidates: cands})
		for _, c := range cands {
			if lc := strings.ToLower(c); !seenType[lc] {
				seenType[lc] = true
				typeOrder = append(typeOrder, lc)
			}
		}
	}

	if len(batch) == 0 {
		return leftover
	}

	color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
		"\n⚡ Multi-hash mode: %d target(s), hashing each candidate once against all\n", len(batch))
	if len(typeOrder) > 1 {
		clrYellow.Fprintf(os.Stderr, "  candidate types: %s\n", strings.Join(typeOrder, ", "))
	}

	remaining := int64(len(batch))
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
		batchRunType(t, mode, active, batch, &remaining,
			wordlist, charset, minLen, maxLen, workers, rules, mc)
	}

	// Report and record.
	var founds []string
	for _, e := range batch {
		if atomic.LoadInt32(&e.flag) == 1 {
			clrGreen.Fprintf(os.Stderr, "  %s  =>  %s\n", e.norm, e.password)
			if cc != nil {
				cc.pot.add(e.norm, e.password)
			}
			founds = append(founds, e.norm+":"+e.password)
		} else {
			clrYellow.Fprintf(os.Stderr, "  %s  =>  (not found)\n", e.norm)
		}
	}
	if outFile != "" && len(founds) > 0 {
		if err := os.WriteFile(outFile, []byte(strings.Join(founds, "\n")+"\n"), 0644); err == nil {
			clrGreen.Fprintf(os.Stderr, "Saved %d result(s) to %s\n", len(founds), outFile)
		}
	}
	return leftover
}

// batchRunType runs one attack pass for a single type against all unfound
// targets in digestToIdx, wrapping the shared engines with a progress bar.
func batchRunType(typ, mode string, active []int, batch []*batchTarget,
	remaining *int64, wordlist, charset string, minLen, maxLen, workers int,
	rules *ruleEngine, mc *maskConfig) {

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

	// progress bar total
	var total int64 = -1
	m := strings.ToLower(mode)
	switch m {
	case "dict":
		if n, err := countWordlistLines(wordlist); err == nil {
			total = n
			if rules != nil {
				total *= int64(1 + rules.count())
			}
		}
	case "brute":
		total = calcBruteTotal(charset, minLen, maxLen)
	case "mask":
		if mc != nil {
			total = calcMaskTotal(mc)
		}
	}
	bar := newCrackBar(total)
	tickCtx, tickCancel := context.WithCancel(context.Background())
	go progressTicker(tickCtx, bar, &atomicAttempts)

	switch m {
	case "brute":
		_, _ = runLayout(context.Background(), bruteLayout(charset, minLen, maxLen),
			0, workers, &atomicAttempts, nil, verify)
	case "mask":
		if mc != nil {
			if layout, err := maskLayout(mc); err == nil {
				_, _ = runLayout(context.Background(), layout, 0, workers, &atomicAttempts, nil, verify)
			}
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

	try := func(pw string) bool {
		atomic.AddInt64(atomicAttempts, 1)
		if verify(pw) {
			cancel()
			return true
		}
		return false
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
