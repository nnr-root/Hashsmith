package main

// Multi-hash mode. When several targets of the same salt-independent raw-digest
// type are cracked together, each candidate is hashed once and looked up against
// a map of every target — instead of re-running the whole attack per target.
// For N targets this turns O(N · keyspace) work into O(keyspace), the standard
// "crack a whole dump at once" acceleration.
//
// Two families qualify.
//
// Salt-independent raw digests (the digest is a pure function of the
// candidate): one hashed candidate is testable against every target, so a dump
// is one pass.
//
// Simple salted concatenations — md5/sha1/sha256 of salt||pass or pass||salt,
// hashcat 10/20, 110/120, 1410/1420 — are shareable only among targets that
// share a salt, because the message hashed is different for each distinct
// salt. Those targets are therefore GROUPED by salt (batchSaltGroups) and each
// group is one pass: a dump behind one -s is a single pass with the full
// multi-target benefit, and a dump of hash:salt lines with N distinct salts is
// N passes. N passes is inherent to salting — it is what salts are for — and
// the grouping is what keeps it linear in N rather than in the target count.
//
// Expensive or structured types (crypt, bcrypt, PBKDF2, containers, network
// captures …) still run per target: their salt is embedded in a record and the
// digest is not a concatenation at all.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sort"
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
	norm string // normalized target (potfile key / display)
	// key is the bare hex digest a hashed candidate is compared against,
	// lowercased — the digest-map key, and the digest every fast path decodes.
	// It is lower(norm) for an unsalted target; for a hash:salt input it is the
	// HASH HALF alone, since norm keeps the whole input line (that is the
	// potfile key and what the operator sees).
	key        string
	orig       string   // pre-normalization input key — matches cc's --username/--left bookkeeping
	candidates []string // batchable candidate types for this target
	// salt is the salt THIS target is hashed with — "" for an unsalted target,
	// the -s value when one salt covers the run, or the target's own :salt
	// field. It is what batchSaltGroups partitions on, and every target in a
	// pass shares it.
	salt     string
	flag     int32  // 0 = unfound, 1 = found (CAS-guarded)
	password string // set once by the CAS winner
}

// saltedBatchType reports the single candidate type a SALTED multi-hash run
// sweeps, or "" when this run is not one.
//
// It deliberately requires an explicit -t. Auto-detection over a salted dump
// is ambiguous by construction — a 32-hex digest with a salt is any of
// hashcat 10, 20, 30, 40 — and sweeping all of them would multiply the passes
// by the candidate types on top of the distinct salts. An operator who names
// the format gets the acceleration; one who does not keeps today's per-target
// path, which is what resolves that ambiguity one hash at a time.
//
// The type must additionally be one the contiguous batch path computes
// identically to hashText (stdSaltedPlanFor: md5/sha1/sha256 around a
// prefix or suffix salt). Anything else — sha512-pass-salt, the UTF-16LE
// variants, every structured record — is left exactly where it is today.
// A probe salt is used only to ask "is this shape supported"; the real salt
// is resolved per target below.
func saltedBatchType(typ, salt, saltMode string) string {
	if typ == "" || strings.EqualFold(typ, "auto") {
		return ""
	}
	canon := canonicalHashType(typ)
	_, isCompat := compatSaltedDigests[canon]
	if salt == "" && !isCompat {
		return "" // an unsalted run: the existing raw-digest path owns it
	}
	probe := salt
	if probe == "" {
		probe = "hashsmith-probe-salt"
	}
	if _, _, ok := stdSaltedPlanFor(canon, probe, saltMode); !ok {
		return ""
	}
	return canon
}

// saltedBatchTarget resolves one input line of a salted run into the digest to
// match and the salt to hash with, through compatSaltedTargetParts — the SAME
// split verifyCompatSaltedDigest uses, so a target the batch path accepts is
// hashed with exactly the salt the scalar verifier would have used. It refuses
// (rather than guesses) anything whose digest half is not the right number of
// hex characters, leaving that target to the per-target path.
func saltedBatchTarget(target, salt string, digLen int) (digest, effSalt string, ok bool) {
	digest, effSalt, ok = compatSaltedTargetParts(target, salt)
	if !ok {
		return "", "", false
	}
	digest = strings.TrimSpace(digest)
	if len(digest) != digLen*2 || !isHex(digest) {
		return "", "", false
	}
	return digest, effSalt, true
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
	minLen, maxLen, workers int, salt, saltMode, outFile string, copyResult bool,
	rules *ruleEngine, mc *maskConfig, cc *crackCtx) ([]string, int, error) {

	var batch []*batchTarget
	var leftover []string
	typeOrder := []string{}
	seenType := map[string]bool{}

	// A salted run sweeps exactly one named type; "" means this is the
	// unsalted raw-digest path, unchanged in every respect.
	saltedTyp := saltedBatchType(typ, salt, saltMode)
	saltedDigLen := 0
	if saltedTyp != "" {
		probe := salt
		if probe == "" {
			probe = "hashsmith-probe-salt"
		}
		algo, _, _ := stdSaltedPlanFor(saltedTyp, probe, saltMode)
		saltedDigLen = algo.digLen
	}

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
		if saltedTyp != "" {
			digest, tsalt, ok := saltedBatchTarget(target, salt, saltedDigLen)
			if !ok {
				// No usable salt (no -s and no :salt field), or a digest half
				// that is not this type's width. The per-target path reports
				// that as the error it is, one hash at a time.
				leftover = append(leftover, raw)
				continue
			}
			batch = append(batch, &batchTarget{
				norm: target, key: strings.ToLower(digest), orig: origKey,
				candidates: []string{saltedTyp}, salt: tsalt,
			})
			if !seenType[saltedTyp] {
				seenType[saltedTyp] = true
				typeOrder = append(typeOrder, saltedTyp)
			}
			continue
		}
		cands, ok := allBatchable(typ, target)
		if !ok {
			leftover = append(leftover, raw)
			continue
		}
		batch = append(batch, &batchTarget{
			norm: target, key: strings.ToLower(target), orig: origKey,
			candidates: cands,
		})
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

	// ── distributed slice (--skip/--limit) and session resume ───────────────
	// Both carry EXACTLY their single-target meaning here (see doCrack): skip
	// and limit are candidate indices into the whole layout — word indices in
	// dict mode — and limit is a count, not an end index. They used to divert a
	// multi-target run away from this path entirely; see crackTargets.
	var skip, limit int64
	if cc != nil {
		skip, limit = cc.skip, cc.limit
	}
	// The distinct salts this dump needs, in first-seen order. Exactly one
	// entry — "" for an unsalted dump, or the shared salt — means candidates
	// are shareable across every target and the run is a single pass per type,
	// as it always was. Several entries is the per-target-salt case: one pass
	// each, since a candidate hashed with salt A says nothing about a target
	// salted with B.
	runSalts := batchSaltGroups(batch)
	runCtx := context.Background()
	sess, resumeFrom, sessStop := batchSession(&runCtx, targets, typeOrder, runSalts, mode,
		charset, minLen, maxLen, saltMode, wordlist, mc, cc)
	if sessStop != nil {
		defer sessStop()
	}
	// --skip (distributed cracking) vs. a resumed session's saved checkpoint:
	// an explicit --skip wins, exactly as it does for a single target — and for
	// the same reason: --skip 0 is indistinguishable from "not passed", so it
	// can only ever relocate a run, never force a session back to index 0.
	if skip != 0 {
		if resumeFrom != 0 {
			clrYellow.Fprintf(os.Stderr,
				"--skip %d overrides session %q's saved checkpoint (%d)\n",
				skip, cc.sessName, resumeFrom)
		}
		resumeFrom = skip
	}

	// The GPU kernels take no resume/limit bound (see doCrack's identical
	// guard), so a sliced or resumed run stays on the CPU. Said once, before
	// the passes, rather than once per candidate type.
	gpuUnbounded := resumeFrom == 0 && limit == 0 && sess == nil
	if cc != nil && cc.useGPU && !gpuUnbounded {
		clrYellow.Fprintln(os.Stderr,
			"GPU multi-hash does not support --skip/--limit or --session yet — using CPU")
	}

	remaining := int64(len(batch))
	var refusal error
	var interrupted bool
	for _, t := range typeOrder {
		if atomic.LoadInt64(&remaining) == 0 {
			break
		}
		// The type banner is printed only when this type actually has work
		// left, exactly as it was before the salt grouping went in: the
		// per-salt loop below cannot make that decision, since it would print
		// once per group.
		typeHasWork := false
		for _, e := range batch {
			if atomic.LoadInt32(&e.flag) == 1 {
				continue
			}
			for _, c := range e.candidates {
				if strings.EqualFold(c, t) {
					typeHasWork = true
					break
				}
			}
			if typeHasWork {
				break
			}
		}
		if !typeHasWork {
			continue
		}
		if len(typeOrder) > 1 {
			color.New(themeAttr, color.Bold).Fprintf(os.Stderr, "\n→ Testing as %s\n", t)
		}
		for _, gsalt := range runSalts {
			if atomic.LoadInt64(&remaining) == 0 || interrupted || refusal != nil {
				break
			}
			// Collect still-unfound targets that list type t AND carry this
			// pass's salt. The salt filter is what makes one hashed candidate
			// a valid answer for every target in `active`.
			var active []int
			for i, e := range batch {
				if atomic.LoadInt32(&e.flag) == 1 || e.salt != gsalt {
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
			if len(runSalts) > 1 {
				color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
					"\n→ salt %q (%d target(s))\n", gsalt, len(active))
			}
			wl2 := ""
			if cc != nil {
				wl2 = cc.wordlist2
			}
			// Multi-target on the GPU: hash-and-match every candidate against
			// all still-unfound md5 targets in one dispatch. Falls through to
			// the CPU batch engine when ineligible, when no GPU is present, or
			// when the run is sliced or resumed (gpuUnbounded) — the kernels
			// take no resume/limit bound, exactly as in doCrack, so those runs
			// stay on the CPU, which does. The kernels hash the raw candidate,
			// so a salted pass is never offered to them.
			if cc != nil && cc.useGPU && gpuUnbounded && gsalt == "" &&
				(t == "md5" || t == "md4" || t == "ntlm" || t == "sha256" || t == "sha1") &&
				(mode == "brute" || mode == "mask") {
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
			intr, err := batchRunType(runCtx, t, mode, active, batch, &remaining,
				wordlist, wl2, charset, minLen, maxLen, princeElemsFor(cc), workers, rules, mc,
				gsalt, saltMode, cc != nil && cc.force, sess, resumeFrom, limit)
			if intr {
				interrupted = true
			}
			if err != nil {
				// Stop, but fall through to the reporting loop below so
				// anything an earlier pass cracked is still reported and
				// recorded.
				refusal = err
				break
			}
			if interrupted {
				// Ctrl-C ends the whole run, not just this pass — the next
				// would start on an already-cancelled context and sweep
				// nothing while claiming to have run.
				break
			}
		}
		if interrupted || refusal != nil {
			break
		}
	}

	// Session bookkeeping — the same three outcomes doCrack resolves, read
	// against the whole target set rather than one hash: everything found ends
	// the job; an interrupt keeps the checkpoint; and a --limit-bounded run
	// that merely exhausted its SLICE (Checkpoint < Total) keeps it too, so a
	// slice is never mistaken for the whole keyspace having been covered.
	if sess != nil {
		switch {
		case atomic.LoadInt64(&remaining) == 0:
			sess.remove()
		case interrupted:
			_ = sess.save()
			clrYellow.Fprintf(os.Stderr,
				"Interrupted — session %q saved at index %d/%d (resume: hashsmith crack --restore %s ...)\n",
				cc.sessName, sess.Checkpoint, sess.Total, cc.sessName)
		case sess.Checkpoint < sess.Total:
			_ = sess.save()
			clrYellow.Fprintf(os.Stderr,
				"Slice exhausted (not the whole keyspace) — session %q saved at index %d/%d "+
					"(resume: hashsmith crack --restore %s ...)\n",
				cc.sessName, sess.Checkpoint, sess.Total, cc.sessName)
		default:
			sess.remove()
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

// batchSaltGroups returns the distinct salts across a batch, in first-seen
// order, and never returns an empty slice for a non-empty batch.
//
// The order is first-seen rather than sorted so a dump's passes run in the
// order its lines were given — the same order runBatch reports results in, and
// the order a reader of the output would predict. For an unsalted dump every
// target's salt is "" and this returns exactly [""], which collapses the
// grouping to the single pass that has always run.
func batchSaltGroups(batch []*batchTarget) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range batch {
		if !seen[e.salt] {
			seen[e.salt] = true
			out = append(out, e.salt)
		}
	}
	return out
}

// batchSessionModes are the modes --session checkpoints, for one target or a
// whole dump. Identical to doCrack's list on purpose: a session's meaning is a
// property of the candidate STREAM (a global keyspace index), not of how many
// targets are being compared against it, so the two must never disagree about
// which modes are resumable.
var batchSessionModes = map[string]bool{
	"brute": true, "mask": true, "markov": true,
	"hybrid": true, "combinator": true, "prince": true,
}

// batchSessionTarget derives the session identity of a multi-target run: the
// SHA-256 of every input target, trimmed, sorted and newline-joined, tagged so
// it can never collide with a real hash in sessionState.Target.
//
// It is computed from the run's INPUT list, not from the still-unfound subset,
// and that is load-bearing. An interrupted run records what it already cracked
// into the potfile, so the next run's batch excludes those targets — keying
// the session on the surviving set would make it fail to match its own
// checkpoint and silently restart from index 0, re-doing work the operator was
// told had been done.
func batchSessionTarget(targets []string) string {
	norm := make([]string, 0, len(targets))
	for _, t := range targets {
		if v := strings.TrimSpace(t); v != "" {
			norm = append(norm, v)
		}
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "\n")))
	return "multi:" + hex.EncodeToString(sum[:])
}

// batchSession resolves --session for a multi-hash run: it returns the session
// to checkpoint into (nil when none applies), the index to resume from, and a
// stop function for the SIGINT handler it installs (nil when it installed
// none). *ctx is replaced with a cancellable context when a session is active,
// so Ctrl-C checkpoints and exits cleanly exactly as it does for one target.
//
// Sessions are refused — loudly, never silently — for a run whose checkpoint
// could not be read back unambiguously: a mode that has no stable global index
// (dict), or an ambiguous dump where several candidate TYPES are swept in turn
// and one index would have to stand for all of them.
func batchSession(ctx *context.Context, targets []string, typeOrder, runSalts []string, mode,
	charset string, minLen, maxLen int, saltMode, wordlist string,
	mc *maskConfig, cc *crackCtx) (*sessionState, int64, func()) {

	if cc == nil || cc.sessName == "" {
		return nil, 0, nil
	}
	m := strings.ToLower(mode)
	if !batchSessionModes[m] {
		clrYellow.Fprintf(os.Stderr,
			"--session is not checkpointed for -M %s in multi-hash mode; running without a checkpoint\n", m)
		return nil, 0, nil
	}
	if len(typeOrder) != 1 {
		clrYellow.Fprintln(os.Stderr,
			"--session is not checkpointed for an ambiguous multi-hash dump (several candidate "+
				"types are swept in turn, and one checkpoint cannot mean all of them); "+
				"running without a checkpoint — specify -t to make it resumable")
		return nil, 0, nil
	}
	// The same objection, for the same reason, when the dump carries several
	// distinct salts: each salt is its own sweep of the keyspace, so one index
	// cannot say how far the run got. A dump behind ONE salt is a single sweep
	// and checkpoints exactly as an unsalted one does.
	if len(runSalts) != 1 {
		clrYellow.Fprintln(os.Stderr,
			"--session is not checkpointed for a multi-hash dump with several distinct salts "+
				"(each salt is its own sweep, and one checkpoint cannot mean all of them); "+
				"running without a checkpoint")
		return nil, 0, nil
	}
	runSalt := runSalts[0]

	runCtx, cancel := context.WithCancel(*ctx)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() { <-sigCh; cancel() }()
	*ctx = runCtx
	stop := func() { signal.Stop(sigCh); cancel() }

	maskStr, custom, inc := "", [4]string{}, false
	if mc != nil {
		maskStr, custom, inc = mc.mask, mc.custom, mc.increment
	}
	key := batchSessionTarget(targets)
	pe := princeElemsFor(cc)
	if cc.session.matches(m, typeOrder[0], key, charset, minLen, maxLen, maskStr, custom, inc,
		runSalt, saltMode, wordlist, cc.wordlist2, pe) {
		sess := cc.session
		if sess.Checkpoint > 0 {
			clrYellow.Fprintf(os.Stderr, "Resuming session %q from index %d of %d\n",
				cc.sessName, sess.Checkpoint, sess.Total)
		}
		return sess, sess.Checkpoint, stop
	}
	return &sessionState{
		Name: cc.sessName, Mode: m, Type: typeOrder[0], Target: key,
		Charset: charset, MinLen: minLen, MaxLen: maxLen,
		Mask: maskStr, Custom: custom, Increment: inc,
		Salt: runSalt, SaltMode: saltMode, Wordlist: wordlist, Wordlist2: cc.wordlist2,
		PrinceElems: pe,
		path:        sessionPath(cc.sessName),
	}, 0, stop
}

// batchRunType runs one attack pass for a single type against all unfound
// targets in digestToIdx, wrapping the shared engines with a progress bar.
// ctx carries the session's Ctrl-C cancellation (context.Background() when no
// session is active). sess (may be nil) is checkpointed through the SAME
// runner-agnostic core the single-target path uses, runSessionRunner —
// deliberately not a second copy of the flush loop, since a second copy is
// exactly how the two paths would drift apart on the one property that makes a
// checkpoint trustworthy: it must never record progress that did not happen.
// resumeFrom/limit are --skip/--limit's slice, with their single-target
// meaning (see runLayout).
//
// salt is the salt EVERY target in `active` carries ("" for an unsalted pass);
// saltMode is -S, used only by the raw-digest constructions where the type
// name does not already fix the order. Callers must have grouped by salt — see
// batchSaltGroups — because a single candidate is hashed ONCE per pass and
// compared against all of `active`.
//
// It returns whether the pass was interrupted (Ctrl-C) rather than finishing.
func batchRunType(ctx context.Context, typ, mode string, active []int, batch []*batchTarget,
	remaining *int64, wordlist, wordlist2, charset string, minLen, maxLen, princeElems, workers int,
	rules *ruleEngine, mc *maskConfig, salt, saltMode string, force bool,
	sess *sessionState, resumeFrom, limit int64) (bool, error) {

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

	// hashName and pre/suf resolve this pass's construction once, outside the
	// candidate loop: for a salted pass the message is pre||candidate||suf and
	// the digest is a plain raw hash of it, which is precisely what
	// stdSaltedPlanFor asserts is identical to hashText. An unsalted pass
	// leaves both affixes empty and hashName == typ, so the closures below are
	// byte for byte what they were.
	hashName, pre, suf := typ, "", ""
	if salt != "" {
		algo, sp, ok := stdSaltedPlanFor(typ, salt, saltMode)
		if !ok {
			// runBatch only admits salted targets whose plan resolves, so this
			// is unreachable; refusing the pass rather than silently hashing
			// the bare candidate is the safe way to be wrong.
			return false, fmt.Errorf("%s: unsupported salted construction for multi-hash mode", typ)
		}
		hashName, pre, suf = algo.name, string(sp.pre), string(sp.suf)
	}

	// Prefer the zero-allocation raw-byte path: hash into a stack buffer and key
	// the target map by fixed [64]byte digests (no hex encode, no map-key alloc).
	// Types without a fast hasher fall back to the hex-string digest.
	var verify func(string) bool
	if h, ok := rawHasher(hashName); ok {
		m := make(map[[64]byte][]int, len(active))
		for _, idx := range active {
			tb, err := hex.DecodeString(strings.TrimSpace(batch[idx].key))
			if err != nil || len(tb) > 64 {
				continue
			}
			var k [64]byte
			copy(k[:], tb)
			m[k] = append(m[k], idx)
		}
		verify = func(candidate string) bool {
			var buf [64]byte
			h(buf[:], pre+candidate+suf)
			idxs, ok := m[buf]
			if !ok {
				return false
			}
			return record(candidate, idxs)
		}
	} else {
		digestFn := rawDigest(hashName)
		m := make(map[string][]int, len(active))
		for _, idx := range active {
			m[batch[idx].key] = append(m[batch[idx].key], idx)
		}
		verify = func(candidate string) bool {
			idxs, ok := m[digestFn(pre+candidate+suf)]
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
	// bruteLay / maskLay are the actual layout objects for a brute-force /
	// mask pass, built here (once, below, alongside `total`) so the
	// feasibility probe further down can dispatch a small slice of the REAL
	// pass through the REAL batchFastLayout/batchStdLayout/runLayout chain —
	// the exact dispatch runPass calls further down — instead of
	// feasibility.go re-deriving which internal path that dispatch would
	// choose. Mirrors doCrack's identically-named locals for the
	// single-target path. Built for at most one of the two, matching m; the
	// dispatch switch below reuses whichever was built instead of rebuilding
	// it.
	var bruteLay, maskLay *keyspaceLayout
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

	// progress bar total. boundWordIdx narrows a raw count to what THIS pass
	// will actually attempt — min(n, resumeFrom+limit) - resumeFrom — exactly
	// as doCrack's identically-named closure does for one target, so a sliced
	// dump's bar and ETA describe the slice rather than the whole keyspace. A
	// no-op when the run is unsliced and unresumed, which is what keeps every
	// existing multi-hash run's output unchanged.
	boundWordIdx := func(n int64) int64 {
		if n < 0 || (limit <= 0 && resumeFrom <= 0) {
			return n
		}
		bound := n
		if limit > 0 {
			if b := satAdd(resumeFrom, limit); b < bound {
				bound = b
			}
		}
		rem := bound - resumeFrom
		if rem < 0 {
			rem = 0
		}
		return rem
	}
	var total int64 = -1
	switch m {
	case "dict":
		if n, err := countWordlistLines(wordlist); err == nil {
			total = boundWordIdx(n)
			if rules != nil {
				total = satMul(total, int64(1+rules.count()))
			}
		}
	case "brute", "markov":
		total = boundWordIdx(calcBruteTotal(charset, minLen, maxLen))
		if exact, overflowed := calcBruteTotalExact(charset, minLen, maxLen); overflowed {
			warnKeyspaceNotExhaustive(exact)
		}
		if m == "brute" {
			bruteLay = bruteLayout(charset, minLen, maxLen)
		}
	case "mask":
		if mc != nil {
			total = boundWordIdx(calcMaskTotal(mc))
			if exact, overflowed := calcMaskTotalExact(mc); overflowed {
				warnKeyspaceNotExhaustive(exact)
			}
			if lay, e := maskLayout(mc); e == nil {
				maskLay = lay
			}
		}
	case "hybrid":
		if mc != nil {
			if n, err := countWordlistLines(wordlist); err == nil {
				if sets, e := parseMask(mc); e == nil {
					total = boundWordIdx(satMul(n, maskKeyspace(sets)))
				}
			}
		}
	case "combinator":
		if a, e1 := countWordlistLines(wordlist); e1 == nil {
			if b, e2 := countWordlistLines(wordlist2); e2 == nil {
				total = boundWordIdx(satMul(a, b))
			}
		}
	case "prince":
		if princeLay != nil {
			total = boundWordIdx(princeLay.total)
		}
	}
	// feasibility probe: for brute/mask, hand the guard a way to time the REAL
	// batch dispatch — batchFastLayout / batchStdLayout / the scalar runLayout
	// fallback, exactly the chain runPass drives further down — over a small
	// slice of the SAME layout this pass will enumerate, rather than have
	// feasibility.go re-derive which internal path that dispatch would choose.
	// Mirrors doCrack's probe for the single-target path (see crack.go); nil
	// for every other mode, and for brute/mask whose layout did not build —
	// feasibilityRate's fallback to benchTarget is unchanged for those.
	//
	// active/batch/record are this pass's own group: the targets that share
	// both this type AND this salt (see the gsalt loop in runBatch). The probe
	// therefore measures exactly the group this call is about to run, which is
	// the right thing to measure — multi-hash mode hashes each candidate ONCE
	// against every target in the group, so throughput does not scale with the
	// group's size and one representative measurement of THIS group is exactly
	// this pass's real rate, not an approximation of it.
	//
	// A K-salt dump calls batchRunType once per distinct salt (runBatch's
	// gsalt loop), each call reaching this same point with its own total, its
	// own active/batch group and — with this change — its own independently
	// measured probe rate. So a K-salt dump already prints and checks K
	// separate ETAs, one per pass; there is no single aggregate ETA this probe
	// could make K times too small by measuring only one group; measuring
	// "one representative group" is simply what each call has always done,
	// now done with an accurate rate instead of the scalar fallback's.
	var probe feasibilityProbe
	if lay := bruteLay; m == "brute" && lay != nil {
		probe = func(pctx context.Context, n int64) (int64, bool) {
			var attempts int64
			if batchFastLayout(pctx, typ, salt, saltMode, lay, active, batch,
				0, n, workers, &attempts, nil, record) {
				return attempts, true
			}
			if batchStdLayout(pctx, typ, lay, active, batch, salt, saltMode,
				0, n, workers, &attempts, nil, record) {
				return attempts, true
			}
			if _, err := runLayout(pctx, lay, 0, n, workers, &attempts, nil, verify); err != nil {
				return 0, false
			}
			return attempts, true
		}
	} else if lay := maskLay; m == "mask" && lay != nil {
		probe = func(pctx context.Context, n int64) (int64, bool) {
			var attempts int64
			if batchFastLayout(pctx, typ, salt, saltMode, lay, active, batch,
				0, n, workers, &attempts, nil, record) {
				return attempts, true
			}
			if batchStdLayout(pctx, typ, lay, active, batch, salt, saltMode,
				0, n, workers, &attempts, nil, record) {
				return attempts, true
			}
			if _, err := runLayout(pctx, lay, 0, n, workers, &attempts, nil, verify); err != nil {
				return 0, false
			}
			return attempts, true
		}
	}

	// Run feasibility guard — same estimate the per-hash path makes in doCrack,
	// over the same number that sizes the progress bar. `bounded` says whether
	// this run is a distributed slice or a resumed one: a slice of an enormous
	// keyspace is perfectly feasible on its own, so estimating it as if it were
	// the whole keyspace would refuse every distributed run.
	if err := checkFeasibility(total, resumeFrom != 0 || limit > 0,
		typ, batch[active[0]].norm, salt, saltMode, workers, force, probe); err != nil {
		return false, err
	}

	bar := newCrackBar(total)
	tickCtx, tickCancel := context.WithCancel(context.Background())
	go progressTicker(tickCtx, bar, &atomicAttempts)

	// Brute and mask are the two layouts the vector fast path can enumerate —
	// salted or not, since the cores hash a block and do not care what is in
	// it — so each first offers its layout to batchFastLayout (multi-target
	// hash-and-binary-search, the CPU twin of the *maskmulti GPU kernels).
	// It declines — leaving nothing recorded and nothing counted — whenever
	// the type, backend or layout is not eligible, and the SAME layout then
	// runs on the scalar path exactly as it always did. Every other mode
	// (hybrid, markov, combinator, prince, dict) is scalar-only by design:
	// their layouts carry a gen override or a non-decodable structure that
	// fastPathEligible correctly refuses.
	// runPass drives one layout through runSessionRunner — the single place
	// session checkpointing lives, shared verbatim with the single-target path.
	// The layout's runner is chosen inside the closure: the multi-target vector
	// runner when the pass is eligible, otherwise the identical layout on the
	// scalar path, exactly as before.
	var interrupted bool
	runPass := func(layout *keyspaceLayout, fastEligible bool) {
		if layout == nil {
			return
		}
		_, intr, _ := runSessionRunner(ctx, layout, sess, resumeFrom, func(watermark *int64) (string, error) {
			if fastEligible {
				if batchFastLayout(ctx, typ, salt, saltMode, layout, active, batch,
					resumeFrom, limit, workers, &atomicAttempts, watermark, record) {
					return "", nil
				}
				// The vector path declined: no core for this type (sha1,
				// sha256), or a salted construction it cannot reproduce
				// exactly, or one whose salt does not leave the candidate
				// inside a single block. A stdlib raw digest — sha1, sha256,
				// and md5/sha1/sha256 around a prefix or suffix salt — still
				// has a contiguous-batch path, with no one-block limit; see
				// stdfast.go. It declines in turn, just as safely, for
				// anything it cannot enumerate.
				if batchStdLayout(ctx, typ, layout, active, batch, salt, saltMode,
					resumeFrom, limit, workers, &atomicAttempts, watermark, record) {
					return "", nil
				}
			}
			return runLayout(ctx, layout, resumeFrom, limit, workers, &atomicAttempts, watermark, verify)
		})
		interrupted = interrupted || intr
	}

	switch m {
	case "brute":
		// Reuse the layout the feasibility probe already built above (same
		// charset/minLen/maxLen, so it is identical) rather than paying for a
		// second allocation of the same segments.
		layout := bruteLay
		if layout == nil {
			layout = bruteLayout(charset, minLen, maxLen)
		}
		runPass(layout, true)
	case "mask":
		if mc != nil {
			// Reuse the layout the feasibility probe already built above when
			// it built successfully; otherwise (probe wasn't run, or
			// maskLayout failed there for a reason worth surfacing) build it
			// here so a bad mask still behaves exactly as before.
			layout := maskLay
			if layout == nil {
				layout, _ = maskLayout(mc)
			}
			if layout != nil {
				runPass(layout, true)
			}
		}
	case "hybrid":
		if mc != nil {
			if sets, err := parseMask(mc); err == nil {
				if words, _, e := loadWordlistSlice(wordlist); e == nil {
					runPass(hybridLayout(words, sets, mc.maskFirst), false)
				}
			}
		}
	case "markov":
		if model, err := trainMarkov(charset, wordlist); err == nil {
			runPass(markovLayout(model, minLen, maxLen), false)
		}
	case "combinator":
		if wordlist2 != "" {
			if left, _, e1 := loadWordlistSlice(wordlist); e1 == nil {
				if right, _, e2 := loadWordlistSlice(wordlist2); e2 == nil {
					runPass(combinatorLayout(left, right), false)
				}
			}
		}
	case "prince":
		runPass(princeLay, false)
	default: // dict
		batchDictAttack(ctx, wordlist, resumeFrom, limit, verify, workers, rules, &atomicAttempts)
		interrupted = ctx.Err() != nil
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
	return interrupted, nil
}

// batchDictAttack is the dictionary engine for multi-hash mode: it never stops
// on the first match, running until verify signals all targets found or the
// wordlist is exhausted.
//
// skip and limit (0 = unbounded) bound it to word indices [skip, skip+limit)
// of the whole wordlist, through the SAME dictWordBounds arithmetic dictAttack
// and --stdout use — so a dump sliced across machines moves whole words, each
// carrying its full rule expansion, exactly as a single-target dict slice does.
func batchDictAttack(parent context.Context, wordlistPath string, skip, limit int64,
	verify func(string) bool, workers int, rules *ruleEngine, atomicAttempts *int64) {

	// The source line ("Wordlist: ...") is announced once per run at the CLI
	// entry point (resolveWordlistForMode), not once per target here.
	f, _, err := openWordlist(wordlistPath)
	if err != nil {
		clrRed.Fprintf(os.Stderr, "  wordlist error: %v\n", err)
		return
	}
	defer f.Close()
	skip, upper := dictWordBounds(skip, limit)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	batchCh := make(chan []string, workers*4)
	go func() {
		defer close(batchCh)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		cur := make([]string, 0, dictBatchSize)
		var idx int64
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
			}
			i := idx
			idx++
			if i < skip {
				continue
			}
			if upper >= 0 && i >= upper {
				break
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
