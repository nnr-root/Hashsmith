package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	dictBatchSize = 512  // words per batch sent over channel
	ctxCheckEvery = 1024 // brute-force iterations between context polls
)

// md5TargetBytes decodes a hex MD5 digest into the fixed-size array
// runLayoutFast compares against. It returns false for anything that
// isn't exactly 16 bytes of hex — the fast path is simply skipped in that
// case, falling back to the scalar path's own (already-validated) handling.
func md5TargetBytes(targetHex string) ([16]byte, bool) {
	var t [16]byte
	b, err := hex.DecodeString(strings.TrimSpace(targetHex))
	if err != nil || len(b) != 16 {
		return t, false
	}
	copy(t[:], b)
	return t, true
}

// runBruteOrMaskLayout dispatches a brute-force or mask layout run to the
// vector fast path when it is eligible, else to the scalar runner. This is
// the only seam between the two: every other format, salt, and attack mode
// keeps exactly today's code path, since fastPathEligible returns false for
// all of them. limit (0 = unbounded) is --limit's candidate-count bound; both
// the fast and scalar paths honour it identically (see runLayout /
// runLayoutFast).
//
// A session no longer forces the scalar path. It used to, and that cost every
// resumable run roughly 10x throughput for nothing: runLayoutFast already
// maintains the same watermark, by the same cur[]-of-in-flight-chunks rule as
// runLayout, so a checkpoint means the identical thing under either runner
// and resumes correctly across both. Both runners are therefore handed to the
// SAME checkpointing core (runSessionRunner) — sess == nil simply means it
// passes a nil watermark, which is what the old fast path did by hand.
func runBruteOrMaskLayout(ctx context.Context, layout *keyspaceLayout, sess *sessionState,
	resumeFrom, limit int64, workers int, atomicAttempts *int64,
	typ, salt, targetHash string, verify func(string) bool) (string, bool, error) {

	if algo, ok := fastPathEligible(typ, salt, layout); ok {
		if target, ok := md5TargetBytes(targetHash); ok {
			return runSessionRunner(ctx, layout, sess, resumeFrom, func(watermark *int64) (string, error) {
				return runLayoutFast(ctx, layout, resumeFrom, limit, workers, atomicAttempts, watermark, algo, target)
			})
		}
	}
	return runSessionLayout(ctx, layout, sess, resumeFrom, limit, workers, atomicAttempts, verify)
}

// crackedResult carries the found password and an optional human-readable label
// describing which mangling rule produced it (empty when no rule was applied).
type crackedResult struct {
	password  string
	ruleLabel string
}

// crackCtx carries cross-cutting run state — the potfile (skip / record cracked
// hashes) and an optional resumable session — through the crack call chain.
type crackCtx struct {
	pot       *potfile
	session   *sessionState // pre-loaded saved session (may be nil)
	sessName  string        // session name; "" disables sessions
	showOnly  bool          // --show: print potfile hits only, never attack
	wordlist2 string        // combinator right-hand list ("" when unused)
	useGPU    bool          // --gpu: try raw-digest GPU dictionary/brute/mask kernels when available
	skip      int64         // --skip: candidate index (whole-layout / word index) to start at; 0 = unset
	limit     int64         // --limit: candidate count to try, 0 = unbounded
	// force is --force: start an attack the feasibility guard would otherwise
	// refuse (see checkFeasibility). The ETA is still measured and printed —
	// --force suppresses the refusal, never the honesty.
	force bool
	// princeElems is --prince-elems: the maximum number of elements PRINCE
	// concatenates into one chain. 0 means unset — see princeElemsFor, which
	// resolves it to princeDefaultElems.
	princeElems int

	// ── pipeline plumbing (--username / --left / --outfile-format) ──────────
	username bool                // --username: input lines are "user:hash"
	left     bool                // --left: report still-uncracked targets instead of/after results
	outFmt   []int               // --outfile-format field list (nil = default per-path format)
	outW     *outWriter          // shared, append-only -o writer for this run (nil when unused)
	userOf   map[string]string   // input hash -> username (only populated when username is set)
	rawOf    map[string]string   // input hash -> original input line, verbatim (for --left)
	usersOf  map[string][]string // input hash -> EVERY distinct username mapped to it, in first-seen
	// order. userOf above keeps only the last-parsed username per hash — fine
	// for display, but --single needs every account that could own a shared
	// hash (two accounts with the same weak password on an unsalted digest),
	// not just whichever line happened to be parsed last. See usernamesFor.

	// passwdGecos is --passwd's username -> GECOS map (parsePasswdGecos in
	// extract_shadow.go), consulted only by runSingleCrack (single.go) to
	// add name-derived seeds alongside the username-derived ones. nil when
	// --passwd wasn't given (or --single wasn't), which single.go treats
	// identically to "this account has no GECOS entry" — never an error and
	// never a reason to skip an account.
	passwdGecos map[string]string

	foundMu sync.Mutex
	found   map[string]bool // input hash -> cracked this run (potfile hit or freshly found)

	// ── --loopback plumbing ──────────────────────────────────────────────────
	// potPlains is a one-time snapshot of every plaintext already on record in
	// the potfile, taken at load time (newCrackCtx) — before this run cracks
	// anything of its own. --loopback seeds its first pass with these (when the
	// potfile is enabled) alongside whatever this run freshly cracks: real
	// passwords already known from this environment.
	potPlains []string

	plainsMu   sync.Mutex
	plainsSeen map[string]bool // every plaintext ever claimed for loopback (potfile seed or a fresh crack) — claimed at most once, for the life of this crackCtx
	newPlains  []string        // freshly cracked plaintexts (real attacks only, never a potfile hit) queued since the last drainNewPlains
}

// markFound records that hash was cracked (freshly, or already known via the
// potfile) — the source of truth --left consults afterward to know which
// targets are still outstanding. Safe to call on a nil *crackCtx.
func (cc *crackCtx) markFound(hash string) {
	if cc == nil {
		return
	}
	cc.foundMu.Lock()
	if cc.found == nil {
		cc.found = map[string]bool{}
	}
	cc.found[hash] = true
	cc.foundMu.Unlock()
}

func (cc *crackCtx) wasFound(hash string) bool {
	if cc == nil {
		return false
	}
	cc.foundMu.Lock()
	defer cc.foundMu.Unlock()
	return cc.found[hash]
}

// foundCount reports how many distinct hashes have been marked found so far
// this run — used by --loopback to measure how many targets a pass recovered
// (before-count vs. after-count around the pass's crackTargets call).
func (cc *crackCtx) foundCount() int {
	if cc == nil {
		return 0
	}
	cc.foundMu.Lock()
	defer cc.foundMu.Unlock()
	return len(cc.found)
}

// claimPlain marks plain as spoken for — either fed to --loopback already, or
// about to be — and reports whether THIS call is the one that claims it. A
// plaintext is claimed at most once for the life of a crackCtx, so it is
// fed to loopback's candidate stream at most once, however many times (or
// which route) it's recovered. Safe on a nil receiver.
func (cc *crackCtx) claimPlain(plain string) bool {
	if cc == nil || plain == "" {
		return false
	}
	cc.plainsMu.Lock()
	defer cc.plainsMu.Unlock()
	if cc.plainsSeen == nil {
		cc.plainsSeen = map[string]bool{}
	}
	if cc.plainsSeen[plain] {
		return false
	}
	cc.plainsSeen[plain] = true
	return true
}

// recordPlain queues a plaintext recovered by an actual attack (never a
// potfile hit — see the call sites in doCrack and runBatch) as a candidate
// for --loopback's next pass, unless this exact plaintext has already been
// claimed (fed once already, or seeded from the potfile). Safe on a nil
// receiver; a no-op when --loopback was never requested, since nothing ever
// drains newPlains in that case.
func (cc *crackCtx) recordPlain(plain string) {
	if cc == nil || !cc.claimPlain(plain) {
		return
	}
	cc.plainsMu.Lock()
	cc.newPlains = append(cc.newPlains, plain)
	cc.plainsMu.Unlock()
}

// drainNewPlains returns and clears the plaintexts queued by recordPlain
// since the last drain — exactly what's NEW since the previous --loopback
// pass. This is what guarantees the loop terminates: each pass is fed only
// this, never a running total, so a pass that finds nothing new drains empty
// and the loop stops. Safe on a nil receiver.
func (cc *crackCtx) drainNewPlains() []string {
	if cc == nil {
		return nil
	}
	cc.plainsMu.Lock()
	defer cc.plainsMu.Unlock()
	out := cc.newPlains
	cc.newPlains = nil
	return out
}

// usernameFor returns the username --username stripped from hash's input
// line, or "" when none is known (--username not set, or hash has no
// username field).
func (cc *crackCtx) usernameFor(hash string) string {
	if cc == nil || cc.userOf == nil {
		return ""
	}
	return cc.userOf[hash]
}

// usernamesFor returns EVERY distinct username mapped to hash, in first-seen
// order — unlike usernameFor, which returns only the last one parsed (fine
// for a display label, wrong for choosing single-crack candidates). Two
// accounts sharing one hash — the same weak password on an unsalted digest —
// means either login could be the real one, so --single seeds from all of
// them. Empty when --username was never set or hash carries no username.
func (cc *crackCtx) usernamesFor(hash string) []string {
	if cc == nil || cc.usersOf == nil {
		return nil
	}
	return cc.usersOf[hash]
}

// rawFor returns the original, verbatim input line for hash (used by
// --left), falling back to hash itself when no line is on record.
func (cc *crackCtx) rawFor(hash string) string {
	if cc != nil && cc.rawOf != nil {
		if r, ok := cc.rawOf[hash]; ok {
			return r
		}
	}
	return hash
}

// resultLine formats a cracked result for -o when --outfile-format is set,
// using hashField as field 1 (prefixed with the known username, if any) —
// callers keep their own path-specific default formatting when outFmt is
// unset, so an unadorned run's -o output is unchanged from before this flag
// existed.
func (cc *crackCtx) resultLine(hashKey, hashField, password string) (string, bool, error) {
	if cc == nil || len(cc.outFmt) == 0 {
		return "", false, nil
	}
	hf := hashField
	if u := cc.usernameFor(hashKey); u != "" {
		hf = u + ":" + hf
	}
	line, err := formatOutfileLine(cc.outFmt, hf, password)
	return line, true, err
}

// newCrackCtx loads the potfile (unless disabled) and any saved session. A nil
// return is never produced — a disabled potfile simply yields a nil p.pot.
func newCrackCtx(potPath string, noPot bool, sessName string, showOnly bool, wordlist2 string, useGPU bool, skip, limit int64) (*crackCtx, error) {
	cc := &crackCtx{sessName: sessName, showOnly: showOnly, wordlist2: wordlist2, useGPU: useGPU, skip: skip, limit: limit}
	if !noPot {
		p, err := loadPotfile(potPath)
		if err != nil {
			return nil, err
		}
		cc.pot = p
		// Snapshot every plaintext already on record BEFORE this run cracks
		// anything of its own — --loopback's potfile-sourced seed (see
		// potPlains' doc comment). Taken here, at load time, so it can never
		// include this run's own fresh cracks (which land in p.seen too, via
		// potfile.add, as the run progresses).
		cc.potPlains = p.allPlains()
	}
	if sessName != "" {
		s, err := loadSession(sessName)
		if err != nil {
			return nil, err
		}
		cc.session = s
	}
	return cc, nil
}

// ── -o output: fixing the truncation bug, plus --outfile-format ────────────
//
// Every write to -o used to be its own os.WriteFile call, which O_TRUNCs the
// file. That's harmless when exactly one call ever happens, but a multi-target
// run makes several calls against the SAME file over its lifetime — once per
// batch-mode group, once per per-target crack — and each one destroyed every
// result written before it, leaving only whichever call ran last. outWriter
// opens the file once (truncating exactly once, at the start of the run) and
// appends every subsequent line, so nothing already written is lost.

type outWriter struct {
	mu sync.Mutex
	f  *os.File
}

// newOutWriter opens path for a fresh run (path == "" yields a nil, no-op
// writer — every method below tolerates a nil receiver).
func newOutWriter(path string) (*outWriter, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &outWriter{f: f}, nil
}

func (w *outWriter) writeLine(line string) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := fmt.Fprintln(w.f, line)
	return err
}

func (w *outWriter) Close() error {
	if w == nil {
		return nil
	}
	return w.f.Close()
}

// formatOutfileLine renders one -o line for --outfile-format: hashcat's
// numbered field selection. Hashsmith currently supports:
//
//	1 = hash       the target as it was tested (username-prefixed under --username)
//	2 = plain      the recovered plaintext
//	3 = hex_plain  the recovered plaintext, hex-encoded
//
// Fields are joined with ':', matching hashcat's own outfile-format output.
func formatOutfileLine(fields []int, hashField, password string) (string, error) {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		switch f {
		case 1:
			parts = append(parts, hashField)
		case 2:
			parts = append(parts, password)
		case 3:
			parts = append(parts, hex.EncodeToString([]byte(password)))
		default:
			return "", fmt.Errorf("--outfile-format: unsupported field %d — hashsmith supports "+
				"1=hash, 2=plain, 3=hex_plain", f)
		}
	}
	return strings.Join(parts, ":"), nil
}

// parseOutfileFormat parses --outfile-format's "N[,N...]" value. An empty
// string (the flag not given) yields a nil slice — every caller treats that as
// "use my existing default format", never an error.
func parseOutfileFormat(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("--outfile-format: invalid field %q: not a number", p)
		}
		switch n {
		case 1, 2, 3:
			out = append(out, n)
		default:
			return nil, fmt.Errorf("--outfile-format: unsupported field %d — hashsmith supports "+
				"1=hash, 2=plain, 3=hex_plain", n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("--outfile-format: no fields given")
	}
	return out, nil
}

// ── --username: "user:hash" input ───────────────────────────────────────────
//
// hashcat splits a "user:hash" input line on the FIRST colon only, with
// everything after it — further colons included — treated as the hash. That
// matters here because hashsmith supports 461 formats and many embed colons in
// the target itself: salted digests ("hash:salt"), IKE, IPMI, CHAP, CMS,
// 1Password and others. Splitting anywhere but the first colon would slice a
// legitimate hash in half.

// inputLine pairs one gathered input with what --username peeled off it.
type inputLine struct {
	raw      string // the original line, verbatim — what --left re-emits
	hash     string // the value actually cracked
	username string // "" when the line had no username field
}

// splitUsername implements the first-colon-only split. A line with no colon
// at all has no username (the whole line is the hash) — hashcat's behavior
// for a plain hash list even when --username is on.
func splitUsername(raw string) (username, hash string) {
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		return "", raw
	}
	return raw[:i], raw[i+1:]
}

// looksLikeValidTarget reports whether hash parses as a plausible target for
// typ (or, when typ is "" / "auto", for ANY type detection recognizes) — the
// same up-front check doCrack itself relies on (see verifyCandidate probing
// there), reused here so a misuse of --username can be refused before an
// attack ever starts.
func looksLikeValidTarget(hash, typ, salt, saltMode string) bool {
	if typ != "" && !strings.EqualFold(typ, "auto") {
		_, err := verifyCandidate("hashsmith-probe", hash, typ, salt, saltMode)
		return err == nil
	}
	return len(detectHashTypes(hash)) > 0
}

// parseUsernameLines applies --username's split to every gathered input line.
//
// THE TRAP: many of hashsmith's formats already put a colon in a
// username-less target — "hash:salt" for salted digests, plus IKE, IPMI,
// CHAP, CMS, 1Password and others. Run --username against one of those and
// the hash becomes the "username" while the salt becomes a bogus "hash": every
// target then fails to crack, reported only as an unremarkable "Not found",
// with nothing pointing at the real cause. So a split hash portion that
// doesn't look like a valid target for the resolved type is refused outright
// here, before any cracking starts, rather than left to silently fail later.
func parseUsernameLines(raws []string, typ, salt, saltMode string) ([]inputLine, error) {
	lines := make([]inputLine, 0, len(raws))
	for _, raw := range raws {
		r := strings.TrimSpace(raw)
		user, hash := splitUsername(r)
		if user != "" && !looksLikeValidTarget(hash, typ, salt, saltMode) {
			return nil, fmt.Errorf("--username: after splitting %q on its first ':', %q doesn't "+
				"look like a valid hash — if this line has no username, drop --username; if "+
				"auto-detection is guessing wrong, pass -t explicitly (refusing rather than "+
				"silently treating %q as a username and %q as the hash)", r, hash, user, hash)
		}
		lines = append(lines, inputLine{raw: r, hash: hash, username: user})
	}
	return lines, nil
}

// ── CLI entry ────────────────────────────────────────────────────────────────

func runCrack(args []string) error {
	fs := flag.NewFlagSet("crack", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "hash type (omit or 'auto' to auto-detect)")
	mode := fs.String("M", "dict", "attack mode: dict|brute")
	wordlist := fs.String("w", "", "wordlist path (dict mode; auto-detects an installed rockyou.txt, else the built-in common.txt — see `hashsmith wordlists`)")
	wordlistLong := fs.String("wordlist", "", "alias for -w")
	noAutoWordlist := fs.Bool("no-auto-wordlist", false, "skip wordlist auto-detection and use the built-in common.txt, for scripted runs that need the same keyspace on every machine (ignored when -w is given, which never auto-detects anyway)")
	charset := fs.String("C", "abcdefghijklmnopqrstuvwxyz0123456789", "charset (brute mode)")
	minLen := fs.Int("n", 1, "min length (brute)")
	maxLen := fs.Int("x", 4, "max length (brute)")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode: prefix|suffix")
	workers := fs.Int("p", 0, "parallel workers (0 = NumCPU)")
	outFile := fs.String("o", "", "write result to file")
	copyResult := fs.Bool("c", false, "copy result to clipboard")
	useRules := fs.Bool("r", false, "enable the built-in mangling rules in dict mode")
	var rulesFiles stringSliceFlag
	fs.Var(&rulesFiles, "rules", "path to a rule file (dict mode; overrides -r); repeatable to stack rule files left-to-right, e.g. --rules a.rule --rules b.rule")
	maskStr := fs.String("mask", "", "mask for -M mask (e.g. ?u?l?l?l?d?d)")
	cs1 := fs.String("1", "", "custom charset 1 (mask -1)")
	cs2 := fs.String("2", "", "custom charset 2 (mask -2)")
	cs3 := fs.String("3", "", "custom charset 3 (mask -3)")
	cs4 := fs.String("4", "", "custom charset 4 (mask -4)")
	increment := fs.Bool("increment", false, "mask increment mode (try shorter lengths first)")
	maskFirst := fs.Bool("mask-first", false, "hybrid mode: place the mask before the word (mask+word)")
	potPath := fs.String("pot", "", "potfile path (default ~/.hashsmith/hashsmith.pot)")
	noPot := fs.Bool("no-pot", false, "disable the potfile (do not read or record cracked hashes)")
	showOnly := fs.Bool("show", false, "print already-cracked hashes from the potfile; do not attack")
	sessName := fs.String("session", "", "named resumable session (brute/mask/markov/hybrid/combinator/prince)")
	restore := fs.String("restore", "", "alias for --session: resume a saved session by name")
	wordlist2 := fs.String("wordlist2", "", "right-hand wordlist for -M combinator")
	w2 := fs.String("w2", "", "alias for --wordlist2")
	princeElems := fs.Int("prince-elems", princeDefaultElems, "maximum elements concatenated into one chain (-M prince)")
	stdoutMode := fs.Bool("stdout", false, "emit the candidate stream to stdout instead of cracking (no hash needed)")
	useGPU := fs.Bool("gpu", false, "use GPU dictionary/brute/mask kernels when supported")
	keyspaceOnly := fs.Bool("keyspace", false, "print the total candidate count to stdout and exit, without attacking (dict mode: word count, not words×rules — matches --skip/--limit's unit)")
	skip := fs.Int64("skip", 0, "distributed cracking: start at candidate index N (whole-layout index, hashcat-style; word index in dict mode, where a word's whole rule expansion stays in its slice)")
	limit := fs.Int64("limit", 0, "distributed cracking: try at most N candidates from --skip, then stop (0 = unbounded; N words in dict mode, each with its full rule expansion)")
	username := fs.Bool("username", false, "input lines are \"user:hash\" (split on the FIRST colon only); show the username with each result")
	left := fs.Bool("left", false, "write still-uncracked targets, in their original input form, to -o or stdout — for a second pass")
	outfileFormat := fs.String("outfile-format", "", "comma-separated -o field selection, hashcat-style: 1=hash, 2=plain, 3=hex_plain (default: unchanged from before this flag existed)")
	loopback := fs.Bool("loopback", false, "after the main attack, feed newly cracked plaintexts (plus, if the potfile is enabled, plaintexts already on record there) back as dict-mode candidates against any still-uncracked targets, with --rules/-r applied; repeats until a pass finds nothing new")
	single := fs.Bool("single", false, "single-crack mode: before the main attack, try candidates derived from each account's own username (via --username), tried only against that account's hash — with --rules/-r applied; requires --username")
	force := fs.Bool("force", false, "start an attack even when the feasibility guard estimates it cannot finish (the ETA is still measured and printed)")
	passwdPath := fs.String("passwd", "", "optional /etc/passwd-format file for --single: also derive candidates from each account's GECOS/real-name field (\"John Smith\" -> jsmith, johns, smithj, john.smith, ...), tried only against that account's hash; unused without --single")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	// A negative --skip/--limit has no meaning (both are counts/indices into a
	// non-negative keyspace); *runLayout already clamps a negative resumeFrom
	// to 0 and treats a non-positive limit as unbounded, so a typo'd negative
	// value would silently mean "start from the beginning" / "do everything" —
	// the opposite of a deliberate distributed slice. Reject it outright.
	if *skip < 0 {
		return fmt.Errorf("--skip must not be negative (got %d)", *skip)
	}
	if *limit < 0 {
		return fmt.Errorf("--limit must not be negative (got %d)", *limit)
	}

	// --single derives its candidates from each account's login name — with
	// no --username there are no usernames to derive them from. Refuse
	// outright rather than silently running zero single-crack passes and
	// reporting "not found": that failure mode (a flag that looks honored but
	// quietly does nothing) is exactly what this project keeps finding bugs
	// in, so make the missing prerequisite loud instead.
	if *single && !*username {
		return fmt.Errorf("--single requires --username (its candidates come from each " +
			"account's login name, so there must be a username to derive them from)")
	}

	// --passwd only feeds --single (see runSingleCrack / gecosSeeds in
	// single.go); using it without --single isn't wrong, just pointless. Say
	// so instead of silently accepting and ignoring it — the same "make a
	// no-op loud" principle behind the --single-without-username refusal
	// above, just a warning rather than a refusal since --passwd genuinely
	// has no other job to do here.
	if *passwdPath != "" && !*single {
		clrYellow.Fprintln(os.Stderr, "--passwd given without --single; ignored "+
			"(GECOS-derived seeds only apply to --single)")
	}

	// Resolve wordlist from either -w or its --wordlist alias. An empty value
	// falls through to the built-in common.txt inside doCrack/dictAttack.
	wl := *wordlist
	if wl == "" {
		wl = *wordlistLong
	}
	wl2 := *wordlist2
	if wl2 == "" {
		wl2 = *w2
	}

	// Resolve the wordlist ONCE, here, before anything reads it. Everything
	// downstream — the pre-count that sizes the progress bar, the feasibility
	// ETA, --keyspace, --stdout and the attack itself — receives the resolved
	// path, so they all describe the same list. Resolving lower down (per
	// target, or inside dictAttack) would let the ETA be computed from the
	// embedded default's 230,930 words while the attack actually ran a
	// 14M-word rockyou, which is exactly the kind of confidently wrong number
	// the feasibility guard exists to prevent.
	wlChoice, err := resolveWordlistForMode(*mode, wl, *noAutoWordlist)
	if err != nil {
		return err
	}
	wl = wlChoice.path

	// A distributed slice built on a per-machine default does not line up.
	if warn := distributedWordlistWarning(wlChoice, *skip, *limit, *keyspaceOnly); warn != "" {
		clrYellow.Fprintln(os.Stderr, warn)
	}

	mc := buildMaskConfig(*maskStr, *cs1, *cs2, *cs3, *cs4, *increment, *minLen, *maskFirst)

	// --keyspace: report the total candidate count and exit — no target or
	// hashing required, and no attack runs. Handled before --stdout / gatherInputs
	// so it works with or without a hash argument.
	if *keyspaceOnly {
		return printKeyspace(*mode, wl, wl2, *charset, *minLen, *maxLen, *princeElems, mc)
	}

	// --stdout: generate candidates only, no target or hashing required.
	if *stdoutMode {
		engine, err := buildRuleEngine(rulesFiles.values, *useRules)
		if err != nil {
			return err
		}
		return streamCandidates(*mode, wl, wl2, *charset, *minLen, *maxLen, *princeElems, mc, engine, *skip, *limit)
	}

	outFmt, err := parseOutfileFormat(*outfileFormat)
	if err != nil {
		return err
	}

	rawInputs, err := gatherInputs(fs.Args())
	if err != nil {
		return err
	}

	// --username: split every line on its FIRST colon only (everything after,
	// further colons included, is the hash — see parseUsernameLines). Refuses
	// outright when a split hash portion doesn't look like a valid target, so a
	// username-less "hash:salt" line misused with --username fails loudly
	// instead of silently cracking garbage.
	var lines []inputLine
	if *username {
		lines, err = parseUsernameLines(rawInputs, *typ, *salt, *saltMode)
		if err != nil {
			return err
		}
	} else {
		lines = make([]inputLine, len(rawInputs))
		for i, r := range rawInputs {
			t := strings.TrimSpace(r)
			lines[i] = inputLine{raw: t, hash: t}
		}
	}
	targets := make([]string, len(lines))
	for i, l := range lines {
		targets[i] = l.hash
	}

	w := *workers
	if w < 1 {
		w = runtime.NumCPU()
	}
	sn := *sessName
	if sn == "" {
		sn = *restore
	}
	cc, err := newCrackCtx(*potPath, *noPot, sn, *showOnly, wl2, *useGPU, *skip, *limit)
	if err != nil {
		return err
	}
	cc.princeElems = *princeElems
	cc.force = *force
	cc.username = *username
	cc.left = *left
	cc.outFmt = outFmt
	cc.userOf = map[string]string{}
	cc.rawOf = map[string]string{}
	cc.usersOf = map[string][]string{}
	seenUser := map[string]map[string]bool{} // hash -> username -> already recorded
	for _, l := range lines {
		cc.rawOf[l.hash] = l.raw
		if l.username != "" {
			cc.userOf[l.hash] = l.username
			if seenUser[l.hash] == nil {
				seenUser[l.hash] = map[string]bool{}
			}
			if !seenUser[l.hash][l.username] {
				seenUser[l.hash][l.username] = true
				cc.usersOf[l.hash] = append(cc.usersOf[l.hash], l.username)
			}
		}
	}

	// --passwd: build the username -> GECOS map --single consults for
	// name-derived seeds (single.go's gecosSeeds). Parsed only when --single
	// is actually on — the warning above already told the operator --passwd
	// is a no-op otherwise, so there is nothing to gain by opening the file
	// in that case. A read failure here (bad path, unreadable file) fails
	// the whole run loudly, same as any other input file this command reads.
	if *single && *passwdPath != "" {
		gecos, gerr := parsePasswdGecos(*passwdPath)
		if gerr != nil {
			return fmt.Errorf("--passwd: %w", gerr)
		}
		cc.passwdGecos = gecos
	}

	// -o's role changes under --left: it becomes the destination for the
	// leftover-target list (written once, after the whole run) rather than the
	// per-result writer, so the two purposes can't jumble into one file.
	// Without --left, -o keeps writing results exactly as before — just
	// through a single append-only handle (outWriter) instead of one
	// truncating os.WriteFile call per result, which used to destroy every
	// earlier result in a multi-target run.
	if !*left {
		ow, err := newOutWriter(*outFile)
		if err != nil {
			return err
		}
		cc.outW = ow
		defer ow.Close()
	}

	engine, err := buildRuleEngine(rulesFiles.values, *useRules)
	if err != nil {
		return err
	}

	// --single runs BEFORE the main attack: it is cheap (a handful of
	// per-account candidates) and high-yield (login-derived passwords are the
	// common case), so trying it first means the main attack never burns its
	// full keyspace re-discovering what single-crack already found. Only
	// targets it doesn't crack are handed to the main attack below — see
	// runSingleCrack's doc comment for why per-target isolation is structural
	// there, not a filter applied after the fact.
	if *single {
		if err := runSingleCrack(lines, *typ, w, *salt, *saltMode, *outFile, *copyResult, engine, cc); err != nil {
			return err
		}
		targets = remainingTargets(lines, cc)
	}

	runErr := crackTargets(targets, *typ, *mode, wl, *charset,
		*minLen, *maxLen, w, *salt, *saltMode, *outFile, *copyResult, engine, mc, cc)
	if runErr != nil {
		return runErr
	}

	if *loopback {
		if err := runLoopback(lines, *typ, w, *salt, *saltMode, *outFile, *copyResult, engine, cc); err != nil {
			return err
		}
	}
	if *single || *loopback {
		// crackTargets/runBatch only ever SET exitCode = 1 (once, on their own
		// call's uncracked count) — never clear it back to 0. --single's own
		// per-target crackTargets calls (in runSingleCrack) can set it for a
		// target the MAIN attack then goes on to crack, and the same is true
		// of the main attack relative to --loopback — so whichever ran first
		// can leave a stale failure behind. Recompute from the final state
		// instead of trusting whichever call happened to run last.
		if len(remainingTargets(lines, cc)) == 0 {
			exitCode = 0
		} else {
			exitCode = 1
		}
	}

	if cc.left {
		var leftover []string
		for _, l := range lines {
			if !cc.wasFound(l.hash) {
				leftover = append(leftover, l.raw)
			}
		}
		return writeLeftover(leftover, *outFile)
	}
	return nil
}

// writeLeftover emits --left's still-uncracked targets, one original input
// line per line, to outFile (or stdout when outFile is ""). This is the whole
// point of --left: piped or saved back into a second `hashsmith crack` run, it
// must reproduce exactly the set of targets that didn't crack this time —
// no more, no fewer — so a pipeline can iterate without losing or duplicating
// work.
func writeLeftover(leftover []string, outFile string) error {
	var buf strings.Builder
	for _, l := range leftover {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	if outFile == "" {
		fmt.Print(buf.String())
		return nil
	}
	if err := os.WriteFile(outFile, []byte(buf.String()), 0644); err != nil {
		return err
	}
	clrGreen.Fprintf(os.Stderr, "Wrote %d uncracked target(s) to %s\n", len(leftover), outFile)
	return nil
}

// ── --loopback: feed cracked plaintexts back as candidates ─────────────────
//
// Multi-hash mode (batch.go) already hashes each candidate once and checks it
// against every salt-independent raw-digest target in ONE pass — "crack one,
// try it against the rest" is already free there. What --loopback adds is
// different: it carries a plaintext recovered from one hash INTO A NEW PASS,
// where --rules can mutate it ("summer2024" -> "Summer2024!") to reach a
// target the base word alone never would — and it does that for salted /
// expensive targets too, which run per-target and get none of multi-hash
// mode's benefit.
//
// Termination: every pass is fed ONLY cc.drainNewPlains() — the plaintexts
// claimed (via cc.recordPlain, itself gated by cc.claimPlain) since the
// PREVIOUS drain, never a running total. claimPlain also guarantees a given
// plaintext string is claimed at most once for the whole run, however many
// times or routes it's recovered by — so the total candidate material
// available to ever feed a pass is bounded by (targets cracked this run +
// pre-existing potfile entries), a fixed, finite quantity. A pass that
// recovers nothing new therefore drains empty, which ends the loop; the
// bounded pool guarantees that outcome is reached in finitely many passes.
func runLoopback(lines []inputLine, typ string, workers int, salt, saltMode, outFile string,
	copyResult bool, rules *ruleEngine, cc *crackCtx) error {
	// --show never attacks (see crackTargets' showOnly gate) — --loopback must
	// not either.
	if cc == nil || cc.showOnly {
		return nil
	}

	// Seed pass 1: this run's own fresh cracks (from the main attack, already
	// queued via recordPlain) plus, if the potfile is enabled, every plaintext
	// already on record before this run started (potPlains — see crackCtx).
	// claimPlain dedupes across both sources so nothing is fed twice.
	var feed []string
	for _, p := range cc.potPlains {
		if cc.claimPlain(p) {
			feed = append(feed, p)
		}
	}
	feed = append(feed, cc.drainNewPlains()...)

	pass := 0
	for len(feed) > 0 {
		// Defensive backstop, not a limit on legitimate work. Termination is
		// guaranteed by claimPlain: each plaintext is fed at most once ever, and
		// the total feedable material is bounded by (targets cracked + potfile
		// entries), so a correct run stops long before this. But a future
		// regression in the claim/drain bookkeeping would otherwise surface as a
		// HANG — caught only by an outer test timeout or, for a user, as an
		// apparently frozen tool. Failing loudly beats spinning silently.
		if pass >= maxLoopbackPasses {
			return fmt.Errorf("loopback exceeded %d passes — refusing to continue; "+
				"this indicates a bug in the recovered-plaintext bookkeeping, since "+
				"each plaintext should be fed at most once", maxLoopbackPasses)
		}
		remaining := remainingTargets(lines, cc)
		if len(remaining) == 0 {
			break
		}
		pass++
		tmp, err := writeTempWordlist(feed)
		if err != nil {
			return fmt.Errorf("--loopback: %w", err)
		}
		color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
			"\n◇ Loopback pass %d: %d candidate plaintext(s) (dict mode) against %d still-uncracked target(s)\n",
			pass, len(feed), len(remaining))

		// --skip/--limit bound the MAIN attack's keyspace slice for
		// distributed cracking. A loopback pass draws from a completely
		// different, self-contained candidate source — the plaintexts just
		// recovered — not a slice of the original keyspace, so slicing it by
		// the main attack's indices would be meaningless at best (a small
		// list, most of it skipped) and silently wrong at worst (dropping
		// candidates a split run's OTHER machines have no way to try instead,
		// since each machine only loops back over what it personally
		// cracked). So every loopback pass runs unbounded, regardless of
		// --skip/--limit on the main run.
		savedSkip, savedLimit := cc.skip, cc.limit
		cc.skip, cc.limit = 0, 0
		before := cc.foundCount()
		runErr := crackTargets(remaining, typ, "dict", tmp, "", 0, 0, workers,
			salt, saltMode, outFile, copyResult, rules, nil, cc)
		cc.skip, cc.limit = savedSkip, savedLimit
		os.Remove(tmp)
		if runErr != nil {
			return runErr
		}
		newly := cc.foundCount() - before
		clrGreen.Fprintf(os.Stderr, "  loopback pass %d: %d new target(s) cracked\n", pass, newly)

		feed = cc.drainNewPlains()
	}
	if pass > 0 {
		clrGreen.Fprintf(os.Stderr, "Loopback: %d pass(es) run\n", pass)
	}
	return nil
}

// maxLoopbackPasses bounds runLoopback defensively. See the check in the pass
// loop for why a cap exists even though termination is already guaranteed.
const maxLoopbackPasses = 256

// remainingTargets returns the hash (not raw-line) form of every input line
// not yet marked found — --loopback's per-pass target list, and what --left
// consults too (via cc.wasFound directly) for the final leftover report.
func remainingTargets(lines []inputLine, cc *crackCtx) []string {
	var out []string
	for _, l := range lines {
		if !cc.wasFound(l.hash) {
			out = append(out, l.hash)
		}
	}
	return out
}

// writeTempWordlist writes words, one per line, to a fresh temp file so
// --loopback can feed them through the existing dict-mode engine, which only
// ever reads a wordlist from a path. The caller removes the file once the
// pass finishes.
func writeTempWordlist(words []string) (string, error) {
	f, err := os.CreateTemp("", "hashsmith-loopback-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	for _, word := range words {
		if _, err := bw.WriteString(word); err != nil {
			return "", err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return "", err
		}
	}
	if err := bw.Flush(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// buildRuleEngine selects the mangling-rule source: one or more compiled rule
// files when given (reporting any skipped invalid rules; 2+ files are stacked
// as a cross product — see loadRuleFiles/expandStacked), else the built-in set
// when -r is present, else nil (no rules). A single rulesFiles entry produces
// output byte-identical to before stacking existed.
func buildRuleEngine(rulesFiles []string, useBuiltin bool) (*ruleEngine, error) {
	if len(rulesFiles) > 0 {
		e, bad, err := loadRuleFiles(rulesFiles)
		if err != nil {
			return nil, err
		}
		var msg string
		if len(rulesFiles) == 1 {
			msg = fmt.Sprintf("Loaded %d rules from %s", e.count(), rulesFiles[0])
		} else {
			msg = fmt.Sprintf("Loaded stacked rules from %s: %d candidates per word",
				strings.Join(rulesFiles, " + "), e.count())
		}
		if bad > 0 {
			msg += fmt.Sprintf(" (%d invalid rule(s) skipped)", bad)
		}
		clrGreen.Fprintln(os.Stderr, msg)
		return e, nil
	}
	if useBuiltin {
		return builtinRuleEngine(), nil
	}
	return nil, nil
}

// crackTargets runs crackWithDetection over one or more targets, printing a
// header for each when several were supplied.
func crackTargets(targets []string, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool, rules *ruleEngine, mc *maskConfig, cc *crackCtx) error {
	// Multi-hash acceleration: when several salt-independent raw-digest targets
	// are given, hash each candidate once and check it against all of them. Only
	// the targets multi-hash mode cannot handle are returned for per-target work.
	// --skip/--limit are not (yet) threaded through this shared-candidate path,
	// so a distributed slice takes the slower but correct per-target path instead
	// of silently attacking the whole keyspace against every target.
	skipLimitSet := cc != nil && (cc.skip != 0 || cc.limit != 0)
	showOnly := cc != nil && cc.showOnly
	uncracked := 0
	// --show never attacks (it only reports potfile hits) — the per-target
	// loop below already honors that via crackWithDetection's showOnly check,
	// but runBatch does not, so a multi-target --show run must skip the batch
	// path entirely rather than silently launching a real attack.
	if len(targets) > 1 && salt == "" && !skipLimitSet && !showOnly {
		var nb int
		var berr error
		targets, nb, berr = runBatch(targets, typ, mode, wordlist, charset,
			minLen, maxLen, workers, saltMode, outFile, copyResult, rules, mc, cc)
		uncracked += nb
		if berr != nil {
			if uncracked > 0 {
				exitCode = 1
			}
			return berr
		}
		if len(targets) == 0 {
			if uncracked > 0 {
				exitCode = 1
			}
			return nil
		}
		color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
			"\n── %d target(s) need per-hash cracking (salted / non-raw types)\n", len(targets))
	}
	for i, tgt := range targets {
		if len(targets) > 1 {
			color.New(themeAttr, color.Bold).Fprintf(os.Stderr,
				"\n══ [%d/%d] %s\n", i+1, len(targets), tgt)
		}
		found, err := crackWithDetection(tgt, typ, mode, wordlist, charset,
			minLen, maxLen, workers, salt, saltMode, outFile, copyResult, rules, mc, cc)
		if err != nil {
			// Same reasoning as crackWithDetection's: a refusal applies to the
			// attack itself, so every remaining target would be refused too.
			if len(targets) == 1 || isFeasibilityRefusal(err) {
				return err
			}
			clrRed.Fprintf(os.Stderr, "  error: %v\n", err)
			uncracked++
			continue
		}
		if !found {
			uncracked++
		}
	}
	if uncracked > 0 {
		exitCode = 1
	}
	return nil
}

// ── Core engine ──────────────────────────────────────────────────────────────

// doCrack runs a single attack for one concrete hash type and reports whether
// the password was found. It never prints "Not found" itself — the caller
// decides how to report failure (important when several candidate types are
// tried in sequence).
func doCrack(targetHash, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool, rules *ruleEngine, mc *maskConfig, cc *crackCtx) (bool, error) {

	start := time.Now()
	var atomicAttempts int64

	// Validate the type and hash format up front. The per-candidate verify loops
	// ignore errors for speed, so without this an unknown type or malformed hash
	// would silently "find nothing"; probing once surfaces it as a real error.
	if _, err := verifyCandidate("hashsmith-probe", targetHash, typ, salt, saltMode); err != nil {
		return false, err
	}

	// ── attack setup: session resume + --skip/--limit ───────────────────────
	// A named session installs a SIGINT handler so Ctrl-C checkpoints progress
	// and exits cleanly; without one the run uses a plain background context.
	// This is resolved before the pre-count below so the progress bar can be
	// sized to what --limit will actually bound, not the full keyspace.
	m := strings.ToLower(mode)
	runCtx := context.Background()
	var sess *sessionState
	var resumeFrom int64
	if cc != nil && cc.sessName != "" && (m == "brute" || m == "mask" || m == "markov" || m == "hybrid" || m == "combinator" || m == "prince") {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() { <-sigCh; cancel() }()
		defer func() { signal.Stop(sigCh); cancel() }()

		maskStr, custom, inc := "", [4]string{}, false
		if mc != nil {
			maskStr, custom, inc = mc.mask, mc.custom, mc.increment
		}
		wl2 := cc.wordlist2
		pe := princeElemsFor(cc)
		if cc.session.matches(m, typ, targetHash, charset, minLen, maxLen, maskStr, custom, inc, salt, saltMode, wordlist, wl2, pe) {
			sess = cc.session
			resumeFrom = sess.Checkpoint
			if resumeFrom > 0 {
				clrYellow.Fprintf(os.Stderr, "Resuming session %q from index %d of %d\n",
					cc.sessName, resumeFrom, sess.Total)
			}
		} else {
			sess = &sessionState{
				Name: cc.sessName, Mode: m, Type: typ, Target: targetHash,
				Charset: charset, MinLen: minLen, MaxLen: maxLen,
				Mask: maskStr, Custom: custom, Increment: inc,
				Salt: salt, SaltMode: saltMode, Wordlist: wordlist, Wordlist2: wl2,
				PrinceElems: pe,
				path:        sessionPath(cc.sessName),
			}
		}
	}

	// --skip (distributed cracking) vs. a resumed session's saved checkpoint:
	// an explicit --skip wins. --skip 0 is indistinguishable from "not passed"
	// (0 is also its unset default), so it only ever narrows/relocates a run —
	// it can't be used to force a session back to index 0; use
	// `hashsmith sessions rm <name>` for that.
	var limit int64
	if cc != nil {
		limit = cc.limit
		if cc.skip != 0 {
			if resumeFrom != 0 {
				clrYellow.Fprintf(os.Stderr,
					"--skip %d overrides session %q's saved checkpoint (%d)\n",
					cc.skip, cc.sessName, resumeFrom)
			}
			resumeFrom = cc.skip
		}
	}

	// ── pre-count for progress bar ──────────────────────────────────────────
	// boundWordIdx narrows a raw count n (counted in the same index space as
	// resumeFrom/limit — word indices for dict, candidate indices everywhere
	// else) to what this run will actually attempt: min(n, resumeFrom+limit) -
	// resumeFrom, clamped to [0, n]. A no-op when unbounded (limit == 0) or n is
	// the "unknown / not countable" sentinel (-1), so a run without --limit
	// shows exactly the total it always has.
	boundWordIdx := func(n int64) int64 {
		if n < 0 || limit <= 0 {
			return n
		}
		bound := n
		if b := satAdd(resumeFrom, limit); b < bound {
			bound = b
		}
		remaining := bound - resumeFrom
		if remaining < 0 {
			remaining = 0
		}
		return remaining
	}

	// PRINCE builds its chain table up front: it is needed both to size the
	// progress bar and to run the attack, and building it twice would re-read
	// and re-bucket the whole element list. Errors here (an oversized element
	// list, an unenumerable chain count, a bad -n/-x range) surface before the
	// progress bar and ticker exist, so there is nothing to tear down.
	var princeLay *keyspaceLayout
	var princeExact *big.Int
	if m == "prince" {
		elems, _, e := loadWordlistSlice(wordlist)
		if e != nil {
			return false, e
		}
		princeLay, princeExact, e = princeLayout(elems, minLen, maxLen, princeElemsFor(cc))
		if e != nil {
			return false, e
		}
	}

	var total int64 = -1
	if m == "dict" {
		// An empty wordlist path counts the embedded common.txt. Bound the raw
		// word count BEFORE the rules multiplier: --limit's dict-mode semantics
		// count base words, not rule-mangled variants.
		if n, err := countWordlistLines(wordlist); err == nil {
			total = boundWordIdx(n)
			if rules != nil {
				// Each word generates up to rules.count() extra candidates.
				total = satMul(total, int64(1+rules.count()))
			}
		}
	} else if m == "brute" || m == "markov" {
		total = boundWordIdx(calcBruteTotal(charset, minLen, maxLen))
		if exact, overflowed := calcBruteTotalExact(charset, minLen, maxLen); overflowed {
			warnKeyspaceNotExhaustive(exact)
		}
	} else if m == "mask" && mc != nil {
		total = boundWordIdx(calcMaskTotal(mc))
		if exact, overflowed := calcMaskTotalExact(mc); overflowed {
			warnKeyspaceNotExhaustive(exact)
		}
	} else if m == "hybrid" && mc != nil {
		if n, err := countWordlistLines(wordlist); err == nil {
			if sets, e := parseMask(mc); e == nil {
				total = boundWordIdx(satMul(n, maskKeyspace(sets)))
			}
		}
	} else if m == "combinator" && cc != nil && cc.wordlist2 != "" {
		if a, e1 := countWordlistLines(wordlist); e1 == nil {
			if b, e2 := countWordlistLines(cc.wordlist2); e2 == nil {
				total = boundWordIdx(satMul(a, b))
			}
		}
	} else if m == "prince" && princeLay != nil {
		total = boundWordIdx(princeLay.total)
		if princeExact != nil && princeExact.Cmp(maxInt64Big) > 0 {
			warnKeyspaceNotExhaustive(princeExact)
		}
	}

	// ── run feasibility guard ───────────────────────────────────────────────
	// total is exactly the work THIS run will attempt, which is what the ETA
	// has to be measured over:
	//
	//   - boundWordIdx has already narrowed it to the --skip/--limit slice. A
	//     distributed job splits an enormous keyspace across many machines and
	//     each slice is perfectly feasible, so estimating from the full
	//     keyspace would refuse every distributed run.
	//   - In dict mode it has already been multiplied by the rule expansion
	//     (1 + rules.count(), the product for stacked rule files). --keyspace
	//     deliberately reports the WORD count instead, without that multiplier,
	//     because that is --skip/--limit's unit — slicing moves whole words,
	//     each carrying its full rule expansion (see printKeyspace and
	//     TestKeyspaceUnitIsSkipStepsToCoverDictRun). So --keyspace and this
	//     ETA disagree on purpose: --keyspace is about slicing, the ETA is
	//     about time, and time is words x rules.
	//
	// This runs after every setup error above and before the progress bar, so a
	// refused run has started nothing and has nothing to tear down.
	if err := checkFeasibility(total, resumeFrom != 0 || limit > 0,
		typ, targetHash, salt, saltMode, workers, cc != nil && cc.force); err != nil {
		return false, err
	}

	bar := newCrackBar(total)

	// progress ticker — updates bar from atomic counter every 100 ms
	tickCtx, tickCancel := context.WithCancel(context.Background())
	go progressTicker(tickCtx, bar, &atomicAttempts)

	verifyFn := func(c string) bool {
		ok, _ := verifyCandidate(c, targetHash, typ, salt, saltMode)
		return ok
	}
	// Zero-allocation fast path for salt-independent raw digests (md5, sha*,
	// ntlm, …): hash straight into a stack buffer and compare bytes, avoiding a
	// hex-encode and heap allocation on every candidate.
	if salt == "" {
		if fv, ok := newFastVerifier(typ, targetHash); ok {
			verifyFn = fv.match
		}
	}

	var (
		result      crackedResult
		err         error
		interrupted bool
	)
	// GPU kernels (dict/brute/mask) don't yet accept a resume/limit bound, so a
	// --skip/--limit run always takes the CPU path, which does.
	gpuBounded := resumeFrom == 0 && limit == 0
	switch m {
	case "dict":
		// An empty wordlist path uses the built-in common.txt (see openWordlist).
		if cc != nil && cc.useGPU && gpuBounded && salt == "" && typ == "md5" {
			var usedGPU bool
			result, err, usedGPU = gpuDictAttack(runCtx, wordlist, targetHash, rules, &atomicAttempts)
			if !usedGPU {
				_, reason := activeGPUBackend()
				clrYellow.Fprintf(os.Stderr, "GPU dictionary unavailable (%s) — using CPU\n", reason)
				result, err = dictAttack(runCtx, wordlist, resumeFrom, limit, workers, &atomicAttempts, rules, verifyFn)
			}
		} else {
			if cc != nil && cc.useGPU {
				if !gpuBounded {
					clrYellow.Fprintf(os.Stderr, "GPU dictionary does not support --skip/--limit yet — using CPU\n")
				} else {
					clrYellow.Fprintf(os.Stderr, "GPU dictionary currently supports unsalted MD5; using CPU for %s\n", typ)
				}
			}
			result, err = dictAttack(runCtx, wordlist, resumeFrom, limit, workers, &atomicAttempts, rules, verifyFn)
		}
		interrupted = runCtx.Err() != nil
	case "brute":
		if minLen < 1 || maxLen < minLen {
			tickCancel()
			return false, errors.New("invalid -n/-x range")
		}
		var pw string
		if cc != nil && cc.useGPU && gpuBounded {
			if gp, _, usedGPU := gpuBruteHash(targetHash, typ, charset, minLen, maxLen, &atomicAttempts); usedGPU {
				pw = gp
			} else {
				_, reason := activeGPUBackend()
				clrYellow.Fprintf(os.Stderr,
					"GPU brute unavailable for this run (%s) — using CPU\n", gpuReasonOrType(reason, typ))
				pw, interrupted, err = runBruteOrMaskLayout(runCtx, bruteLayout(charset, minLen, maxLen),
					sess, resumeFrom, limit, workers, &atomicAttempts, typ, salt, targetHash, verifyFn)
			}
		} else {
			if cc != nil && cc.useGPU && !gpuBounded {
				clrYellow.Fprintf(os.Stderr, "GPU brute does not support --skip/--limit yet — using CPU\n")
			}
			pw, interrupted, err = runBruteOrMaskLayout(runCtx, bruteLayout(charset, minLen, maxLen),
				sess, resumeFrom, limit, workers, &atomicAttempts, typ, salt, targetHash, verifyFn)
		}
		result = crackedResult{password: pw}
	case "mask":
		if mc == nil {
			tickCancel()
			return false, errors.New("mask mode requires --mask <mask>")
		}
		layout, e := maskLayout(mc)
		if e != nil {
			tickCancel()
			return false, e
		}
		var pw string
		if cc != nil && cc.useGPU && gpuBounded {
			if gp, _, usedGPU := gpuMaskHash(targetHash, typ, mc, &atomicAttempts); usedGPU {
				pw = gp
			} else {
				_, reason := activeGPUBackend()
				clrYellow.Fprintf(os.Stderr,
					"GPU mask unavailable for this run (%s) — using CPU\n", gpuReasonOrType(reason, typ))
				pw, interrupted, err = runBruteOrMaskLayout(runCtx, layout,
					sess, resumeFrom, limit, workers, &atomicAttempts, typ, salt, targetHash, verifyFn)
			}
		} else {
			if cc != nil && cc.useGPU && !gpuBounded {
				clrYellow.Fprintf(os.Stderr, "GPU mask does not support --skip/--limit yet — using CPU\n")
			}
			pw, interrupted, err = runBruteOrMaskLayout(runCtx, layout,
				sess, resumeFrom, limit, workers, &atomicAttempts, typ, salt, targetHash, verifyFn)
		}
		result = crackedResult{password: pw}
	case "markov":
		if minLen < 1 || maxLen < minLen {
			tickCancel()
			return false, errors.New("invalid -n/-x range")
		}
		model, e := trainMarkov(charset, wordlist)
		if e != nil {
			tickCancel()
			return false, e
		}
		var pw string
		pw, interrupted, err = runSessionLayout(runCtx, markovLayout(model, minLen, maxLen),
			sess, resumeFrom, limit, workers, &atomicAttempts, verifyFn)
		result = crackedResult{password: pw}
	case "hybrid":
		if mc == nil {
			tickCancel()
			return false, errors.New("hybrid mode requires --mask <mask> and -w <wordlist>")
		}
		sets, e := parseMask(mc)
		if e != nil {
			tickCancel()
			return false, e
		}
		words, _, e := loadWordlistSlice(wordlist)
		if e != nil {
			tickCancel()
			return false, e
		}
		var pw string
		pw, interrupted, err = runSessionLayout(runCtx, hybridLayout(words, sets, mc.maskFirst),
			sess, resumeFrom, limit, workers, &atomicAttempts, verifyFn)
		result = crackedResult{password: pw}
	case "combinator":
		if cc == nil || cc.wordlist2 == "" {
			tickCancel()
			return false, errors.New("combinator mode requires -w <left list> and --wordlist2 <right list>")
		}
		left, _, e1 := loadWordlistSlice(wordlist)
		if e1 != nil {
			tickCancel()
			return false, e1
		}
		right, _, e2 := loadWordlistSlice(cc.wordlist2)
		if e2 != nil {
			tickCancel()
			return false, e2
		}
		var pw string
		pw, interrupted, err = runSessionLayout(runCtx, combinatorLayout(left, right),
			sess, resumeFrom, limit, workers, &atomicAttempts, verifyFn)
		result = crackedResult{password: pw}
	case "prince":
		// princeLay was built above (before the progress bar), so any refusal
		// has already been reported; it is never nil here.
		var pw string
		pw, interrupted, err = runSessionLayout(runCtx, princeLay,
			sess, resumeFrom, limit, workers, &atomicAttempts, verifyFn)
		result = crackedResult{password: pw}
	default:
		tickCancel()
		return false, errors.New("unknown mode: use dict, brute, mask, markov, hybrid, combinator or prince")
	}

	tickCancel()
	_ = bar.Finish()
	fmt.Fprintln(os.Stderr) // newline after bar
	if err != nil {
		return false, err
	}

	elapsed := time.Since(start).Seconds()
	attempts := atomic.LoadInt64(&atomicAttempts)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(attempts) / elapsed
	}

	found := result.password != ""
	if found && cc != nil {
		cc.pot.add(targetHash, result.password)
		cc.recordPlain(result.password)
		cc.markFound(targetHash)
	}
	// Session bookkeeping. Three outcomes:
	//   - found: the job is done, discard the session file.
	//   - interrupted (Ctrl-C): keep the checkpoint so the run can be resumed.
	//   - otherwise, not found: this is only "the whole keyspace was searched
	//     and it wasn't there" when sess.Checkpoint reached sess.Total (the
	//     true, unbounded total — see runSessionLayout). A --limit-bounded run
	//     that exhausts its slice stops with Checkpoint < Total: that is
	//     "exhausted my slice", not "exhausted the keyspace", and reporting
	//     "Not found" while deleting the checkpoint would let an operator
	//     mistake a slice for the whole keyspace having been covered — the
	//     same failure the tiling property exists to prevent, by a different
	//     route. So keep the session in that case too.
	if sess != nil {
		switch {
		case found:
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
	if found {
		clrGreen.Fprint(os.Stderr, "Found: ")
		if result.ruleLabel != "" {
			fmt.Fprintf(os.Stderr, "%s (via rule: %s)\n", result.password, result.ruleLabel)
		} else {
			fmt.Fprintln(os.Stderr, result.password)
		}
		if u := cc.usernameFor(targetHash); u != "" {
			clrGreen.Fprintf(os.Stderr, "  user: %s\n", u)
		}
		// Under --left, -o is repurposed entirely as the leftover-target
		// destination (written once, after the whole run — see runCrack), so
		// a found result is not also written there; it would only be
		// clobbered by that final write anyway.
		if outFile != "" && (cc == nil || !cc.left) {
			// Default line (--outfile-format unset): unchanged from before —
			// just the password. --outfile-format overrides it with the
			// selected, hashcat-style fields.
			line := result.password
			if fmted, ok, e := cc.resultLine(targetHash, targetHash, result.password); e != nil {
				return true, e
			} else if ok {
				line = fmted
			}
			// cc.outW (when set) is a single handle opened once for the whole
			// run and appended to for every result — see newOutWriter. Without
			// it (e.g. crackReport's standalone interactive path, which has no
			// crackCtx wiring for outW), fall back to the single-shot write
			// that existed before, which is safe for a lone result.
			var e error
			if cc != nil && cc.outW != nil {
				e = cc.outW.writeLine(line)
			} else {
				e = os.WriteFile(outFile, []byte(line+"\n"), 0644)
			}
			if e != nil {
				return true, e
			}
			clrGreen.Fprintf(os.Stderr, "Saved to %s\n", outFile)
		}
		if copyResult {
			if copyToClipboard(result.password) {
				clrGreen.Fprintln(os.Stderr, "Copied to clipboard")
			} else {
				clrYellow.Fprintln(os.Stderr, "Unable to copy to clipboard")
			}
		}
	}
	color.New(themeAttr).Fprintf(os.Stderr,
		"Attempts: %d | Elapsed: %.2fs | Rate: %s\n",
		attempts, elapsed, formatRate(rate))
	return found, nil
}

// emitResult writes an already-known password to the -o file and/or clipboard,
// via cc's shared append-only outW when one is configured (falling back to a
// single-shot write otherwise — see doCrack's identical fallback). Shared by
// the potfile fast-path and --show, which skip the attack entirely. origKey
// is the pre-normalization input key: what cc's --username/--left bookkeeping
// is keyed by, so a potfile hit or --show hit still marks the target as found
// and prints its username, exactly like a freshly-cracked result does.
func emitResult(cc *crackCtx, origKey, pw, outFile string, copyResult bool) {
	cc.markFound(origKey)
	if u := cc.usernameFor(origKey); u != "" {
		clrGreen.Fprintf(os.Stderr, "  user: %s\n", u)
	}
	// Under --left, -o is repurposed entirely as the leftover-target
	// destination (written once, after the whole run) — see doCrack's
	// identical guard for the reasoning.
	if outFile != "" && (cc == nil || !cc.left) {
		line := pw
		if fmted, ok, err := cc.resultLine(origKey, origKey, pw); err == nil && ok {
			line = fmted
		}
		var err error
		if cc != nil && cc.outW != nil {
			err = cc.outW.writeLine(line)
		} else {
			err = os.WriteFile(outFile, []byte(line+"\n"), 0644)
		}
		if err == nil {
			clrGreen.Fprintf(os.Stderr, "Saved to %s\n", outFile)
		}
	}
	if copyResult && copyToClipboard(pw) {
		clrGreen.Fprintln(os.Stderr, "Copied to clipboard")
	}
}

// showPotEntry implements --show: report the potfile plaintext for a hash, if
// one has been recorded, without running any attack.
func showPotEntry(cc *crackCtx, origKey, target, outFile string, copyResult bool) (bool, error) {
	// Both call sites today gate on cc != nil before reaching here, but that's
	// an invariant this function shouldn't have to trust — a nil cc has no
	// potfile to look anything up in, so it's simply "not in potfile", not a
	// nil-pointer panic on cc.pot.
	if cc == nil {
		clrYellow.Fprintln(os.Stderr, "Not in potfile")
		return false, nil
	}
	if pw, ok := cc.pot.lookup(target); ok {
		clrGreen.Fprint(os.Stderr, "Found (potfile): ")
		fmt.Fprintln(os.Stderr, pw)
		emitResult(cc, origKey, pw, outFile, copyResult)
		return true, nil
	}
	clrYellow.Fprintln(os.Stderr, "Not in potfile")
	return false, nil
}

// crackReport runs a single-type attack and prints "Not found" on failure.
// Used by callers that already know the concrete hash type (interactive mode).
func crackReport(targetHash, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool, useRules bool) error {
	cc, _ := newCrackCtx("", false, "", false, "", false, 0, 0)
	var engine *ruleEngine
	if useRules {
		engine = builtinRuleEngine()
	}
	found, err := doCrack(targetHash, typ, mode, wordlist, charset,
		minLen, maxLen, workers, salt, saltMode, outFile, copyResult, engine, nil, cc)
	if err != nil {
		return err
	}
	if !found {
		clrYellow.Fprintln(os.Stderr, "Not found")
	}
	return nil
}

// crackWithDetection cracks a hash whose type may be unknown. When explicitType
// is empty or "auto", it uses detectHashTypes to find candidate algorithms and
// tries each in turn until one succeeds — the auto-detect crack workflow.
// Base58/Base64-encoded hashes are normalized to hex first.
func crackWithDetection(rawTarget, explicitType, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool, rules *ruleEngine, mc *maskConfig, cc *crackCtx) (bool, error) {

	target := strings.TrimSpace(rawTarget)
	// origKey is captured here, before any of the transformations below, so
	// it exactly matches the hash string --username/--left bookkeeping (built
	// in runCrack from the same gathered input) is keyed by.
	origKey := target
	// A "user:hash" or raw /etc/shadow line (from shadow2smith) is
	// reduced to its crypt-hash field so the verifier sees a clean hash.
	if stripped := stripShadowUsername(target); stripped != target {
		clrYellow.Fprintf(os.Stderr, "Detected shadow entry — cracking hash for user %q\n",
			target[:strings.IndexByte(target, ':')])
		target = stripped
	}
	skipNormalization := canonicalHashType(explicitType) == "cisco4"
	if normalized, enc := normalizeHashInput(target); !skipNormalization && enc != "" {
		clrYellow.Fprintf(os.Stderr, "Detected %s encoded hash — normalizing to hex\n", enc)
		target = normalized
	}

	// --show reports the potfile entry (if any) for this hash and stops.
	if cc != nil && cc.showOnly {
		return showPotEntry(cc, origKey, target, outFile, copyResult)
	}
	// A hash already in the potfile is reported without re-running the attack.
	if cc != nil {
		if pw, ok := cc.pot.lookup(target); ok {
			clrGreen.Fprint(os.Stderr, "Already cracked (potfile): ")
			fmt.Fprintln(os.Stderr, pw)
			emitResult(cc, origKey, pw, outFile, copyResult)
			return true, nil
		}
	}

	var types []string
	if explicitType != "" && !strings.EqualFold(explicitType, "auto") {
		types = []string{strings.ToLower(explicitType)}
	} else {
		types = detectHashTypes(target)
		if len(types) == 0 {
			return false, fmt.Errorf("could not auto-detect hash type — specify it with -t "+
				"(try 'hashsmith identify -i %s' for analysis)", target)
		}
		if len(types) == 1 {
			clrGreen.Fprintf(os.Stderr, "Detected hash type: %s\n", types[0])
		} else {
			clrYellow.Fprintf(os.Stderr,
				"Ambiguous hash — trying candidate types: %s\n", strings.Join(types, ", "))
		}
	}

	for _, t := range types {
		if len(types) > 1 {
			color.New(themeAttr, color.Bold).Fprintf(os.Stderr, "\n→ Attempting as %s\n", t)
		}
		found, err := doCrack(target, t, mode, wordlist, charset,
			minLen, maxLen, workers, salt, saltMode, outFile, copyResult, rules, mc, cc)
		if err != nil {
			// A feasibility refusal is about the ATTACK, not about this
			// candidate type — every remaining type would be refused on the
			// same grounds. Swallowing it here and moving on would end the run
			// with "Not found", which is the exact lie the guard exists to
			// prevent, so it aborts the whole run instead.
			if len(types) == 1 || isFeasibilityRefusal(err) {
				return false, err
			}
			// One candidate's hash format may be invalid; keep trying the rest.
			clrYellow.Fprintf(os.Stderr, "  (%s not applicable: %v)\n", t, err)
			continue
		}
		if found {
			// doCrack already marks targetHash found; origKey is marked too in
			// case a shadow-line/encoded-hash normalization made targetHash
			// differ from it, so --left's bookkeeping still keys correctly on
			// the exact string --username/--left tracked from the input.
			cc.markFound(origKey)
			return true, nil
		}
	}

	clrYellow.Fprintln(os.Stderr, "Not found")
	return false, nil
}

// ── Dictionary attack — producer-consumer pipeline ───────────────────────────
//
// One reader goroutine fills a batch channel; N worker goroutines drain it.
// Batch size is dictBatchSize to amortise channel overhead without starving
// workers. Context cancellation propagates through both the reader and workers.

// dictWordBounds computes the [skip, upper) word-index bound that
// --skip/--limit apply in dict mode: skip clamped to >= 0, and upper is the
// exclusive end (-1 = unbounded) when a positive limit narrows it. Both the
// real dictAttack reader and --stdout's dict candidate stream (streamCandidates)
// must use exactly this bound — a second, hand-rolled copy of this arithmetic
// is how a preview and the attack it previews drift apart.
func dictWordBounds(skip, limit int64) (lo, upper int64) {
	if skip < 0 {
		skip = 0
	}
	upper = -1 // -1 = unbounded
	if limit > 0 {
		upper = satAdd(skip, limit)
	}
	return skip, upper
}

// dictAttack streams a wordlist through `workers` verifiers. skip and limit
// (0 = unbounded) bound it to word indices [skip, skip+limit) of the whole
// wordlist — --skip/--limit's dictionary-mode semantics — letting a dict
// attack be split across machines the same way brute/mask/hybrid layouts are.
func dictAttack(ctx context.Context, wordlistPath string, skip, limit int64, workers int, atomicAttempts *int64,
	rules *ruleEngine, verify func(string) bool) (crackedResult, error) {

	// The source line ("Wordlist: ...") is announced once per run at the CLI
	// entry point (resolveWordlistForMode), not once per target here.
	f, _, err := openWordlist(wordlistPath)
	if err != nil {
		return crackedResult{}, err
	}
	defer f.Close()
	skip, upper := dictWordBounds(skip, limit)

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type batch = []string
	batchCh := make(chan batch, workers*4)
	resultCh := make(chan crackedResult, 1)

	// reader
	go func() {
		defer close(batchCh)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB line buffer
		cur := make(batch, 0, dictBatchSize)
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
					cur = make(batch, 0, dictBatchSize)
				case <-innerCtx.Done():
					return
				}
			}
		}
		if len(cur) > 0 {
			select {
			case batchCh <- cur:
			case <-innerCtx.Done():
			}
		}
	}()

	// workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			var localAttempts int64
			defer func() {
				atomic.AddInt64(atomicAttempts, localAttempts)
				wg.Done()
			}()
			tryCandidate := func(pw, ruleLabel string) bool {
				localAttempts++
				if localAttempts >= 1024 {
					atomic.AddInt64(atomicAttempts, localAttempts)
					localAttempts = 0
				}
				if !verify(pw) {
					return false
				}
				select {
				case resultCh <- crackedResult{password: pw, ruleLabel: ruleLabel}:
				default:
				}
				cancel()
				return true
			}
			for {
				select {
				case <-innerCtx.Done():
					return
				case words, ok := <-batchCh:
					if !ok {
						return
					}
					for _, word := range words {
						select {
						case <-innerCtx.Done():
							return
						default:
						}
						// Test the base word first (no rule applied).
						if tryCandidate(word, "") {
							return
						}
						// Test all mangled variants when rules are enabled.
						if rules != nil {
							for _, mw := range rules.expand(word) {
								select {
								case <-innerCtx.Done():
									return
								default:
								}
								if tryCandidate(mw.password, mw.ruleLabel) {
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
	select {
	case res := <-resultCh:
		return res, nil
	default:
		return crackedResult{}, nil
	}
}

// ── Progress ─────────────────────────────────────────────────────────────────

func progressTicker(ctx context.Context, bar *progressbar.ProgressBar, atomicAttempts *int64) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := atomic.LoadInt64(atomicAttempts)
			if delta := cur - last; delta > 0 {
				_ = bar.Add64(delta)
				last = cur
			}
		}
	}
}

func newCrackBar(total int64) *progressbar.ProgressBar {
	filled := color.New(themeAttr).Sprint("▬")
	head := color.New(themeAttr, color.Bold).Sprint("▬")
	yellow := color.New(color.FgYellow, color.Bold)
	themed := color.New(themeAttr, color.Bold)
	return progressbar.NewOptions64(
		total,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetDescription(yellow.Sprint("⚡")+" "+themed.Sprint("Cracking")+" "),
		progressbar.OptionSetWidth(14),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("H"),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionSetElapsedTime(true),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        filled,
			SaucerHead:    head,
			SaucerPadding: "▭",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionOnCompletion(func() {}),
	)
}

func formatRate(r float64) string {
	switch {
	case r >= 1e9:
		return fmt.Sprintf("%.2f GH/s", r/1e9)
	case r >= 1e6:
		return fmt.Sprintf("%.2f MH/s", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.2f kH/s", r/1e3)
	default:
		return fmt.Sprintf("%.2f H/s", r)
	}
}

// warnKeyspaceNotExhaustive tells the user, once, that the requested mask or
// brute-force range is larger than the engine can enumerate. The engine
// indexes every candidate with an int64 (maskIdxInto is a pure mixed-radix
// decode, correct for any index below the true keyspace), so the run still
// proceeds and every candidate it tries is genuine — it just cannot reach
// the full space in one pass. At ~65 MH/s even 2^63-1 candidates is on the
// order of 4500 years, so capping the sweep (rather than refusing to start,
// or worse, silently truncating to whatever int64 happened to wrap to) is
// the only choice that keeps the "start a huge mask and let it run" workflow
// usable while still being honest about what will actually be searched.
func warnKeyspaceNotExhaustive(exact *big.Int) {
	clrYellow.Fprintf(os.Stderr,
		"Warning: true keyspace is %s candidates, which exceeds %d (max int64) — "+
			"this run will only cover the first %d candidates and will NOT be exhaustive\n",
		exact.String(), int64(math.MaxInt64), int64(math.MaxInt64))
}

// printKeyspace implements --keyspace: it computes the exact (never-saturated,
// math/big) candidate count for the requested mode and prints it — nothing
// else — to stdout, so `$(hashsmith crack ... --keyspace)` works in a shell.
//
// --skip and --limit index the WHOLE layout (see runLayout's bound), so this
// intentionally reports the true, unbounded total rather than anything
// narrowed by --skip/--limit — a caller divides this number to build its own
// --skip/--limit slices.
//
// When the true count exceeds int64 (the type every candidate index in this
// engine is), printing a saturated math.MaxInt64 would silently mislead a
// script into under-covering the space when it divides the printed value to
// build slices. So this refuses instead: an error here (not a printed number)
// is what tells such a script its divide-and-slice plan cannot work.
// exactWordlistCount wraps countWordlistLines for --keyspace, rejecting its
// -1 "not countable" sentinel (returned for pipes, stdin, /dev/fd/N — see
// wordlist.go) instead of letting it flow into the arithmetic as a bogus
// count. Printing a negative or nonsensical number is the same failure mode
// as printing a saturated one: a script divides it to build --skip/--limit
// slices, so an unusable count must be a refusal, not a value.
func exactWordlistCount(path string) (int64, error) {
	n, err := countWordlistLines(path)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		label := path
		if strings.TrimSpace(label) == "" {
			label = defaultWordlistLabel
		}
		return 0, fmt.Errorf("cannot compute an exact keyspace: %q is not seekable "+
			"(a pipe, stdin, or /dev/fd/N) so its word count cannot be known in advance", label)
	}
	return n, nil
}

func printKeyspace(mode, wordlist, wordlist2, charset string, minLen, maxLen, princeElems int, mc *maskConfig) error {
	m := strings.ToLower(mode)
	var exact *big.Int
	switch m {
	case "brute", "markov":
		if minLen < 1 || maxLen < minLen {
			return errors.New("invalid -n/-x range")
		}
		exact, _ = calcBruteTotalExact(charset, minLen, maxLen)
	case "mask":
		if mc == nil {
			return errors.New("mask mode requires --mask <mask>")
		}
		exact, _ = calcMaskTotalExact(mc)
	case "hybrid":
		if mc == nil {
			return errors.New("hybrid mode requires --mask <mask> and -w <wordlist>")
		}
		n, err := exactWordlistCount(wordlist)
		if err != nil {
			return err
		}
		sets, err := parseMask(mc)
		if err != nil {
			return err
		}
		maskExact, _ := maskKeyspaceExact(sets)
		exact = new(big.Int).Mul(big.NewInt(n), maskExact)
	case "combinator":
		if wordlist2 == "" {
			return errors.New("combinator mode requires -w <left list> and --wordlist2 <right list>")
		}
		a, err := exactWordlistCount(wordlist)
		if err != nil {
			return err
		}
		b, err := exactWordlistCount(wordlist2)
		if err != nil {
			return err
		}
		exact = new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	case "prince":
		// Unlike dict/combinator/hybrid, this does not go through
		// exactWordlistCount: PRINCE needs the element STRINGS (to bucket them
		// by rune length), not just a count, so it reads the list in full. That
		// works for a pipe or stdin too, and the resulting number is exact —
		// which is the property --keyspace's refusal exists to protect.
		elems, _, err := loadWordlistSlice(wordlist)
		if err != nil {
			return err
		}
		_, ex, err := princeLayout(elems, minLen, maxLen, princeElems)
		if err != nil {
			return err
		}
		exact = ex
	case "dict":
		n, err := exactWordlistCount(wordlist)
		if err != nil {
			return err
		}
		exact = big.NewInt(n)
	default:
		return errors.New("unknown mode: use dict, brute, mask, markov, hybrid, combinator or prince")
	}
	if exact.Cmp(maxInt64Big) > 0 {
		return fmt.Errorf("true keyspace is %s candidates, which exceeds %d (max int64) — "+
			"refusing to print a saturated value a script would divide and under-cover",
			exact.String(), int64(math.MaxInt64))
	}
	fmt.Println(exact.String())
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// calcBruteTotal has the same overflow shape as maskKeyspace (base^length
// summed across lengths) and is fixed the same way: saturate at
// math.MaxInt64 via satMul/satAdd rather than silently wrap. It only feeds
// the progress bar — the actual enumeration bound comes from keyspaceLayout
// (bruteLayout -> newLayout), which is fixed independently in keyspace.go.
func calcBruteTotal(charset string, minLen, maxLen int) int64 {
	base := int64(len([]rune(charset)))
	if base == 0 {
		return 0
	}
	var total, power int64
	power = 1
	for i := 1; i <= maxLen; i++ {
		power = satMul(power, base)
		if i >= minLen {
			total = satAdd(total, power)
		}
	}
	return total
}

// calcBruteTotalExact mirrors calcBruteTotal with math/big so it can never
// overflow, giving the true keyspace size regardless of int64 range. It
// exists solely to detect and report when calcBruteTotal had to saturate.
func calcBruteTotalExact(charset string, minLen, maxLen int) (*big.Int, bool) {
	base := big.NewInt(int64(len([]rune(charset))))
	if base.Sign() == 0 {
		return big.NewInt(0), false
	}
	total := big.NewInt(0)
	power := big.NewInt(1)
	for i := 1; i <= maxLen; i++ {
		power.Mul(power, base)
		if i >= minLen {
			total.Add(total, power)
		}
	}
	return total, total.Cmp(maxInt64Big) > 0
}

// ── Hash verification ─────────────────────────────────────────────────────────

func verifyCandidate(candidate, targetHash, typ, salt, saltMode string) (bool, error) {
	algo := canonicalHashType(typ)
	// John's "postgres" label covers PostgreSQL challenge/response records,
	// while Hashsmith also uses postgres for the stored md5(password+user) form.
	if algo == "postgres" && strings.HasPrefix(targetHash, "$postgres$") {
		return verifyPostgresCRAM(targetHash, candidate)
	}
	if algo == "bcrypt-sha256" && strings.HasPrefix(targetHash, "$bcrypt-sha256$") {
		return verifyPasslibBcryptSHA256(targetHash, candidate)
	}
	// John exposes all QNX and SAP CODVN H digest variants through one label.
	if algo == "qnx-sha512" {
		switch {
		case strings.HasPrefix(targetHash, "@m"):
			return verifyQNX(targetHash, candidate, "m")
		case strings.HasPrefix(targetHash, "@s"):
			return verifyQNX(targetHash, candidate, "s")
		}
	}
	if algo == "sap-issha512" {
		switch {
		case strings.HasPrefix(targetHash, "{x-issha, "):
			return verifySAPIteratedSHA(targetHash, candidate, "sha1")
		case strings.HasPrefix(targetHash, "{x-isSHA256, "):
			return verifySAPIteratedSHA(targetHash, candidate, "sha256")
		case strings.HasPrefix(targetHash, "{x-isSHA384, "):
			return verifySAPIteratedSHA(targetHash, candidate, "sha384")
		}
	}
	if _, ok := compatSaltedDigests[algo]; ok {
		return verifyCompatSaltedDigest(candidate, targetHash, algo, salt)
	}
	if _, ok := compositeConstructions[algo]; ok {
		return verifyComposite(candidate, targetHash, algo, salt)
	}
	if algo == "siphash" {
		return verifySipHash(targetHash, candidate, salt)
	}
	if mode, ok := cryptCascadeModes[algo]; ok {
		return verifyCryptCascadeMode(targetHash, candidate, mode.kdf, mode.bits, mode.vera, mode.boot)
	}
	if mode, ok := luksModeSpecs[algo]; ok {
		return verifyLUKSMode(targetHash, candidate, mode)
	}
	switch algo {
	case "bitcoin-wif-p2pkh-compressed", "bitcoin-wif-p2pkh-uncompressed",
		"bitcoin-wif-p2wpkh-compressed", "bitcoin-wif-p2wpkh-uncompressed",
		"bitcoin-wif-p2sh-p2wpkh-compressed", "bitcoin-wif-p2sh-p2wpkh-uncompressed",
		"bitcoin-raw-p2pkh-compressed", "bitcoin-raw-p2pkh-uncompressed",
		"bitcoin-raw-p2wpkh-compressed", "bitcoin-raw-p2wpkh-uncompressed",
		"bitcoin-raw-p2sh-p2wpkh-compressed", "bitcoin-raw-p2sh-p2wpkh-uncompressed":
		return verifyBitcoinPrivateKeyAddress(targetHash, candidate, algo)
	case "pkcs8-pem-sha1", "pkcs8-pem-sha256":
		return verifyHashcatPEM(targetHash, candidate, algo)
	case "jks-private-key":
		return verifyJKSPrivateKey(targetHash, candidate)
	case "vmware-vmx":
		return verifyVMX(targetHash, candidate)
	case "virtualbox-aes128", "virtualbox-aes256":
		return verifyVirtualBox(targetHash, candidate, algo)
	case "metamask":
		return verifyMetaMask(targetHash, candidate, false)
	case "metamask-short":
		return verifyMetaMask(targetHash, candidate, true)
	case "exodus":
		return verifyExodus(targetHash, candidate)
	case "pbkdf1":
		return verifyPBKDF1SHA1(targetHash, candidate)
	case "crc32-hashcat":
		return verifyCRC32Hashcat(targetHash, candidate, salt)
	case "murmurhash":
		return verifyMurmurHash25700(targetHash, candidate, salt)
	case "murmur64a":
		return verifyMurmurHash64A(targetHash, candidate, salt, false)
	case "murmur64a-zero":
		return verifyMurmurHash64A(targetHash, candidate, "0000000000000000", false)
	case "murmur64a-truncated":
		return verifyMurmurHash64A(targetHash, candidate, "0000000000000000", true)
	case "murmur3-seeded":
		return verifyMurmur3Seeded(targetHash, candidate)
	case "crc32c-hashcat":
		return verifyCRC32CSeeded(targetHash, candidate)
	case "crc64-jones":
		return verifyCRC64Jones(targetHash, candidate)
	case "skip32":
		return verifySkip32(targetHash, candidate)
	case "aes128-ecb-nokdf":
		return verifyAESNOKDF(targetHash, candidate, 16)
	case "aes192-ecb-nokdf":
		return verifyAESNOKDF(targetHash, candidate, 24)
	case "aes256-ecb-nokdf":
		return verifyAESNOKDF(targetHash, candidate, 32)
	case "des-plaintext":
		return verifyDESKnownPlaintext(targetHash, candidate, false)
	case "3des-plaintext":
		return verifyDESKnownPlaintext(targetHash, candidate, true)
	case "chacha20":
		return verifyChaCha20KnownPlaintext(targetHash, candidate)
	case "rc4-dropn":
		return verifyRC4DropN(targetHash, candidate)
	}
	switch algo {
	case "android-backup":
		return verifyAndroidBackup(targetHash, candidate)
	case "dmg":
		return verifyDMG(targetHash, candidate)
	case "monero":
		return verifyMonero(targetHash, candidate)
	case "signal":
		return verifySignal(targetHash, candidate)
	case "macos-keychain":
		return verifyKeychain(targetHash, candidate)
	case "telegram-desktop":
		return verifyTelegramDesktop(targetHash, candidate)
	case "vnc":
		return verifyVNC(targetHash, candidate)
	case "encfs":
		return verifyEncFS(targetHash, candidate)
	case "mozilla-nss":
		return verifyMozillaNSS(targetHash, candidate)
	case "md5-salt1-pass-salt2":
		return verifyMD5DualSalt(targetHash, candidate)
	case "blockchain-legacy":
		return verifyBlockchainLegacy(targetHash, candidate)
	case "krb5tgs-nt", "krb5asrep-nt":
		return verifyKrb5NT(targetHash, candidate)
	case "phpass-md5":
		return verifyPhpassMD5(targetHash, candidate)
	case "symfony-legacy":
		return verifySymfonyLegacy(targetHash, candidate)
	case "wpa-pmkid":
		return verifyWPAPMKID(targetHash, candidate, false)
	case "wpa-pmk":
		return verifyWPAPMKID(targetHash, candidate, true)
	case "wpa-hccapx":
		return verifyHCCAPX(targetHash, candidate, false)
	case "wpa-hccapx-pmk":
		return verifyHCCAPX(targetHash, candidate, true)
	case "ethereum-presale":
		return verifyEthereumPresale(targetHash, candidate)
	case "aescrypt":
		return verifyAESCrypt(targetHash, candidate)
	case "multibit-key":
		return verifyMultiBitKey(targetHash, candidate)
	case "terra-wallet":
		return verifyTerraWallet(targetHash, candidate)
	case "tripcode":
		return verifyTripcode(targetHash, candidate)
	case "mojolicious":
		return verifyMojolicious(targetHash, candidate)
	case "blockchain-second":
		return verifyBlockchainSecond(targetHash, candidate)
	case "dcc-nt":
		return verifyDCCNT(targetHash, candidate)
	case "dcc2-nt":
		return verifyDCC2NT(targetHash, candidate)
	case "arubaos":
		return verifyArubaOS(targetHash, candidate)
	case "sha1-cx":
		return verifySHA1CX(targetHash, candidate)
	case "dovecot-cram-md5":
		return verifyDovecotCRAMMD5(targetHash, candidate)
	case "dane-sha256":
		return verifyDANESHA256(targetHash, candidate)
	case "samsung-android":
		return verifySamsungAndroid(targetHash, candidate)
	case "sspr":
		return verifySSPR(targetHash, candidate)
	case "netiq-pbkdf2":
		return verifyNetIQPBKDF2(targetHash, candidate)
	case "as400-ssha1":
		return verifyAS400SSHA1(targetHash, candidate)
	case "authme-sha256":
		return verifyAuthMeSHA256(targetHash, candidate)
	case "phps":
		return verifyPHPS(targetHash, candidate)
	case "md5-salt1-upper-md5-salt2-pass":
		return verifyDualSaltMD5(targetHash, candidate, "upper-inner")
	case "md5-triple-dual-salt":
		return verifyDualSaltMD5(targetHash, candidate, "triple")
	case "empirecms":
		return verifyDualSaltMD5(targetHash, candidate, "empirecms")
	case "cisco-ise":
		return verifyCiscoISE(targetHash, candidate)
	case "fortigate":
		return verifyFortiGate(targetHash, candidate)
	case "lastpass":
		return verifyLastPass(targetHash, candidate)
	case "sap-issha512":
		return verifySAPIsSHA512(targetHash, candidate)
	case "radmin2":
		return verifyRadmin2(targetHash, candidate)
	case "peoplesoft-token":
		return verifyPeopleSoftToken(targetHash, candidate)
	case "java-hashcode":
		return verifyJavaHashCode(targetHash, candidate)
	case "rails-restful-auth":
		return verifyRailsRestfulAuth(targetHash, candidate)
	case "web2py-pbkdf2":
		return verifyWeb2pyPBKDF2(targetHash, candidate)
	case "flask-session":
		return verifyFlaskSession(targetHash, candidate)
	case "wordpress-bcrypt":
		return verifyWordPressBcrypt(targetHash, candidate)
	case "krb5db":
		return verifyKrb5DB(targetHash, candidate)
	case "netntlmv1-nt":
		return verifyNetNTLMv1NT(targetHash, candidate)
	case "mysql-cram":
		return verifyMySQLCRAM(targetHash, candidate)
	case "tacacs-plus":
		return verifyTACACSPlus(targetHash, candidate)
	case "apple-secure-notes":
		return verifyAppleSecureNotes(targetHash, candidate)
	case "oracle-otm":
		return verifyOracleOTM(targetHash, candidate)
	case "xmpp-scram":
		return verifyXMPPSCRAM(targetHash, candidate)
	case "office2016-sheet":
		return verifyOffice2016Sheet(targetHash, candidate)
	case "postgres-cram":
		return verifyPostgresCRAM(targetHash, candidate)
	case "totp":
		return verifyTOTP(targetHash, candidate)
	case "snmpv3":
		return verifySNMPv3(targetHash, candidate)
	case "stellar-wallet":
		return verifyStellarWallet(targetHash, candidate)
	case "openedge":
		return verifyOpenEdge(targetHash, candidate)
	case "aws-sig-v4":
		return verifyAWSSignatureV4(targetHash, candidate)
	case "qnx-md5":
		return verifyQNX(targetHash, candidate, "m")
	case "qnx-sha256":
		return verifyQNX(targetHash, candidate, "s")
	case "qnx-sha512":
		return verifyQNX(targetHash, candidate, "S")
	case "sap-issha1":
		return verifySAPIteratedSHA(targetHash, candidate, "sha1")
	case "sap-issha256":
		return verifySAPIteratedSHA(targetHash, candidate, "sha256")
	case "sap-issha384":
		return verifySAPIteratedSHA(targetHash, candidate, "sha384")
	case "bcrypt-md5":
		return verifyWrappedBcrypt(targetHash, candidate, "md5")
	case "bcrypt-sha1":
		return verifyWrappedBcrypt(targetHash, candidate, "sha1")
	case "bcrypt-sha256":
		return verifyWrappedBcrypt(targetHash, candidate, "sha256")
	case "bcrypt-sha512":
		return verifyWrappedBcrypt(targetHash, candidate, "sha512")
	case "passlib-bcrypt-sha256":
		return verifyPasslibBcryptSHA256(targetHash, candidate)
	case "telegram-passcode":
		return verifyTelegramPasscode(targetHash, candidate)
	case "ms-sntp":
		return verifyMSSNTP(targetHash, candidate)
	case "citrix-pbkdf2":
		return verifyCitrixPBKDF2(targetHash, candidate)
	case "anope-sha256":
		return verifyAnopeSHA256(targetHash, candidate)
	case "citrix-sha512":
		return verifyCitrixSHA512(targetHash, candidate)
	case "fortigate256":
		return verifyFortiGate256(targetHash, candidate)
	case "umbraco-hmac-sha1":
		return verifyUmbracoHMACSHA1(targetHash, candidate)
	case "dahua-auth-md5":
		return verifyDahuaAuthMD5(targetHash, candidate, false)
	case "besder-auth-md5":
		return verifyDahuaAuthMD5(targetHash, candidate, true)
	case "netwitness-sha256":
		return verifyNetWitnessSHA256(targetHash, candidate)
	case "oracle-h":
		return verifyOracleH(targetHash, candidate)
	case "dnssec-nsec3":
		return verifyNSEC3(targetHash, candidate)
	case "ipmi-md5":
		return verifyIPMIMD5(targetHash, candidate)
	case "sha1-salt-user-password":
		return verifySaltedUsernameSHA1(targetHash, candidate)
	case "radmin3":
		return verifyRadmin3(targetHash, candidate)
	case "sha1-salt1-pass-salt2", "md5-salt1-sha1salt2pass", "md5-triple-passsalt-dual":
		return verifyHashcatDualSaltComposite(targetHash, candidate, algo)
	case "rails-restful-auth-one-round":
		return verifyRailsRestfulAuthOneRound(targetHash, candidate)
	case "veeam-vbk":
		return verifyVeeamVBK(targetHash, candidate)
	case "ms-online-account":
		return verifyMSOnlineAccount(targetHash, candidate)
	case "securecrt-v2":
		return verifySecureCRTV2(targetHash, candidate)
	case "knx-ip-secure":
		return verifyKNXIPSecure(targetHash, candidate)
	case "netntlmv2-nt":
		return verifyNetNTLMv2NT(targetHash, candidate)
	case "teamspeak3":
		return verifyTeamSpeak3(targetHash, candidate)
	case "shiro1-sha512":
		return verifyShiro1(targetHash, candidate)
	case "bcrypt":
		return bcrypt.CompareHashAndPassword([]byte(targetHash), []byte(candidate)) == nil, nil
	case "md5crypt":
		return verifyMD5Crypt(targetHash, candidate)
	case "apr1":
		return verifyAPR1(targetHash, candidate)
	case "sha256crypt":
		return verifyShaCrypt(sha256Params, targetHash, candidate)
	case "sha512crypt":
		return verifyShaCrypt(sha512Params, targetHash, candidate)
	case "sha1crypt":
		return verifySHA1Crypt(targetHash, candidate)
	case "sm3crypt":
		return verifySM3Crypt(targetHash, candidate)
	case "descrypt":
		return verifyDescrypt(targetHash, candidate)
	case "argon2":
		return verifyArgon2(targetHash, candidate), nil
	case "scrypt":
		return verifyScrypt(targetHash, candidate)
	case "mssql2005":
		return verifyMSSQL2005(targetHash, candidate)
	case "mssql2012":
		return verifyMSSQL2012(targetHash, candidate)
	case "zipcrypto":
		return verifyZipCrypto(targetHash, candidate)
	case "zipaes128", "zipaes192", "zipaes256":
		return verifyZipAES(targetHash, candidate)
	case "7z":
		return verify7z(targetHash, candidate)
	case "rar4":
		return verifyRAR4(targetHash, candidate)
	case "rar5":
		return verifyRAR5(targetHash, candidate)
	case "pdf":
		return verifyPDF(targetHash, candidate)
	case "ssh":
		return verifySSH(targetHash, candidate)
	case "pkcs8":
		return verifyPKCS8(targetHash, candidate)
	case "pfx":
		return verifyPKCS12(targetHash, candidate)
	case "pwsafe":
		return verifyPwsafe(targetHash, candidate)
	case "gpg":
		return verifyGPG(targetHash, candidate)
	case "office":
		return verifyOffice(targetHash, candidate)
	case "office-old":
		return verifyOldOffice(targetHash, candidate, "")
	case "office-old-md5":
		return verifyOldOffice(targetHash, candidate, "md5")
	case "office-old-sha1":
		return verifyOldOffice(targetHash, candidate, "sha1")
	case "keepass":
		return verifyKeePass(targetHash, candidate)
	case "wpa":
		return verifyWPA(targetHash, candidate)
	case "ethereum":
		return verifyEthereum(targetHash, candidate)
	case "bitcoin":
		return verifyBitcoin(targetHash, candidate)
	case "django":
		return verifyDjango(targetHash, candidate)
	case "mysql8":
		return verifyMySQL8(targetHash, candidate)
	case "veracrypt":
		return verifyVeraCrypt(targetHash, candidate)
	case "truecrypt":
		return verifyTrueCrypt(targetHash, candidate)
	case "truecrypt-ripemd160":
		return verifyTrueCryptMode(targetHash, candidate, "ripemd160")
	case "truecrypt-sha512":
		return verifyTrueCryptMode(targetHash, candidate, "sha512")
	case "truecrypt-whirlpool":
		return verifyTrueCryptMode(targetHash, candidate, "whirlpool")
	case "veracrypt-ripemd160":
		return verifyVeraCryptMode(targetHash, candidate, "ripemd160")
	case "veracrypt-sha512":
		return verifyVeraCryptMode(targetHash, candidate, "sha512")
	case "veracrypt-whirlpool":
		return verifyVeraCryptMode(targetHash, candidate, "whirlpool")
	case "veracrypt-sha256":
		return verifyVeraCryptMode(targetHash, candidate, "sha256")
	case "bitlocker":
		return verifyBitLocker(targetHash, candidate)
	case "electrum":
		return verifyElectrum(targetHash, candidate)
	case "phpass":
		return verifyPhpass(targetHash, candidate)
	case "drupal7":
		return verifyDrupal7(targetHash, candidate)
	case "luks":
		return verifyLUKS(targetHash, candidate)
	case "cisco8":
		return verifyCiscoType8(targetHash, candidate)
	case "cisco9":
		return verifyCiscoType9(targetHash, candidate)
	case "cisco4":
		return verifyCiscoType4(targetHash, candidate)
	case "macos":
		return verifyMacOS(targetHash, candidate)
	case "atlassian":
		return verifyAtlassian(targetHash, candidate)
	case "jwt":
		return verifyJWT(targetHash, candidate)
	case "pbkdf2":
		return verifyPBKDF2(targetHash, candidate)
	case "passlib-pbkdf2":
		return verifyPasslibPBKDF2(targetHash, candidate)
	case "werkzeug":
		return verifyWerkzeug(targetHash, candidate)
	case "aspnet-identity":
		return verifyASPNetIdentity(targetHash, candidate)
	case "grub2":
		return verifyGRUB2(targetHash, candidate)
	case "mediawiki":
		return verifyMediaWiki(targetHash, candidate)
	case "vbulletin":
		return verifyVBulletin(targetHash, candidate)
	case "redmine":
		return verifyRedmine(targetHash, candidate)
	case "dcc":
		return verifyDCC(targetHash, candidate)
	case "dcc2":
		return verifyDCC2(targetHash, candidate)
	case "citrix":
		return verifyCitrix(targetHash, candidate)
	case "cisco-pix":
		return verifyCiscoPIX(targetHash, candidate)
	case "cisco-asa":
		return verifyCiscoASA(targetHash, candidate)
	case "cram-md5":
		return verifyCRAMMD5(targetHash, candidate)
	case "scram":
		return verifySCRAM(targetHash, candidate)
	case "ipmi":
		return verifyIPMI(targetHash, candidate)
	case "half-md5":
		return verifyHalfMD5(targetHash, candidate)
	case "sap-fg":
		return verifySAPCodvnFG(targetHash, candidate)
	case "sap-fg-rfc-read-table":
		return verifySAPCodvnFGRFCReadTable(targetHash, candidate)
	case "sap-b":
		return verifySAPCodvnB(targetHash, candidate)
	case "sap-b-rfc-read-table":
		return verifySAPCodvnBRFCReadTable(targetHash, candidate)
	case "sybase":
		return verifySybaseASE(targetHash, candidate)
	case "chap":
		return verifyChap(targetHash, candidate)
	case "ldap":
		return verifyLDAP(targetHash, candidate)
	case "ldap-pbkdf2":
		return verifyRedHat389PBKDF2(targetHash, candidate)
	case "bitwarden":
		return verifyBitwarden(targetHash, candidate)
	case "mongodb":
		return verifyMongoDB(targetHash, candidate)
	case "solarwinds":
		return verifySolarWinds(targetHash, candidate)
	case "peoplesoft":
		return verifyPeopleSoft(targetHash, candidate)
	case "episerver":
		return verifyEpiserver(targetHash, candidate)
	case "azuresync":
		return verifyAzureSync(targetHash, candidate)
	case "hmailserver":
		return verifyHMailServer(targetHash, candidate)
	case "sip":
		return verifySIP(targetHash, candidate)
	case "juniper":
		return verifyJuniper(targetHash, candidate)
	case "itunes":
		return verifyITunesBackup(targetHash, candidate)
	case "1password":
		return verify1Password(targetHash, candidate)
	case "ike":
		return verifyIKE(targetHash, candidate)
	case "ansible":
		return verifyAnsible(targetHash, candidate)
	case "blockchain":
		return verifyBlockchain(targetHash, candidate)
	case "oracle11g":
		return verifyOracle11g(targetHash, candidate)
	case "oracle12c":
		return verifyOracle12c(targetHash, candidate)
	case "axcrypt-sha1":
		return verifyAxCryptSHA1(targetHash, candidate)
	case "aix":
		return verifyAIX(targetHash, candidate)
	case "pdf-r6":
		return verifyPDFR6(targetHash, candidate)
	case "netntlmv2":
		return verifyNetNTLMv2(targetHash, candidate)
	case "netntlmv1":
		return verifyNetNTLMv1(targetHash, candidate)
	case "krb5asrep":
		return verifyKrb5(targetHash, candidate)
	case "krb5tgs":
		return verifyKrb5(targetHash, candidate)
	case "krb5pa":
		return verifyKrb5(targetHash, candidate)
	case "lm":
		got, err := hashText(candidate, algo, salt, saltMode)
		if err != nil {
			return false, err
		}
		// Hashcat mode 3000 cracks the two 7-character LM halves separately;
		// John and Windows dumps commonly retain the full 32-hex representation.
		return strings.EqualFold(got, targetHash) ||
			(len(targetHash) == 16 && strings.EqualFold(got[:16], targetHash)), nil
	case "mysql41":
		got, err := hashText(candidate, algo, salt, saltMode)
		if err != nil {
			return false, err
		}
		return strings.EqualFold(strings.TrimPrefix(got, "*"), strings.TrimPrefix(targetHash, "*")), nil
	case "blake2b", "blake2b256", "blake2s":
		got, err := hashText(candidate, algo, salt, saltMode)
		if err != nil {
			return false, err
		}
		return strings.EqualFold(got, strings.TrimPrefix(targetHash, "$BLAKE2$")), nil
	}
	// HMAC types take their message from a "hash:salt" pairing when no salt was
	// supplied via -s, so `<hmac>:<salt>` targets crack without extra flags.
	target, effSalt := targetHash, salt
	if effSalt == "" && strings.HasPrefix(algo, "hmac-") {
		if i := strings.LastIndexByte(targetHash, ':'); i >= 0 {
			target, effSalt = targetHash[:i], targetHash[i+1:]
		}
	}
	got, err := hashText(candidate, algo, effSalt, saltMode)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(got, target), nil
}

// ── ZIP hash verification ─────────────────────────────────────────────────────

// verifyZipCrypto checks a ZipCrypto password by decrypting the 12-byte
// encryption header and comparing the last plaintext byte to the stored
// check byte (which is either the high byte of the CRC-32 or of ModTime,
// depending on how the hash was extracted).
//
// Hash format: $zipcrypto$<check_byte_hex>$<12_byte_enc_header_hex>
func verifyZipCrypto(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	// "$zipcrypto$XX$YYYYYY..." splits to ["", "zipcrypto", "XX", "YYY..."]
	if len(parts) != 4 || parts[1] != "zipcrypto" {
		return false, errors.New("invalid zipcrypto hash format")
	}
	checkBytes, err := hex.DecodeString(parts[2])
	if err != nil || len(checkBytes) != 1 {
		return false, errors.New("invalid check byte in zipcrypto hash")
	}
	encHeader, err := hex.DecodeString(parts[3])
	if err != nil || len(encHeader) != 12 {
		return false, errors.New("invalid encryption header in zipcrypto hash")
	}
	decrypted := decryptZipCryptoHeader(encHeader, candidate)
	return decrypted[11] == checkBytes[0], nil
}

// verifyZipAES checks a WinZip AES password by re-deriving the PBKDF2 key
// with the stored salt and comparing the last two derived bytes (the password
// verifier) to the stored verifier.
//
// Hash formats:
//
//	$zipaes128$<salt_hex>$<verif_hex>  (8-byte salt,  keyLen=16)
//	$zipaes192$<salt_hex>$<verif_hex>  (12-byte salt, keyLen=24)
//	$zipaes256$<salt_hex>$<verif_hex>  (16-byte salt, keyLen=32)
func verifyZipAES(targetHash, candidate string) (bool, error) {
	var keyLen int
	var rest string
	switch {
	case strings.HasPrefix(targetHash, "$zipaes128$"):
		keyLen, rest = 16, targetHash[len("$zipaes128$"):]
	case strings.HasPrefix(targetHash, "$zipaes192$"):
		keyLen, rest = 24, targetHash[len("$zipaes192$"):]
	case strings.HasPrefix(targetHash, "$zipaes256$"):
		keyLen, rest = 32, targetHash[len("$zipaes256$"):]
	default:
		return false, errors.New("invalid zipaes hash format")
	}
	parts := strings.SplitN(rest, "$", 2)
	if len(parts) != 2 {
		return false, errors.New("invalid zipaes hash: missing verifier field")
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("invalid salt in zipaes hash: %w", err)
	}
	expectedVerif, err := hex.DecodeString(parts[1])
	if err != nil || len(expectedVerif) != 2 {
		return false, fmt.Errorf("invalid verifier in zipaes hash: %w", err)
	}
	// WinZip AES uses PBKDF2-HMAC-SHA1 with 1000 iterations.
	// Derived key layout: [AES key (keyLen)] [HMAC key (keyLen)] [verifier (2)]
	// Total = 2*keyLen + 2 bytes. The verifier is at offset 2*keyLen.
	dkLen := 2*keyLen + 2
	dk := pbkdf2.Key([]byte(candidate), salt, 1000, dkLen, sha1.New)
	return dk[2*keyLen] == expectedVerif[0] && dk[2*keyLen+1] == expectedVerif[1], nil
}

func verifyScrypt(targetHash, candidate string) (bool, error) {
	var fields []string
	var hashcatFormat bool
	if strings.HasPrefix(strings.ToUpper(targetHash), "SCRYPT:") {
		fields = strings.Split(targetHash, ":")
		hashcatFormat = true
	} else {
		fields = strings.Split(targetHash, "$")
	}
	if len(fields) != 6 || (!hashcatFormat && fields[0] != "scrypt") {
		return false, errors.New("invalid scrypt hash (need scrypt$N$r$p$hexsalt$hexdigest or SCRYPT:N:r:p:b64salt:b64digest)")
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil {
		return false, err
	}
	r, err := strconv.Atoi(fields[2])
	if err != nil {
		return false, err
	}
	p, err := strconv.Atoi(fields[3])
	if err != nil {
		return false, err
	}
	if n <= 1 || n&(n-1) != 0 || r < 1 || p < 1 || r > 1<<20 || p > 1<<20 ||
		uint64(128)*uint64(n)*uint64(r) > maxScryptMemory || uint64(r)*uint64(p) >= 1<<30 {
		return false, errors.New("invalid or excessive scrypt work factors")
	}
	var saltBytes, digest []byte
	if hashcatFormat {
		saltBytes, err = decodeBase64Flexible(fields[4], false)
		if err == nil {
			digest, err = decodeBase64Flexible(fields[5], false)
		}
	} else {
		saltBytes, err = hex.DecodeString(fields[4])
		if err == nil {
			digest, err = hex.DecodeString(fields[5])
		}
	}
	if err != nil || len(saltBytes) > maxKDFFieldSize || len(digest) == 0 || len(digest) > maxKDFFieldSize {
		return false, errors.New("invalid scrypt salt or digest encoding")
	}
	got, err := scrypt.Key([]byte(candidate), saltBytes, n, r, p, len(digest))
	if err != nil {
		return false, err
	}
	return bytes.Equal(got, digest), nil
}

func verifyMSSQL2005(targetHash, candidate string) (bool, error) {
	v := strings.TrimSpace(targetHash)
	if !strings.HasPrefix(strings.ToLower(v), "0x0100") || len(v) < 14 {
		return false, errors.New("invalid MSSQL 2005/2012 hash format")
	}
	saltBytes, err := hex.DecodeString(v[6:14])
	if err != nil {
		return false, err
	}
	digest := sha1.Sum(append(utf16le(candidate), saltBytes...))
	got := strings.ToUpper(hex.EncodeToString(digest[:]))
	return strings.ToUpper(v[14:]) == got, nil
}

func verifyMSSQL2012(targetHash, candidate string) (bool, error) {
	v := strings.TrimSpace(targetHash)
	if !strings.HasPrefix(strings.ToLower(v), "0x0200") || len(v) != 142 {
		return false, errors.New("invalid MSSQL 2012/2014 hash format")
	}
	saltBytes, err := hex.DecodeString(v[6:14])
	if err != nil {
		return false, err
	}
	digest := sha512.Sum512(append(utf16le(candidate), saltBytes...))
	got := strings.ToUpper(hex.EncodeToString(digest[:]))
	return strings.ToUpper(v[14:]) == got, nil
}

// ── 7-Zip verification ────────────────────────────────────────────────────────

// verify7z checks a 7-Zip AES-256 password by deriving the key via the 7z
// rolling SHA-256 KDF (single context, 2^numCyclesPower iterations) and
// decrypting the first AES block. Verification uses a structural heuristic:
// the first byte of correctly decrypted 7z header data is always in a known
// range (LZMA property 0x5D, or LZMA2/property-IDs ≤ 0x3F).
//
// Canonical Hashcat format:
// $7z$<type>$<cycles>$<saltLen>$<salt>$<ivLen>$<iv>$<crc>$<dataLen>$<unpackSize>$<data>
//
// Hashsmith's earlier abbreviated extractor format is accepted for backward
// compatibility, but canonical records are verified with their CRC and exact
// unpacked length instead of a structural heuristic.
func verify7z(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	if len(parts) < 8 || parts[1] != "7z" {
		return false, errors.New("invalid 7z hash format")
	}

	var cyclesField, saltField, ivField, dataField string
	var wantCRC uint64
	var unpackSize int
	canonical := len(parts) == 12
	if canonical {
		if parts[2] != "0" {
			return false, errors.New("unsupported 7z data type")
		}
		cyclesField, saltField, ivField, dataField = parts[3], parts[5], parts[7], parts[11]
		saltLen, err := strconv.Atoi(parts[4])
		if err != nil || saltLen < 0 || saltLen > 64 {
			return false, errors.New("invalid 7z salt length")
		}
		ivLen, err := strconv.Atoi(parts[6])
		if err != nil || ivLen < 0 || ivLen > aes.BlockSize {
			return false, errors.New("invalid 7z IV length")
		}
		dataLen, err := strconv.Atoi(parts[9])
		if err != nil || dataLen < aes.BlockSize {
			return false, errors.New("invalid 7z data length")
		}
		unpackSize, err = strconv.Atoi(parts[10])
		if err != nil || unpackSize < 0 || unpackSize > dataLen {
			return false, errors.New("invalid 7z unpack size")
		}
		wantCRC, err = strconv.ParseUint(parts[8], 10, 32)
		if err != nil {
			return false, errors.New("invalid 7z CRC")
		}
		if len(saltField) != saltLen*2 || len(ivField) < ivLen*2 || len(dataField) != dataLen*2 {
			return false, errors.New("7z field length mismatch")
		}
	} else if len(parts) == 8 {
		cyclesField, saltField, ivField, dataField = parts[2], parts[3], parts[4], parts[7]
	} else {
		return false, errors.New("invalid 7z hash field count")
	}

	numCyclesPower, err := strconv.Atoi(cyclesField)
	if err != nil || numCyclesPower < 0 || numCyclesPower > 32 {
		return false, errors.New("invalid 7z numCyclesPower")
	}
	salt, err := hex.DecodeString(saltField)
	if err != nil {
		return false, errors.New("invalid 7z salt")
	}
	iv, err := hex.DecodeString(ivField)
	if err != nil || len(iv) > aes.BlockSize {
		return false, errors.New("invalid 7z IV")
	}
	iv = append(iv, make([]byte, aes.BlockSize-len(iv))...)
	encData, err := hex.DecodeString(dataField)
	if err != nil || len(encData) < aes.BlockSize || len(encData)%aes.BlockSize != 0 {
		return false, errors.New("invalid 7z encrypted data")
	}

	// 7-Zip KDF: single SHA-256 context fed (salt || pw_utf16le || ctr_LE8)
	// for each of 2^numCyclesPower rounds.
	pwBytes := utf16le(candidate)
	h := sha256.New()
	numRounds := uint64(1) << uint(numCyclesPower)
	for i := uint64(0); i < numRounds; i++ {
		if len(salt) > 0 {
			h.Write(salt)
		}
		h.Write(pwBytes)
		var ctr [8]byte
		binary.LittleEndian.PutUint64(ctr[:], i)
		h.Write(ctr[:])
	}
	key := h.Sum(nil) // 32 bytes → AES-256

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	decrypted := make([]byte, len(encData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, encData)
	if canonical {
		return uint64(crc32.ChecksumIEEE(decrypted[:unpackSize])) == wantCRC, nil
	}

	// Legacy two-block structural check:
	//   Block 1: LZMA2 compressed data always has control byte ≥ 0x80.
	//   Block 2: 7-zip zero-pads the LZMA2 stream to a multiple of 16 bytes,
	//            so decrypted block 2 is all-zero with the correct key, but
	//            random (p≈1/2^128) with any wrong key.
	// Combined false-positive probability ≈ 0.
	if len(encData) < aes.BlockSize*2 {
		// Single block available; fall back to a weak first-byte check.
		aligned := make([]byte, aes.BlockSize)
		copy(aligned, decrypted[:aes.BlockSize])
		return aligned[0] >= 0x80, nil
	}
	aligned2 := decrypted[:aes.BlockSize*2]

	if aligned2[0] < 0x80 {
		return false, nil // block 1: not a compressed LZMA2 control byte
	}
	for _, byt := range aligned2[aes.BlockSize:] {
		if byt != 0 {
			return false, nil // block 2 not all-zero → wrong key
		}
	}
	return true, nil
}

// ── RAR4 verification ─────────────────────────────────────────────────────────

// verifyRAR4 checks a RAR4 (-hp) password using the RAR3 SHA-1 rolling KDF
// (0x40000 fixed rounds, password as UTF-16LE) and AES-128-CBC decryption.
// Verification checks that the decrypted archive-header type byte (offset 2)
// equals 0x73 (main archive block type).
//
// Canonical Hashcat/John format: $RAR3$*0*<salt_hex>*<data_hex>.
// Hashsmith's earlier lowercase/dollar-delimited spelling remains accepted.
func verifyRAR4(targetHash, candidate string) (bool, error) {
	var saltHex, dataHex string
	canonical := false
	if strings.HasPrefix(targetHash, "$RAR3$*0*") {
		canonical = true
		parts := strings.Split(targetHash, "*")
		if len(parts) != 4 {
			return false, errors.New("invalid RAR3 hash format")
		}
		saltHex, dataHex = parts[2], parts[3]
	} else {
		parts := strings.Split(targetHash, "$")
		if len(parts) != 5 || !strings.EqualFold(parts[1], "rar3") || parts[2] != "0" {
			return false, errors.New("invalid RAR3 hash format")
		}
		saltHex, dataHex = parts[3], parts[4]
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) != 8 {
		return false, errors.New("invalid rar3 salt (need 8 bytes)")
	}
	encData, err := hex.DecodeString(dataHex)
	if err != nil || len(encData) < 16 {
		return false, errors.New("invalid rar3 encrypted data (need ≥16 bytes)")
	}

	// RAR3 KDF: single SHA-1 context, 262144 (0x40000) rounds.
	// Each round feeds: password_utf16le || salt(8B) || i(3B little-endian).
	pwBytes := utf16le(candidate)
	h := sha1.New()
	iv := make([]byte, 0, aes.BlockSize)
	for i := 0; i < 0x40000; i++ {
		h.Write(pwBytes)
		h.Write(salt)
		h.Write([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		if i&0x3fff == 0 {
			iv = append(iv, h.Sum(nil)[19])
		}
	}
	digest := h.Sum(nil) // 20 bytes

	// RAR stores the SHA-1 state as four little-endian words for its AES key.
	key := make([]byte, 16)
	for i := 0; i < 16; i += 4 {
		key[i], key[i+1], key[i+2], key[i+3] = digest[i+3], digest[i+2], digest[i+1], digest[i]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	decrypted := make([]byte, 16)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, encData[:16])
	if canonical {
		// Hashcat/JtR type-0 records retain the fixed RAR end-header marker.
		return bytes.Equal(decrypted[:7], []byte{0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00}), nil
	}

	// byte[2] of a valid RAR4 main archive header is always 0x73.
	return decrypted[2] == 0x73, nil
}

// ── RAR5 verification ─────────────────────────────────────────────────────────

// verifyRAR5 checks a RAR5 password using PBKDF2-HMAC-SHA256 and the stored
// password-check value. The KDF derives 40 bytes: 32 for the AES key and 8 for
// the check value (stored in the hash during extraction).
//
// Hash format: $rar5$<salt_hex>$<lgcount>$<checkval_hex>
func verifyRAR5(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	if len(parts) != 5 || parts[1] != "rar5" {
		return false, errors.New("invalid rar5 hash format")
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false, err
	}
	lgCount, err := strconv.Atoi(parts[3])
	if err != nil || lgCount < 0 || lgCount > 24 {
		return false, errors.New("invalid rar5 lgCount")
	}
	checkVal, err := hex.DecodeString(parts[4])
	if err != nil || len(checkVal) < 8 {
		return false, errors.New("invalid rar5 check value (need 8 bytes)")
	}

	iterations := 1 << uint(lgCount)
	// Derive 32 (key) + 8 (check) = 40 bytes with PBKDF2-HMAC-SHA256.
	dk := pbkdf2.Key([]byte(candidate), salt, iterations, 40, sha256.New)
	return bytes.Equal(dk[32:40], checkVal[:8]), nil
}

// ── PDF verification ──────────────────────────────────────────────────────────

// pdfPaddingBytes is the standard 32-byte PDF password padding constant
// defined in PDF Reference §3.5.2 (Algorithm 2).
var pdfPaddingBytes = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
	0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
	0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// pdfComputeKey derives the PDF encryption key (Algorithm 2) from the user
// password, /O key, /P permissions, document ID, revision, and key size.
func pdfComputeKey(password string, oKey []byte, p int32, docID []byte, revision, keySize int, encryptMetadata bool) []byte {
	// Pad or truncate the password to exactly 32 bytes.
	padded := make([]byte, 32)
	n := copy(padded, []byte(password))
	copy(padded[n:], pdfPaddingBytes)

	h := md5.New()
	h.Write(padded)
	h.Write(oKey)
	h.Write([]byte{byte(p), byte(p >> 8), byte(p >> 16), byte(p >> 24)})
	h.Write(docID)
	if revision >= 4 && !encryptMetadata {
		h.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	key := h.Sum(nil)[:keySize]

	if revision >= 3 {
		for i := 0; i < 50; i++ {
			h.Reset()
			h.Write(key)
			key = h.Sum(nil)[:keySize]
		}
	}
	return key
}

// verifyPDF checks a PDF user password using the Standard security handler
// (revisions 2-4). It derives the encryption key and validates it against the
// /U (user key) entry stored in the hash.
//
// Canonical Hashcat/John format:
// $pdf$<V>*<R>*<keyBits>*<P>*<encryptMetadata>*<idLen>*<id>*<uLen>*<U>*<oLen>*<O>
// Hashsmith's earlier dollar-delimited short form remains accepted.
func verifyPDF(targetHash, candidate string) (bool, error) {
	var rField, keyField, pField, idHex, uHex, oHex string
	encryptMetadata := true
	if strings.HasPrefix(targetHash, "$pdf$") && strings.Contains(targetHash, "*") {
		parts := strings.Split(strings.TrimPrefix(targetHash, "$pdf$"), "*")
		if len(parts) != 11 {
			return false, errors.New("invalid PDF hash field count")
		}
		rField, keyField, pField = parts[1], parts[2], parts[3]
		encryptMetadata = parts[4] != "0"
		idHex, uHex, oHex = parts[6], parts[8], parts[10]
		idLen, err1 := strconv.Atoi(parts[5])
		uLen, err2 := strconv.Atoi(parts[7])
		oLen, err3 := strconv.Atoi(parts[9])
		if err1 != nil || err2 != nil || err3 != nil || len(idHex) != idLen*2 || len(uHex) != uLen*2 || len(oHex) != oLen*2 {
			return false, errors.New("PDF field length mismatch")
		}
	} else {
		parts := strings.Split(targetHash, "$")
		if len(parts) != 8 || parts[1] != "pdf" {
			return false, errors.New("invalid pdf hash format")
		}
		rField, keyField, pField, idHex, uHex, oHex = parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]
	}
	R, err := strconv.Atoi(rField)
	if err != nil {
		return false, errors.New("invalid PDF revision")
	}
	keyLenBits, err := strconv.Atoi(keyField)
	if err != nil {
		return false, errors.New("invalid PDF key length")
	}
	P64, err := strconv.ParseInt(pField, 10, 32)
	if err != nil {
		return false, errors.New("invalid PDF permissions")
	}
	P := int32(P64)
	docID, err := hex.DecodeString(idHex)
	if err != nil {
		return false, errors.New("invalid pdf docID")
	}
	U, err := hex.DecodeString(uHex)
	if err != nil || len(U) < 16 {
		return false, errors.New("invalid pdf U key (need ≥16 bytes)")
	}
	O, err := hex.DecodeString(oHex)
	if err != nil || len(O) < 32 {
		return false, errors.New("invalid pdf O key (need 32 bytes)")
	}

	keySize := keyLenBits / 8
	if keySize < 5 {
		keySize = 5
	}
	if keySize > 16 {
		keySize = 16
	}

	key := pdfComputeKey(candidate, O, P, docID, R, keySize, encryptMetadata)

	switch R {
	case 2:
		// Algorithm 4: RC4-encrypt the 32-byte padding; compare first 16 B to /U.
		c, err := rc4.NewCipher(key)
		if err != nil {
			return false, err
		}
		computed := make([]byte, 32)
		c.XORKeyStream(computed, pdfPaddingBytes)
		return bytes.Equal(computed[:16], U[:16]), nil

	case 3, 4:
		// Algorithm 5: hash(padding || docID), then 20 passes of RC4 with XOR'd keys.
		h := md5.New()
		h.Write(pdfPaddingBytes)
		h.Write(docID)
		digest := h.Sum(nil) // 16 bytes

		c, err := rc4.NewCipher(key)
		if err != nil {
			return false, err
		}
		computed := make([]byte, 16)
		c.XORKeyStream(computed, digest)

		for i := 1; i <= 19; i++ {
			xkey := make([]byte, keySize)
			for j := range xkey {
				xkey[j] = key[j] ^ byte(i)
			}
			c, _ = rc4.NewCipher(xkey)
			c.XORKeyStream(computed, computed)
		}
		return bytes.Equal(computed[:16], U[:16]), nil
	}

	return false, fmt.Errorf("unsupported PDF revision %d (only R=2,3,4 supported)", R)
}
