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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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

// crackedResult carries the found password and an optional human-readable label
// describing which mangling rule produced it (empty when no rule was applied).
type crackedResult struct {
	password  string
	ruleLabel string
}

// ── CLI entry ────────────────────────────────────────────────────────────────

func runCrack(args []string) error {
	fs := flag.NewFlagSet("crack", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "hash type (omit or 'auto' to auto-detect)")
	targetHash := fs.String("H", "", "target hash")
	mode := fs.String("M", "dict", "attack mode: dict|brute")
	wordlist := fs.String("w", "", "wordlist path (dict mode; defaults to built-in common.txt)")
	wordlistLong := fs.String("wordlist", "", "alias for -w")
	charset := fs.String("C", "abcdefghijklmnopqrstuvwxyz0123456789", "charset (brute mode)")
	minLen := fs.Int("n", 1, "min length (brute)")
	maxLen := fs.Int("x", 4, "max length (brute)")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode: prefix|suffix")
	workers := fs.Int("p", 0, "parallel workers (0 = NumCPU)")
	outFile := fs.String("o", "", "write result to file")
	copyResult := fs.Bool("c", false, "copy result to clipboard")
	useRules := fs.Bool("r", false, "enable mangling rules in dict mode")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *targetHash == "" {
		return errors.New("-H target hash is required")
	}

	// Resolve wordlist from either -w or its --wordlist alias. An empty value
	// falls through to the built-in common.txt inside doCrack/dictAttack.
	wl := *wordlist
	if wl == "" {
		wl = *wordlistLong
	}

	w := *workers
	if w < 1 {
		w = runtime.NumCPU()
	}
	// An empty/"auto" -t triggers auto-detection (normalization happens inside).
	return crackWithDetection(*targetHash, *typ, *mode, wl, *charset,
		*minLen, *maxLen, w, *salt, *saltMode, *outFile, *copyResult, *useRules)
}

// ── Core engine ──────────────────────────────────────────────────────────────

// doCrack runs a single attack for one concrete hash type and reports whether
// the password was found. It never prints "Not found" itself — the caller
// decides how to report failure (important when several candidate types are
// tried in sequence).
func doCrack(targetHash, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool, useRules bool) (bool, error) {

	start := time.Now()
	var atomicAttempts int64

	// ── pre-count for progress bar ──────────────────────────────────────────
	var total int64 = -1
	m := strings.ToLower(mode)
	if m == "dict" {
		// An empty wordlist path counts the embedded common.txt.
		if n, err := countWordlistLines(wordlist); err == nil {
			total = n
			if useRules {
				// Each word generates up to NumManglingRules extra candidates.
				total *= int64(1 + NumManglingRules)
			}
		}
	} else if m == "brute" {
		total = calcBruteTotal(charset, minLen, maxLen)
	}

	bar := newCrackBar(total)

	// progress ticker — updates bar from atomic counter every 100 ms
	tickCtx, tickCancel := context.WithCancel(context.Background())
	go progressTicker(tickCtx, bar, &atomicAttempts)

	// ── attack ──────────────────────────────────────────────────────────────
	var (
		result crackedResult
		err    error
	)
	switch m {
	case "dict":
		// An empty wordlist path uses the built-in common.txt (see openWordlist).
		result, err = dictAttack(context.Background(), wordlist,
			targetHash, typ, salt, saltMode, workers, &atomicAttempts, useRules)
	case "brute":
		if minLen < 1 || maxLen < minLen {
			tickCancel()
			return false, errors.New("invalid -n/-x range")
		}
		var pw string
		pw, err = bruteAttack(context.Background(), targetHash, typ,
			charset, minLen, maxLen, workers, salt, saltMode, &atomicAttempts)
		result = crackedResult{password: pw}
	default:
		tickCancel()
		return false, errors.New("unknown mode: use dict or brute")
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
	if found {
		clrGreen.Fprint(os.Stderr, "Found: ")
		if result.ruleLabel != "" {
			fmt.Fprintf(os.Stderr, "%s (via rule: %s)\n", result.password, result.ruleLabel)
		} else {
			fmt.Fprintln(os.Stderr, result.password)
		}
		if outFile != "" {
			if e := os.WriteFile(outFile, []byte(result.password+"\n"), 0644); e != nil {
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

// crackReport runs a single-type attack and prints "Not found" on failure.
// Used by callers that already know the concrete hash type (interactive mode).
func crackReport(targetHash, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool, useRules bool) error {
	found, err := doCrack(targetHash, typ, mode, wordlist, charset,
		minLen, maxLen, workers, salt, saltMode, outFile, copyResult, useRules)
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
// tries each in turn until one succeeds — the John-the-Ripper-style workflow.
// Base58/Base64-encoded hashes are normalized to hex first.
func crackWithDetection(rawTarget, explicitType, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool, useRules bool) error {

	target := strings.TrimSpace(rawTarget)
	if normalized, enc := normalizeHashInput(target); enc != "" {
		clrYellow.Fprintf(os.Stderr, "Detected %s encoded hash — normalizing to hex\n", enc)
		target = normalized
	}

	var types []string
	if explicitType != "" && !strings.EqualFold(explicitType, "auto") {
		types = []string{strings.ToLower(explicitType)}
	} else {
		types = detectHashTypes(target)
		if len(types) == 0 {
			return fmt.Errorf("could not auto-detect hash type — specify it with -t "+
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
			minLen, maxLen, workers, salt, saltMode, outFile, copyResult, useRules)
		if err != nil {
			if len(types) == 1 {
				return err
			}
			// One candidate's hash format may be invalid; keep trying the rest.
			clrYellow.Fprintf(os.Stderr, "  (%s not applicable: %v)\n", t, err)
			continue
		}
		if found {
			return nil
		}
	}

	clrYellow.Fprintln(os.Stderr, "Not found")
	return nil
}

// ── Dictionary attack — producer-consumer pipeline ───────────────────────────
//
// One reader goroutine fills a batch channel; N worker goroutines drain it.
// Batch size is dictBatchSize to amortise channel overhead without starving
// workers. Context cancellation propagates through both the reader and workers.

func dictAttack(ctx context.Context, wordlistPath, targetHash, typ, salt, saltMode string,
	workers int, atomicAttempts *int64, useRules bool) (crackedResult, error) {

	f, label, err := openWordlist(wordlistPath)
	if err != nil {
		return crackedResult{}, err
	}
	defer f.Close()
	if label == defaultWordlistLabel {
		clrYellow.Fprintf(os.Stderr, "No wordlist supplied — using %s\n", label)
	}

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
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
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

	// tryCandidate tests one candidate and fires resultCh + cancel on match.
	// Returns true if matched so the caller can short-circuit.
	tryCandidate := func(pw, ruleLabel string) bool {
		atomic.AddInt64(atomicAttempts, 1)
		matched, _ := verifyCandidate(pw, targetHash, typ, salt, saltMode)
		if matched {
			select {
			case resultCh <- crackedResult{password: pw, ruleLabel: ruleLabel}:
			default:
			}
			cancel()
			return true
		}
		return false
	}

	// workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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
						if useRules {
							for _, mc := range expandRules(word) {
								select {
								case <-innerCtx.Done():
									return
								default:
								}
								if tryCandidate(mc.password, mc.ruleLabel) {
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

// ── Brute-force attack — stride-based keyspace division ──────────────────────
//
// The keyspace for each length L is [0, base^L). Worker w processes indices
// w, w+workers, w+2*workers, … giving every worker an independent, contiguous-
// stride slice of the keyspace. No coordination channels needed — only one
// atomic increment per attempt plus a non-blocking context check every
// ctxCheckEvery iterations.

func bruteAttack(ctx context.Context, targetHash, typ, charset string,
	minLen, maxLen, workers int, salt, saltMode string,
	atomicAttempts *int64) (string, error) {

	chars := []rune(charset)
	base := int64(len(chars))
	if base == 0 {
		return "", errors.New("charset must not be empty")
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan string, 1)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			stride := int64(workers)
			for l := minLen; l <= maxLen; l++ {
				// total candidates at this length
				total := int64(1)
				for i := 0; i < l; i++ {
					total *= base
				}
				iter := 0
				for idx := int64(wID); idx < total; idx += stride {
					// non-blocking context poll every ctxCheckEvery iters
					iter++
					if iter >= ctxCheckEvery {
						iter = 0
						select {
						case <-innerCtx.Done():
							return
						default:
						}
					}
					candidate := idxToStr(idx, l, chars, base)
					atomic.AddInt64(atomicAttempts, 1)
					ok, _ := verifyCandidate(candidate, targetHash, typ, salt, saltMode)
					if ok {
						select {
						case resultCh <- candidate:
						default:
						}
						cancel()
						return
					}
				}
			}
		}(w)
	}

	wg.Wait()
	select {
	case pass := <-resultCh:
		return pass, nil
	default:
		return "", nil
	}
}

// idxToStr converts a linear index in [0, base^length) to the corresponding
// candidate string. Output is built as []byte (single allocation) since
// cracking charsets are always ASCII; byte(r) is safe for runes < 128.
func idxToStr(index int64, length int, chars []rune, base int64) string {
	out := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		out[i] = byte(chars[index%base])
		index /= base
	}
	return string(out)
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

// ── Helpers ──────────────────────────────────────────────────────────────────

func calcBruteTotal(charset string, minLen, maxLen int) int64 {
	base := int64(len([]rune(charset)))
	if base == 0 {
		return 0
	}
	var total, power int64
	power = 1
	for i := 1; i <= maxLen; i++ {
		power *= base
		if i >= minLen {
			total += power
		}
	}
	return total
}

// ── Hash verification ─────────────────────────────────────────────────────────

func verifyCandidate(candidate, targetHash, typ, salt, saltMode string) (bool, error) {
	algo := strings.ToLower(typ)
	switch algo {
	case "bcrypt":
		return bcrypt.CompareHashAndPassword([]byte(targetHash), []byte(candidate)) == nil, nil
	case "argon2":
		return verifyArgon2(targetHash, candidate), nil
	case "scrypt":
		return verifyScrypt(targetHash, candidate)
	case "mssql2005", "mssql2012":
		return verifyMSSQL2005(targetHash, candidate)
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
	}
	got, err := hashText(candidate, algo, salt, saltMode)
	if err != nil {
		return false, err
	}
	return got == targetHash, nil
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
	parts := strings.Split(targetHash, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false, errors.New("invalid scrypt hash format")
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, err
	}
	r, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, err
	}
	p, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, err
	}
	saltBytes, err := hex.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	digest, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, err
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
	digest := sha1.Sum(append(saltBytes, utf16le(candidate)...))
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
// Hash format: $7z$<numCyclesPower>$<salt_hex>$<iv_hex>$<crc_hex>$<offset>$<data_hex>
func verify7z(targetHash, candidate string) (bool, error) {
	parts := strings.SplitN(targetHash, "$", 8)
	if len(parts) < 8 || parts[1] != "7z" {
		return false, errors.New("invalid 7z hash format")
	}
	numCyclesPower, err := strconv.Atoi(parts[2])
	if err != nil || numCyclesPower < 0 || numCyclesPower > 32 {
		return false, errors.New("invalid 7z numCyclesPower")
	}
	salt, _ := hex.DecodeString(parts[3])
	iv, err := hex.DecodeString(parts[4])
	if err != nil || len(iv) != 16 {
		return false, errors.New("invalid 7z IV")
	}
	encData, err := hex.DecodeString(parts[7])
	if err != nil || len(encData) < aes.BlockSize {
		return false, errors.New("invalid 7z encrypted data")
	}

	// 7-Zip KDF: single SHA-256 context fed (pw_utf16le || salt || ctr_LE8)
	// for each of 2^numCyclesPower rounds.
	pwBytes := utf16le(candidate)
	h := sha256.New()
	numRounds := uint64(1) << uint(numCyclesPower)
	for i := uint64(0); i < numRounds; i++ {
		h.Write(pwBytes)
		if len(salt) > 0 {
			h.Write(salt)
		}
		var ctr [8]byte
		binary.LittleEndian.PutUint64(ctr[:], i)
		h.Write(ctr[:])
	}
	key := h.Sum(nil) // 32 bytes → AES-256

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	// Two-block structural check:
	//   Block 1: LZMA2 compressed data always has control byte ≥ 0x80.
	//   Block 2: 7-zip zero-pads the LZMA2 stream to a multiple of 16 bytes,
	//            so decrypted block 2 is all-zero with the correct key, but
	//            random (p≈1/2^128) with any wrong key.
	// Combined false-positive probability ≈ 0.
	if len(encData) < aes.BlockSize*2 {
		// Single block available; fall back to a weak first-byte check.
		aligned := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(aligned, encData[:aes.BlockSize])
		return aligned[0] >= 0x80, nil
	}
	aligned2 := make([]byte, aes.BlockSize*2)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(aligned2, encData[:aes.BlockSize*2])

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
// Hash format: $rar3$0$<salt_hex>$<data_hex>
func verifyRAR4(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	if len(parts) != 5 || parts[1] != "rar3" {
		return false, errors.New("invalid rar3 hash format")
	}
	salt, err := hex.DecodeString(parts[3])
	if err != nil || len(salt) != 8 {
		return false, errors.New("invalid rar3 salt (need 8 bytes)")
	}
	encData, err := hex.DecodeString(parts[4])
	if err != nil || len(encData) < 16 {
		return false, errors.New("invalid rar3 encrypted data (need ≥16 bytes)")
	}

	// RAR3 KDF: single SHA-1 context, 262144 (0x40000) rounds.
	// Each round feeds: password_utf16le || salt(8B) || i(3B little-endian).
	pwBytes := utf16le(candidate)
	h := sha1.New()
	for i := 0; i < 0x40000; i++ {
		h.Write(pwBytes)
		h.Write(salt)
		h.Write([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
	}
	digest := h.Sum(nil) // 20 bytes

	key := digest[:16] // AES-128
	iv := make([]byte, 16)
	copy(iv, digest[16:20]) // low 4 bytes of digest; upper 12 stay zero

	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	decrypted := make([]byte, 16)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, encData[:16])

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
func pdfComputeKey(password string, oKey []byte, p int32, docID []byte, revision, keySize int) []byte {
	// Pad or truncate the password to exactly 32 bytes.
	padded := make([]byte, 32)
	n := copy(padded, []byte(password))
	copy(padded[n:], pdfPaddingBytes)

	h := md5.New()
	h.Write(padded)
	h.Write(oKey)
	h.Write([]byte{byte(p), byte(p >> 8), byte(p >> 16), byte(p >> 24)})
	h.Write(docID)
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
// Hash format: $pdf$<R>$<keylenBits>$<P>$<id_hex>$<U_hex>$<O_hex>
func verifyPDF(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	if len(parts) < 8 || parts[1] != "pdf" {
		return false, errors.New("invalid pdf hash format")
	}
	R, _ := strconv.Atoi(parts[2])
	keyLenBits, _ := strconv.Atoi(parts[3])
	P64, _ := strconv.ParseInt(parts[4], 10, 64)
	P := int32(P64)
	docID, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid pdf docID")
	}
	U, err := hex.DecodeString(parts[6])
	if err != nil || len(U) < 16 {
		return false, errors.New("invalid pdf U key (need ≥16 bytes)")
	}
	O, err := hex.DecodeString(parts[7])
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

	key := pdfComputeKey(candidate, O, P, docID, R, keySize)

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
