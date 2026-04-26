package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
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
	"golang.org/x/crypto/scrypt"
)

const (
	dictBatchSize = 512  // words per batch sent over channel
	ctxCheckEvery = 1024 // brute-force iterations between context polls
)

// ── CLI entry ────────────────────────────────────────────────────────────────

func runCrack(args []string) error {
	fs := flag.NewFlagSet("crack", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("t", "", "hash type")
	targetHash := fs.String("H", "", "target hash")
	mode := fs.String("M", "dict", "attack mode: dict|brute")
	wordlist := fs.String("w", "", "wordlist path (dict mode)")
	charset := fs.String("C", "abcdefghijklmnopqrstuvwxyz0123456789", "charset (brute mode)")
	minLen := fs.Int("n", 1, "min length (brute)")
	maxLen := fs.Int("x", 4, "max length (brute)")
	salt := fs.String("s", "", "salt")
	saltMode := fs.String("S", "prefix", "salt mode: prefix|suffix")
	workers := fs.Int("p", 0, "parallel workers (0 = NumCPU)")
	outFile := fs.String("o", "", "write result to file")
	copyResult := fs.Bool("c", false, "copy result to clipboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *typ == "" {
		return errors.New("-t type is required")
	}
	if *targetHash == "" {
		return errors.New("-H target hash is required")
	}

	// Normalize Base58/Base64 encoded hash bytes to hex before the attack loop.
	target := *targetHash
	if normalized, enc := normalizeHashInput(target); enc != "" {
		clrYellow.Fprintf(os.Stderr, "Detected %s encoded hash — normalizing to hex\n", enc)
		target = normalized
	}

	w := *workers
	if w < 1 {
		w = runtime.NumCPU()
	}
	return doCrack(target, *typ, *mode, *wordlist, *charset,
		*minLen, *maxLen, w, *salt, *saltMode, *outFile, *copyResult)
}

// ── Core engine ──────────────────────────────────────────────────────────────

func doCrack(targetHash, typ, mode, wordlist, charset string,
	minLen, maxLen, workers int,
	salt, saltMode, outFile string, copyResult bool) error {

	start := time.Now()
	var atomicAttempts int64

	// ── pre-count for progress bar ──────────────────────────────────────────
	var total int64 = -1
	m := strings.ToLower(mode)
	if m == "dict" && wordlist != "" {
		if n, err := countFileLines(wordlist); err == nil {
			total = n
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
		password string
		err      error
	)
	switch m {
	case "dict":
		if wordlist == "" {
			tickCancel()
			return errors.New("-w wordlist is required for dict mode")
		}
		password, err = dictAttack(context.Background(), wordlist,
			targetHash, typ, salt, saltMode, workers, &atomicAttempts)
	case "brute":
		if minLen < 1 || maxLen < minLen {
			tickCancel()
			return errors.New("invalid -n/-x range")
		}
		password, err = bruteAttack(context.Background(), targetHash, typ,
			charset, minLen, maxLen, workers, salt, saltMode, &atomicAttempts)
	default:
		tickCancel()
		return errors.New("unknown mode: use dict or brute")
	}

	tickCancel()
	_ = bar.Finish()
	fmt.Fprintln(os.Stderr) // newline after bar
	if err != nil {
		return err
	}

	elapsed := time.Since(start).Seconds()
	attempts := atomic.LoadInt64(&atomicAttempts)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(attempts) / elapsed
	}

	if password != "" {
		clrGreen.Fprint(os.Stderr, "Found: ")
		fmt.Fprintln(os.Stderr, password)
		if outFile != "" {
			if e := os.WriteFile(outFile, []byte(password+"\n"), 0644); e != nil {
				return e
			}
			clrGreen.Fprintf(os.Stderr, "Saved to %s\n", outFile)
		}
		if copyResult {
			if copyToClipboard(password) {
				clrGreen.Fprintln(os.Stderr, "Copied to clipboard")
			} else {
				clrYellow.Fprintln(os.Stderr, "Unable to copy to clipboard")
			}
		}
	} else {
		clrYellow.Fprintln(os.Stderr, "Not found")
	}
	color.New(themeAttr).Fprintf(os.Stderr,
		"Attempts: %d | Elapsed: %.2fs | Rate: %s\n",
		attempts, elapsed, formatRate(rate))
	return nil
}

// ── Dictionary attack — producer-consumer pipeline ───────────────────────────
//
// One reader goroutine fills a batch channel; N worker goroutines drain it.
// Batch size is dictBatchSize to amortise channel overhead without starving
// workers. Context cancellation propagates through both the reader and workers.

func dictAttack(ctx context.Context, wordlistPath, targetHash, typ, salt, saltMode string,
	workers int, atomicAttempts *int64) (string, error) {

	f, err := os.Open(wordlistPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type batch = []string
	batchCh := make(chan batch, workers*4)
	resultCh := make(chan string, 1)

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
						atomic.AddInt64(atomicAttempts, 1)
						matched, _ := verifyCandidate(word, targetHash, typ, salt, saltMode)
						if matched {
							select {
							case resultCh <- word:
							default:
							}
							cancel()
							return
						}
					}
				}
			}
		}()
	}

	wg.Wait()
	select {
	case pass := <-resultCh:
		return pass, nil
	default:
		return "", nil
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

func countFileLines(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	var n int64
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n, scanner.Err()
}

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
	}
	got, err := hashText(candidate, algo, salt, saltMode)
	if err != nil {
		return false, err
	}
	return got == targetHash, nil
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
