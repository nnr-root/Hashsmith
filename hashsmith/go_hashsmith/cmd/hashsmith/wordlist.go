package main

import (
	"bufio"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"strings"
)

// embeddedCommonWordlist is the bundled common.txt, compiled directly into the
// binary via go:embed. Because it lives inside the executable, dictionary
// attacks work from any working directory and even when the package is
// pip-installed without the external wordlists/ directory.
//
// The file is in two parts, and the split is the point.
//
// The first 3,583 lines are real passwords in frequency order — commonest
// first — so a run that gives up after a few thousand candidates has spent
// them on the candidates most likely to hit. The rest is an English word list
// in alphabetical order. Dictionary words are genuinely used as passwords,
// which is why they stay, but they carry no frequency signal and so they go
// after everything that does.
//
// It used to be the other way round in all but 111 lines. The measurement
// that showed it: of the 3,545 entries in John the Ripper's default
// password.lst, the whole 230,930-line list contained 1,839 anywhere at all,
// and just 91 within its first 5,000 lines. A Hashsmith run that tried 5,000
// candidates from its own default was therefore trying 91 real passwords,
// where John's default would have tried 3,545 — the list was long without
// being useful, because after those 111 curated entries it was an
// alphabetical dictionary and nothing else.
//
// password.lst is merged in as the frequency data the list was missing. Its
// author, Solar Designer of the Openwall Project, states in its header that it
// is assumed to be in the public domain; it was compiled 1996-2011 from Unix
// systems and from public "top N passwords" lists, and is ordered by
// decreasing frequency. The two orderings are combined by reciprocal rank
// fusion, which is the ordinary way to merge two ranked lists that share no
// scale: an entry near the top of either rises, an entry near the top of both
// rises further, and neither list's ordering is destroyed by the other.
//
//go:embed common.txt
var embeddedCommonWordlist string

// defaultWordlistLabel is shown to the user when the built-in list is used.
const defaultWordlistLabel = "built-in common.txt"

// gzipMagic is the two-byte header every gzip stream starts with (RFC 1952).
// Wordlists are detected by CONTENT, not by a ".gz" suffix: Kali ships
// rockyou.txt.gz, but operators also gunzip it and keep the name, or hand a
// gzip stream to -w under any name at all. Sniffing the magic bytes makes both
// work; trusting the extension would silently feed compressed bytes to the
// attack as if they were candidate passwords — a run that tries a few thousand
// bytes of binary garbage and reports "not found".
var gzipMagic = [2]byte{0x1f, 0x8b}

// wordlistReadCloser wraps a decompressing (or plain) reader together with the
// underlying file so Close releases both. gzip.Reader.Close does not close the
// file it was reading from.
type wordlistReadCloser struct {
	r      io.Reader
	closes []io.Closer
}

func (w *wordlistReadCloser) Read(p []byte) (int, error) { return w.r.Read(p) }

func (w *wordlistReadCloser) Close() error {
	var firstErr error
	for _, c := range w.closes {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// openWordlist returns a reader for the requested wordlist. An empty path
// selects the embedded common.txt, so callers can omit -w / --wordlist and
// still get a working default. The returned label describes the source for
// user-facing messages.
//
// A gzip-compressed wordlist is decompressed transparently, so `-w
// rockyou.txt.gz` works without a preparatory gunzip step. Detection is by
// magic bytes (see gzipMagic), so it is the file's content that decides, not
// its name.
func openWordlist(path string) (io.ReadCloser, string, error) {
	if strings.TrimSpace(path) == "" {
		return io.NopCloser(strings.NewReader(embeddedCommonWordlist)), defaultWordlistLabel, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	// bufio.Reader lets the magic bytes be inspected and then put back, so a
	// plain-text list is handed on with nothing consumed.
	br := bufio.NewReaderSize(f, 1<<16)
	if readerLooksGzipped(br) {
		zr, zerr := gzip.NewReader(br)
		if zerr != nil {
			f.Close()
			return nil, "", fmt.Errorf("%s: looks gzip-compressed but cannot be decompressed: %w", path, zerr)
		}
		return &wordlistReadCloser{r: zr, closes: []io.Closer{zr, f}}, path, nil
	}
	return &wordlistReadCloser{r: br, closes: []io.Closer{f}}, path, nil
}

// readerLooksGzipped peeks at the first two bytes without consuming them when
// given a *bufio.Reader, and reads them destructively otherwise. Callers that
// pass a raw file (resolveWordlist's env check) only want the answer and close
// the handle immediately.
func readerLooksGzipped(r io.Reader) bool {
	if br, ok := r.(*bufio.Reader); ok {
		head, err := br.Peek(2)
		return err == nil && head[0] == gzipMagic[0] && head[1] == gzipMagic[1]
	}
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return false
	}
	return head == gzipMagic
}

// isGzipFile reports whether path exists and begins with the gzip magic bytes.
// A missing or unreadable file is simply "not gzip" — this is only used to
// label the source line, never to decide whether a run may proceed.
func isGzipFile(path string) bool {
	// Only a regular file may be inspected. readerLooksGzipped's non-bufio
	// branch READS the first two bytes, and for a pipe, FIFO or /dev/stdin
	// those bytes are gone for good: the attack that follows re-opens the same
	// stream and starts two bytes in, so `printf 'password\n' | hashsmith
	// crack ... -w /dev/stdin` silently tried "ssword" and reported the
	// password uncrackable. This label is cosmetic — it names the source in one
	// status line — and must never cost the run its first candidate.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return readerLooksGzipped(f)
}

// wordlistCountable reports whether a wordlist can be pre-counted for the
// progress bar without harm. Non-regular inputs — pipes, FIFOs, process
// substitution (/dev/fd/N), stdin — are one-shot streams: reading them to count
// lines would consume the data before the attack runs, so they are skipped (the
// progress bar is simply left indeterminate). The embedded default re-reads from
// memory and is always countable.
//
// A gzip file IS countable: it is a regular file, so counting re-opens it and
// the attack that follows gets a fresh, complete stream. The cost is one extra
// decompression pass, which is why the source line says "gzip" — see
// countWordlistLines.
func wordlistCountable(path string) bool {
	if strings.TrimSpace(path) == "" {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

// countWordlistLines counts the non-empty lines of a wordlist (embedded default
// when path is empty) so the progress bar can show an accurate total. It returns
// -1 for non-seekable inputs, which must not be read twice (see wordlistCountable).
//
// For a gzip wordlist there is no shortcut: the decompressed line count is not
// recorded anywhere in the container, so the only honest answer comes from
// decompressing the whole file. That is what happens here — a full pass over a
// freshly opened handle, leaving the attack's own stream untouched. The
// alternatives were both worse: guessing from the compressed size would report
// a WRONG count (a number --keyspace hands to a script to divide), and
// returning -1 would drop the progress total for the single most common
// discovered wordlist on Kali.
func countWordlistLines(path string) (int64, error) {
	if !wordlistCountable(path) {
		return -1, nil
	}
	rc, _, err := openWordlist(path)
	if err != nil {
		return -1, err
	}
	defer rc.Close()

	var n int64
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n, scanner.Err()
}
