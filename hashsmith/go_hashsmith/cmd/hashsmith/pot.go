package main

// The potfile records every cracked hash as a `hash<TAB>plaintext` line so later
// runs can skip work already done. Lookups are keyed by the exact target-hash
// string. A TAB separator keeps the format unambiguous even for hashes that
// themselves contain ':' (NetNTLMv2, Kerberos, HMAC:salt, …).

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type potfile struct {
	path string
	mu   sync.Mutex
	seen map[string]string // targetHash -> plaintext
}

// hashsmithDir is the per-user state directory (~/.hashsmith), holding the
// potfile and saved sessions.
func hashsmithDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".hashsmith")
}

func defaultPotPath() string { return filepath.Join(hashsmithDir(), "hashsmith.pot") }

// loadPotfile reads existing entries. A missing file yields an empty, ready pot.
func loadPotfile(path string) (*potfile, error) {
	if path == "" {
		path = defaultPotPath()
	}
	p := &potfile{path: path, seen: map[string]string{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '\t'); i > 0 {
			p.seen[line[:i]] = line[i+1:]
		}
	}
	return p, sc.Err()
}

// verifiedPlain returns a recorded plaintext only when it actually verifies
// against this target, and reports separately when an entry exists that does
// not.
//
// The potfile is keyed by the target string alone, and a target string does
// not say what it is. "8846f7eaee8fb117ad06bdd830b7586c" is an NTLM hash and
// also a well-formed MD5, so a run that cracked it as NTLM used to make
// `--show -t md5` answer "password" for a digest whose MD5 preimage is
// something else entirely — a wrong password, reported confidently, which is
// the one thing this tool is not allowed to do.
//
// Tagging new entries with their type would stop it happening again but would
// not fix a single existing potfile, and a tag only records what the cracker
// BELIEVED when it wrote the line. Re-deriving the hash from the recorded
// plaintext checks the claim itself, costs one hash per hit, and fixes files
// already on disk. The same check catches the other way this key can collide:
// the same digest string cracked under two different external salts.
//
// A hit that does not verify is not silently dropped — the status says the
// potfile holds an entry which is not this hash's, so the caller can say so.
//
// The third status matters as much as the other two. Some records cannot be
// re-derived from the plaintext alone — a format whose reader needs a file
// that is no longer to hand, or a type this build detects under a name the
// cracking run did not use — and for those the check returns an error rather
// than a verdict. Treating "could not check" as "wrong" would withhold a
// correct answer, which is its own kind of wrong report, so it is reported as
// what it is: a hit nobody could confirm.
type potHitStatus int

const (
	potMiss      potHitStatus = iota // no entry for this string
	potVerified                      // the entry's plaintext re-derives this hash
	potStale                         // it does not: the entry belongs to another hash
	potUnchecked                     // no candidate type returned a verdict either way
)

func (p *potfile) verifiedPlain(target, explicitType, salt, saltMode string) (string, potHitStatus) {
	plain, found := p.lookup(target)
	if !found {
		return "", potMiss
	}
	types := []string{strings.ToLower(explicitType)}
	if explicitType == "" || strings.EqualFold(explicitType, "auto") {
		types = detectHashTypes(target)
	}
	checked := false
	for _, t := range types {
		good, err := verifyCandidate(plain, target, t, salt, saltMode)
		if err != nil {
			continue
		}
		if good {
			return plain, potVerified
		}
		checked = true
	}
	if !checked {
		return plain, potUnchecked
	}
	return plain, potStale
}

func (p *potfile) lookup(hash string) (string, bool) {
	if p == nil {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.seen[hash]
	return v, ok
}

// allPlains returns every plaintext currently on record, in indeterminate
// order — used by --loopback to seed its first pass with real passwords
// already known from this environment. Safe on a nil receiver.
func (p *potfile) allPlains() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.seen))
	for _, v := range p.seen {
		out = append(out, v)
	}
	return out
}

// add records a newly cracked hash, appending it to the file. Duplicate hashes
// are ignored. Failures to persist are non-fatal (the crack still succeeded).
func (p *potfile) add(hash, plain string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[hash]; ok {
		return
	}
	p.seen[hash] = plain
	if err := os.MkdirAll(filepath.Dir(p.path), 0700); err != nil {
		return
	}
	f, err := os.OpenFile(p.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\t%s\n", hash, plain)
}

// potStaleMessage explains a potfile entry that does not belong to this
// target. It is worth saying out loud rather than ignoring: it means an
// earlier run cracked this same STRING as something else — most often the
// same digest read as a different type, or the same digest with a different
// external salt — and the entry is not this hash's answer.
func potStaleMessage(typ string) string {
	as := "as this type"
	if typ != "" && !strings.EqualFold(typ, "auto") {
		as = "as " + strings.ToLower(typ)
	}
	return "Not in potfile: there is an entry for this exact string, but its " +
		"plaintext does not verify " + as + " — an earlier run recorded it under a " +
		"different type or salt, so it is not this hash's answer"
}

// potUncheckedNote marks an answer taken from the potfile that could not be
// re-derived. The answer is still reported, because it is the best thing known
// about this hash; the note says only that nothing confirmed it here.
const potUncheckedNote = " (from the potfile; this build could not re-check it)"
