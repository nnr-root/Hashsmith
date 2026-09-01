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
