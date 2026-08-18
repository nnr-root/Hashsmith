package main

// Combinator attack — concatenate every word of a left list with every word of a
// right list: `super` + `man` → `superman`. It cracks passphrase-style passwords
// built from two real words (two names, adjective+noun, word+word) that neither a
// plain wordlist nor a mask would reach. Keyspace is |left| × |right|.
//
// The right list is held in memory (it is scanned in full for every left word);
// the left list streams through the same producer/consumer pipeline as the other
// modes, so combinator inherits the fast verifier and multi-hash set check via
// the caller-supplied verify closure.

import (
	"bufio"
	"strings"
)

// loadWordlistSlice reads an entire wordlist into memory (trimmed, blanks
// dropped). Used for the combinator right-hand list.
func loadWordlistSlice(path string) ([]string, string, error) {
	f, label, err := openWordlist(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if w := strings.TrimSpace(sc.Text()); w != "" {
			out = append(out, w)
		}
	}
	return out, label, sc.Err()
}

func combinatorLayout(left, right []string) *keyspaceLayout {
	R := int64(len(right))
	layout := &keyspaceLayout{total: int64(len(left)) * R}
	if R == 0 || len(left) == 0 {
		return layout
	}
	layout.gen = func(i int64) string {
		return left[i/R] + right[i%R]
	}
	return layout
}
