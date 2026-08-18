package main

// Markov statistical ordering — a brute-force whose candidates are enumerated in
// order of likelihood rather than lexicographically. A first-order model is
// trained from a wordlist: how often each character starts a word, and how often
// each character follows each other character. Positions are then filled with
// their most-likely characters first, so common passwords surface far earlier
// than the naive aaaa…zzzz sweep would reach them.
//
// The candidate for a global index is a pure function of that index (a mixed-
// radix odometer over per-position likelihood rankings), so Markov runs plug
// into the same resumable, parallel keyspace runner as plain brute-force.

import (
	"bufio"
	"sort"
	"strings"
)

type markovModel struct {
	charset []byte
	first   []byte      // charset ranked by start-frequency (most likely first)
	cond    [256][]byte // cond[c] = charset ranked by P(next | c)
}

// dedupeBytes returns the unique bytes of s preserving first-seen order.
func dedupeBytes(s string) []byte {
	var seen [256]bool
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			out = append(out, s[i])
		}
	}
	return out
}

// rankCharset orders the charset by count desc, breaking ties by original index
// so every ranking is a full permutation (unseen chars fall to the end).
func rankCharset(charset []byte, count *[256]int64) []byte {
	idx := make([]int, len(charset))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return count[charset[idx[a]]] > count[charset[idx[b]]]
	})
	out := make([]byte, len(charset))
	for i, j := range idx {
		out[i] = charset[j]
	}
	return out
}

// trainMarkov builds a first-order model over charset from a wordlist.
func trainMarkov(charset string, wordlistPath string) (*markovModel, error) {
	cs := dedupeBytes(charset)
	var inCS [256]bool
	for _, c := range cs {
		inCS[c] = true
	}

	f, _, err := openWordlist(wordlistPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var firstCount [256]int64
	var transCount [256][256]int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		word := strings.TrimSpace(sc.Text())
		if word == "" {
			continue
		}
		var prev byte
		havePrev := false
		for i := 0; i < len(word); i++ {
			c := word[i]
			if !inCS[c] {
				havePrev = false
				continue
			}
			if !havePrev {
				firstCount[c]++
			} else {
				transCount[prev][c]++
			}
			prev = c
			havePrev = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	m := &markovModel{charset: cs}
	m.first = rankCharset(cs, &firstCount)
	for _, c := range cs {
		tc := transCount[c]
		m.cond[c] = rankCharset(cs, &tc)
	}
	return m, nil
}

// decode maps a local index (within one length L) to its Markov-ordered
// candidate: a mixed-radix odometer where the last position varies fastest and
// each position draws from its likelihood ranking given the character to its left.
func (m *markovModel) decode(idx int64, L int) string {
	base := int64(len(m.charset))
	digits := make([]int, L)
	for p := L - 1; p >= 0; p-- {
		digits[p] = int(idx % base)
		idx /= base
	}
	out := make([]byte, L)
	var prev byte
	for p := 0; p < L; p++ {
		var ranked []byte
		if p == 0 {
			ranked = m.first
		} else {
			ranked = m.cond[prev]
		}
		out[p] = ranked[digits[p]]
		prev = out[p]
	}
	return string(out)
}

// markovLayout builds a resumable keyspace layout that decodes each global index
// through the Markov model (one length segment per length in [minLen, maxLen]).
func markovLayout(m *markovModel, minLen, maxLen int) *keyspaceLayout {
	base := int64(len(m.charset))
	var offs []int64
	var lens []int
	var off int64
	for L := minLen; L <= maxLen; L++ {
		offs = append(offs, off)
		lens = append(lens, L)
		p := int64(1)
		for k := 0; k < L; k++ {
			p *= base
		}
		off += p
	}
	layout := &keyspaceLayout{total: off}
	layout.gen = func(i int64) string {
		seg := 0
		for seg+1 < len(offs) && offs[seg+1] <= i {
			seg++
		}
		return m.decode(i-offs[seg], lens[seg])
	}
	return layout
}
