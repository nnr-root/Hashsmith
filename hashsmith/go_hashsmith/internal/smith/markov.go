package smith

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
	charset    []byte
	positional bool
	// radix is the resolved per-position choice count after threshold
	// truncation — len(first) / len(posFirst[0]), computed once at build
	// time and used directly by decode/markovLayout so both always agree
	// with what was actually built, never re-derived from a separate
	// threshold field.
	radix int

	// live -w-trained path:
	first []byte      // charset ranked by start-frequency (most likely first)
	cond  [256][]byte // cond[c] = charset ranked by P(next | c)

	// hcstat2-loaded path:
	posFirst [256][]byte
	posCond  [256][256][]byte
}

// markovRadix resolves --markov-threshold against a domain size: threshold
// <= 0 means unlimited (keep the whole domain); otherwise the smaller of
// the two.
func markovRadix(threshold, domainSize int) int {
	if threshold <= 0 || threshold > domainSize {
		return domainSize
	}
	return threshold
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
func rankCharset(charset []byte, count *[256]uint64) []byte {
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
func trainMarkov(charset string, wordlistPath string, threshold int) (*markovModel, error) {
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

	var firstCount [256]uint64
	var transCount [256][256]uint64
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

	radix := markovRadix(threshold, len(cs))
	m := &markovModel{charset: cs, radix: radix}
	m.first = rankCharset(cs, &firstCount)[:radix]
	for _, c := range cs {
		tc := transCount[c]
		m.cond[c] = rankCharset(cs, &tc)[:radix]
	}
	return m, nil
}

// loadHCStat2 builds a positional markovModel from a real .hcstat2 file —
// see the design doc's §5 for why every node's ranked list is a uniform
// markovRadix(threshold, 256) long with no padding needed: root/markov are
// already dense over all 256 byte values, so ranking always yields a full
// 256-entry permutation regardless of how sparse the underlying counts are.
func loadHCStat2(path string, threshold int) (*markovModel, error) {
	tables, err := loadHCStat2Tables(path)
	if err != nil {
		return nil, err
	}
	var allBytes [256]byte
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	radix := markovRadix(threshold, 256)
	m := &markovModel{charset: allBytes[:], positional: true, radix: radix}
	for pos := 0; pos < 256; pos++ {
		m.posFirst[pos] = rankCharset(allBytes[:], &tables.root[pos])[:radix]
		for prev := 0; prev < 256; prev++ {
			m.posCond[pos][prev] = rankCharset(allBytes[:], &tables.markov[pos][prev])[:radix]
		}
	}
	return m, nil
}

// decode maps a local index (within one length L) to its Markov-ordered
// candidate: a mixed-radix odometer where the last position varies fastest and
// each position draws from its likelihood ranking given the character to its left.
func (m *markovModel) decode(idx int64, L int) string {
	base := int64(m.radix)
	digits := make([]int, L)
	for p := L - 1; p >= 0; p-- {
		digits[p] = int(idx % base)
		idx /= base
	}
	out := make([]byte, L)
	var prev byte
	for p := 0; p < L; p++ {
		var ranked []byte
		switch {
		case m.positional && p == 0:
			ranked = m.posFirst[0]
		case m.positional:
			ranked = m.posCond[p-1][prev]
		case p == 0:
			ranked = m.first
		default:
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
	base := int64(m.radix)
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
