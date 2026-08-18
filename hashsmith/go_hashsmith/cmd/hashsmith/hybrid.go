package main

// Hybrid attack — a dictionary attack whose every word is extended by a mask.
// For each wordlist word, all expansions of the mask are appended (word+mask)
// or prepended (mask+word), so `password` + `?d?d?d?d` tries password0000 …
// password9999. It combines the coverage of a wordlist with the structured
// brute-force of a mask, which is how most real passwords are built: a base word
// plus a trailing year / digits / symbol.
//
// Words stream through the same producer/consumer pipeline as the dictionary
// attack; each word's mask keyspace is enumerated by the worker that owns it.
// The verify closure is supplied by the caller, so hybrid runs benefit from the
// zero-allocation fast verifier (single target) or the multi-hash set check
// (a whole dump) exactly like the other modes.

func hybridLayout(words []string, sets [][]byte, maskFirst bool) *keyspaceLayout {
	mtotal := maskKeyspace(sets)
	layout := &keyspaceLayout{total: int64(len(words)) * mtotal}
	if mtotal == 0 || len(words) == 0 {
		return layout
	}
	maskLen := len(sets)
	layout.gen = func(i int64) string {
		w := words[i/mtotal]
		mi := i % mtotal
		buf := make([]byte, len(w)+maskLen)
		if maskFirst {
			copy(buf[maskLen:], w)
			maskIdxInto(buf[:maskLen], mi, sets)
		} else {
			copy(buf[:len(w)], w)
			maskIdxInto(buf[len(w):], mi, sets)
		}
		return string(buf)
	}
	return layout
}
