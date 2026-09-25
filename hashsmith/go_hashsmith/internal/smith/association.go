package smith

// ── -M association: hashcat's association attack (-a 9) ─────────────────────
//
// Every other attack mode (dict, brute, mask, hybrid, combinator, markov,
// prince) broadcasts ONE candidate stream to every target. Association
// attack inverts that, the same way --single already does: the target at
// line i is tried ONLY against the word at line i of each companion
// wordlist — never against any other target's word. Where --single derives
// its per-target seed from that account's own username, association attack
// takes it directly from one or more caller-supplied wordlists, each
// independently paired with the target list by line position — hashcat's
// own rule for this attack: "the wordlist must be exactly the same length
// as the target hash list." Rules (-r/--rules) still apply, expanding each
// tiny per-target seed set the same way they expand any dict-mode wordlist.
//
// Unlike hashcat, this does not require every target to share a salt or
// cost factor. That requirement exists in hashcat only so one compiled GPU
// kernel can serve the whole batch; Hashsmith already verifies every
// candidate against every target independently (see crackTargets), so
// nothing here needs that uniformity — a dump of targets with different
// salts pairs and cracks exactly the same as one with a shared salt.
//
// THE PROPERTY THAT MATTERS, same as --single: a word paired with one
// target must never be tried against a different target. Enforced
// structurally here — one target at a time, via a length-1 crackTargets
// call — not by filtering results after the fact.

import (
	"fmt"
	"os"
)

// loadAssociationWordlist reads path and returns its lines verbatim
// (including empty ones — see loadWordlistSlice). Returns an error if the
// line count does not exactly match wantLines: a length mismatch means the
// per-line pairing this attack depends on cannot be established, and
// running anyway would silently pair the wrong word with the wrong target.
func loadAssociationWordlist(path string, wantLines int) ([]string, error) {
	words, _, err := loadWordlistSlice(path)
	if err != nil {
		return nil, err
	}
	if len(words) != wantLines {
		return nil, fmt.Errorf("association wordlist %q has %d line(s), want %d (one per target, in the same order)",
			path, len(words), wantLines)
	}
	return words, nil
}

// runAssociationCrack tries, for the target at line i, the word at line i
// from every companion wordlist (one candidate per wordlist — hashcat pairs
// each wordlist independently with the target list, it does not
// concatenate them) — with rules applied, against that target alone, via
// the same length-1 crackTargets recursion --single's own runSingleCrack
// uses. wordlists[k][i] is wordlist k's word for target i; every slice in
// wordlists is already known to have exactly len(lines) entries (checked by
// loadAssociationWordlist before this is called).
func runAssociationCrack(lines []inputLine, wordlists [][]string, typ string, workers int,
	salt, saltMode, outFile string, copyResult bool, rules *ruleEngine, cc *crackCtx) error {
	if cc == nil || cc.showOnly {
		return nil
	}

	savedSkip, savedLimit := cc.skip, cc.limit
	cc.skip, cc.limit = 0, 0
	defer func() { cc.skip, cc.limit = savedSkip, savedLimit }()

	attacked := 0
	for i, l := range lines {
		if cc.wasFound(l.hash) {
			continue // already cracked by an earlier line's pairing
		}

		// A target repeated at more than one line is not deduplicated here
		// (unlike --single's processed[hash] check): each occurrence has
		// its OWN paired word, from its OWN line, and both are genuinely
		// worth trying — deduplicating by hash would silently drop one.
		seen := make(map[string]bool, len(wordlists))
		seeds := make([]string, 0, len(wordlists))
		for _, wl := range wordlists {
			w := wl[i]
			if w == "" || seen[w] {
				continue
			}
			seen[w] = true
			seeds = append(seeds, w)
		}
		if len(seeds) == 0 {
			continue
		}

		tmp, err := writeTempWordlist(seeds)
		if err != nil {
			return fmt.Errorf("association attack: %w", err)
		}
		attacked++
		runErr := crackTargets([]string{l.hash}, typ, "dict", tmp, "", 0, 0, workers,
			salt, saltMode, outFile, copyResult, rules, nil, cc)
		os.Remove(tmp)
		if runErr != nil {
			return fmt.Errorf("association attack (target line %d): %w", i+1, runErr)
		}
	}
	if attacked > 0 {
		clrGreen.Fprintf(os.Stderr, "Association attack: tried paired candidates against %d target(s)\n", attacked)
	}
	return nil
}
