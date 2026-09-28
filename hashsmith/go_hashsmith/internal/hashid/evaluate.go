package hashid

import "sort"

// Evaluate runs every prototype in table order and applies the suppression
// rule. The returned slice is in table order and includes suppressed matches,
// marked as such, so identify can show a user what was ruled out.
//
// Suppression reproduces the cascade this engine replaces:
//
//   - If any Exclusive prototype matched, the EARLIEST one in table order wins
//     outright. Every other match — before or after it — is marked suppressed.
//     This is the cascade's early `return`.
//   - If none did, no match is suppressed. This is the cascade's trailing
//     length switch, which returns several candidates at once.
//
// A non-exclusive prototype never suppresses anything.
func Evaluate(table []Prototype, in Input) []Match {
	var matches []Match
	winner := -1
	for i := range table {
		p := &table[i]
		var (
			ev       Evidence
			ok       bool
			computed []string
		)
		switch {
		case p.Compute != nil:
			computed, ok = p.Compute(in)
			ev = Evidence("computed candidate set")
		case p.Match != nil:
			ev, ok = p.Match(in)
		}
		if !ok {
			continue
		}
		if winner < 0 && p.Exclusive {
			winner = len(matches)
		}
		matches = append(matches, Match{Proto: p, Evidence: ev, Computed: computed})
	}
	if winner >= 0 {
		for i := range matches {
			matches[i].Suppressed = i != winner
		}
	}
	return matches
}

// evaluateUntilExclusive is Evaluate's fast path for DetectTypes. Evaluate's
// suppression rule marks every match OTHER than the first Exclusive one
// suppressed — before or after it in table order — so DetectTypes' output is
// provably exactly that single winning match's Types once an Exclusive
// prototype matches: every prototype after it in the table cannot change the
// result. Scanning stops the instant that first Exclusive match is found,
// instead of running the remaining ~250 prototypes only to mark them
// suppressed and then discard them.
//
// When no Exclusive prototype matches at all, Evaluate never suppresses
// anything, so this returns every match found across the whole table —
// exactly what Evaluate would have returned filtered to the unsuppressed set.
//
// Used ONLY by DetectTypes. Evaluate itself is left untouched: Identify needs
// the full match set, suppressed entries included, to show a user what was
// ruled out and why.
func evaluateUntilExclusive(table []Prototype, in Input) []Match {
	var matches []Match
	for i := range table {
		p := &table[i]
		var (
			ev       Evidence
			ok       bool
			computed []string
		)
		switch {
		case p.Compute != nil:
			computed, ok = p.Compute(in)
			ev = Evidence("computed candidate set")
		case p.Match != nil:
			ev, ok = p.Match(in)
		}
		if !ok {
			continue
		}
		if p.Exclusive {
			return []Match{{Proto: p, Evidence: ev, Computed: computed}}
		}
		matches = append(matches, Match{Proto: p, Evidence: ev, Computed: computed})
	}
	return matches
}

// DetectTypes returns the canonical -t names crack should try, in order. It is
// exactly the unsuppressed matches' Types, de-duplicated.
// Ranked is one detected type together with the strength of the evidence
// behind it, which is what an attack order has to be built from.
type Ranked struct {
	Type       string
	Tier       Tier
	Prevalence uint8
}

// Rare reports a type this engine offers only because nothing rules it out:
// a shape match on a digest width, for an algorithm too scarce to be a real
// guess. These are worth trying — they are the whole reason an obscure hash
// is crackable at all — but only after everything likelier has failed.
func (r Ranked) Rare() bool { return r.Tier == TierShape && r.Prevalence < extinctPrevalence }

// DetectRanked returns the candidate types in the order they should be
// attacked: strongest evidence first, and within one tier the commonest
// algorithm first.
//
// Table order decides nothing here, which matters because the table is
// grouped by family for a reader's benefit. A 32-character hex string matches
// MD5, MD4, MD2, NTLM, LM and a dozen scarcer digests; whichever order those
// happen to sit in, MD5 and NTLM are what to try first and MD2 is not.
func DetectRanked(table []Prototype, in Input) []Ranked {
	matches := evaluateUntilExclusive(table, in)
	var out []Ranked
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		for _, t := range m.Types() {
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, Ranked{Type: t, Tier: m.Proto.Tier, Prevalence: m.Proto.Prevalence})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tier != out[j].Tier {
			return out[i].Tier < out[j].Tier
		}
		return out[i].Prevalence > out[j].Prevalence
	})
	return out
}

// DetectTypes returns just the names, in the same order.
func DetectTypes(table []Prototype, in Input) []string {
	ranked := DetectRanked(table, in)
	if len(ranked) == 0 {
		return nil
	}
	out := make([]string, len(ranked))
	for i, r := range ranked {
		out[i] = r.Type
	}
	return out
}
