package hashid

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

// DetectTypes returns the canonical -t names crack should try, in order. It is
// exactly the unsuppressed matches' Types, de-duplicated.
func DetectTypes(table []Prototype, in Input) []string {
	matches := Evaluate(table, in)
	var out []string
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if m.Suppressed {
			continue
		}
		for _, t := range m.Types() {
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}
