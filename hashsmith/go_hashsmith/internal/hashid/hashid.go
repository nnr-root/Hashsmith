// Package hashid is Hashsmith's detection engine.
//
// It owns the shape of a detection rule and the rules for combining matches;
// it owns no knowledge of any particular hash format. Callers supply a table
// of prototypes whose Match functions close over their own predicates, so a
// format's detection logic can live beside that format's cracking code.
//
// The engine deliberately reproduces the semantics of the first-match-wins
// cascade it replaces: see Evaluate.
package hashid

// Tier ranks the KIND of evidence a prototype produced, from proof to guess.
// It is the primary input to confidence, ahead of any prevalence weighting.
type Tier uint8

const (
	// TierChecksum: a checksum or polymod verified. Mathematical proof.
	TierChecksum Tier = iota
	// TierSignature: an unambiguous record prefix, e.g. "$2y$" or "$krb5tgs$".
	TierSignature
	// TierStructural: field count, field lengths and encodings all agree.
	TierStructural
	// TierShape: length and alphabet only. The weakest evidence there is.
	TierShape
)

func (t Tier) String() string {
	switch t {
	case TierChecksum:
		return "checksum"
	case TierSignature:
		return "signature"
	case TierStructural:
		return "structural"
	default:
		return "shape"
	}
}

// Input is one candidate string, before and after normalization.
type Input struct {
	Raw        string // exactly what the user supplied
	Normalized string // shadow prefix stripped, base58/base64 decoded to hex
}

// Evidence is the human-readable justification for a match, shown to the user
// and emitted in JSON, e.g. "32-char lowercase hex".
type Evidence string

// Prototype is one detection rule.
type Prototype struct {
	// Types are canonical Hashsmith -t names in the order crack must try them.
	// It is a slice because ordered groups are load-bearing: a "$krb5asrep$23$"
	// record yields {krb5asrep, krb5asrep-nt} and that order is a decision.
	Types []string

	// Display is the human name, e.g. "Kerberos 5 TGS-REP, etype 23".
	Display string

	Tier Tier

	// Exclusive marks a prototype that, on matching, suppresses every
	// lower-precedence prototype. This is how the cascade's early `return` is
	// expressed as data.
	Exclusive bool

	// Match reports whether this prototype recognizes the input.
	Match func(Input) (Evidence, bool)

	// Against is optional negative evidence: it reports a reason THIS input is
	// probably not this format even though the shape fits, e.g. "LM digests are
	// upper-case". It demotes confidence; it never suppresses a match.
	Against func(Input) (string, bool)

	// Compute supplies Types dynamically, for the few cascade branches whose
	// output is calculated rather than fixed — detectBlake2HashcatTypes and
	// detectCompatSaltedTypes both return a variable list. A prototype sets
	// EITHER Types or Compute, never both. Compute runs at this prototype's own
	// table position, which is the whole point: calling those functions from
	// outside the table would run them ahead of every prototype, and
	// detectCompatSaltedTypes sits near the END of the cascade.
	//
	// When Compute is set, Match is ignored: returning types IS the match.
	Compute func(Input) ([]string, bool)

	// Prevalence is a curated 0-100 weight used only to order candidates that
	// carry equally strong evidence. It never promotes past "likely".
	Prevalence uint8

	// Rationale records WHY Prevalence is what it is. It may not be empty; a
	// test enforces this, because an unexplained weight is an unfalsifiable
	// claim about the world.
	Rationale string
}

// Match is one prototype's verdict on one input.
type Match struct {
	Proto      *Prototype
	Evidence   Evidence
	Computed   []string // set instead of Proto.Types when Proto.Compute matched
	Suppressed bool     // ruled out by a higher-precedence exclusive match
}

// Types returns the candidate names this match contributes, from whichever of
// the two sources the prototype uses.
func (m Match) Types() []string {
	if m.Proto.Compute != nil {
		return m.Computed
	}
	return m.Proto.Types
}
