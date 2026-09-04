package hashid

import "sort"

// Confidence is what the tool is willing to assert about a candidate. It is
// deliberately a small ordinal set rather than a percentage: the engine has no
// basis for computing a probability and should not imply that it does.
type Confidence uint8

const (
	Certain Confidence = iota
	Likely
	Possible
	Unlikely
)

func (c Confidence) String() string {
	switch c {
	case Certain:
		return "certain"
	case Likely:
		return "likely"
	case Possible:
		return "possible"
	default:
		return "unlikely"
	}
}

// Thresholds for shape-tier prevalence. Below dominantPrevalence a shape match
// stays "possible"; below extinctPrevalence it is demoted to "unlikely" and
// cites its rationale.
const (
	dominantPrevalence = 60
	extinctPrevalence  = 15
)

// Candidate is one identification result, ready to render.
type Candidate struct {
	Type       string // canonical -t name
	Display    string
	Confidence Confidence
	Tier       Tier
	Evidence   Evidence
	Reason     string // why it was demoted, when it was
	Suppressed bool
}

// Identify converts an evaluation into ranked candidates.
//
// Confidence comes from structural evidence first and curated prevalence only
// second: prevalence breaks ties and can demote, but never promotes a shape
// match past Likely.
func Identify(table []Prototype, in Input) []Candidate {
	matches := Evaluate(table, in)

	// A match is "rivalled" when another unsuppressed match survives alongside
	// it, which is what separates a definitive answer from a shortlist.
	live := 0
	for _, m := range matches {
		if !m.Suppressed {
			live++
		}
	}

	var out []Candidate
	for _, m := range matches {
		p := m.Proto
		for _, typ := range m.Types() {
			c := Candidate{
				Type: typ, Display: p.Display, Tier: p.Tier,
				Evidence: m.Evidence, Suppressed: m.Suppressed,
			}
			switch {
			case m.Suppressed:
				c.Confidence = Unlikely
				c.Reason = "ruled out by a stronger match"
			default:
				c.Confidence = confidenceFor(p, in, live > 1)
				if c.Confidence == Unlikely {
					if p.Against != nil {
						if why, ok := p.Against(in); ok {
							c.Reason = why
						}
					}
					if c.Reason == "" {
						c.Reason = p.Rationale
					}
				}
			}
			out = append(out, c)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence < out[j].Confidence
		}
		return prevalenceOf(table, out[i].Type) > prevalenceOf(table, out[j].Type)
	})
	return out
}

func confidenceFor(p *Prototype, in Input, rivalled bool) Confidence {
	if p.Against != nil {
		if _, fired := p.Against(in); fired {
			return Unlikely
		}
	}
	switch p.Tier {
	case TierChecksum, TierSignature:
		if rivalled {
			return Likely
		}
		return Certain
	case TierStructural:
		if rivalled {
			return Possible
		}
		return Likely
	default: // TierShape
		if p.Prevalence < extinctPrevalence {
			return Unlikely
		}
		if !rivalled {
			return Possible
		}
		if p.Prevalence >= dominantPrevalence {
			return Likely
		}
		return Possible
	}
}

func prevalenceOf(table []Prototype, typ string) uint8 {
	for i := range table {
		for _, t := range table[i].Types {
			if t == typ {
				return table[i].Prevalence
			}
		}
	}
	return 0
}
