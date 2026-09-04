package hashid

import "testing"

func protoShape(name string, prev uint8, against func(Input) (string, bool)) Prototype {
	return Prototype{
		Types: []string{name}, Display: name, Tier: TierShape,
		Match:      func(Input) (Evidence, bool) { return "32 hex", true },
		Against:    against,
		Prevalence: prev, Rationale: name + " rationale",
	}
}

func find(cs []Candidate, typ string) *Candidate {
	for i := range cs {
		if cs[i].Type == typ {
			return &cs[i]
		}
	}
	return nil
}

func TestUnrivalledSignatureIsCertain(t *testing.T) {
	table := []Prototype{{
		Types: []string{"bcrypt"}, Display: "bcrypt", Tier: TierSignature, Exclusive: true,
		Match:      func(Input) (Evidence, bool) { return "$2y$ prefix", true },
		Prevalence: 90, Rationale: "r",
	}}
	cs := Identify(table, Input{Normalized: "$2y$10$x"})
	if len(cs) != 1 || cs[0].Confidence != Certain {
		t.Fatalf("got %+v, want one Certain candidate", cs)
	}
}

func TestDominantPrevalenceShapeIsLikely(t *testing.T) {
	table := []Prototype{
		protoShape("md5", 85, nil),
		protoShape("ntlm", 40, nil),
	}
	cs := Identify(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	if c := find(cs, "md5"); c == nil || c.Confidence != Likely {
		t.Fatalf("md5 = %+v, want Likely", c)
	}
	if c := find(cs, "ntlm"); c == nil || c.Confidence != Possible {
		t.Fatalf("ntlm = %+v, want Possible", c)
	}
}

func TestNegativeEvidenceDemotesAndExplains(t *testing.T) {
	table := []Prototype{
		protoShape("md5", 85, nil),
		protoShape("lm", 70, func(Input) (string, bool) {
			return "LM digests are upper-case", true
		}),
	}
	cs := Identify(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	c := find(cs, "lm")
	if c == nil || c.Confidence != Unlikely {
		t.Fatalf("lm = %+v, want Unlikely", c)
	}
	if c.Reason != "LM digests are upper-case" {
		t.Fatalf("lm reason = %q, want the Against string", c.Reason)
	}
}

func TestVeryLowPrevalenceDemotesAndCitesRationale(t *testing.T) {
	table := []Prototype{
		protoShape("md5", 85, nil),
		protoShape("md2", 5, nil),
	}
	cs := Identify(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	c := find(cs, "md2")
	if c == nil || c.Confidence != Unlikely {
		t.Fatalf("md2 = %+v, want Unlikely", c)
	}
	if c.Reason != "md2 rationale" {
		t.Fatalf("md2 reason = %q, want the Rationale", c.Reason)
	}
}

func TestCandidatesAreOrderedByConfidenceThenPrevalence(t *testing.T) {
	table := []Prototype{
		protoShape("md2", 5, nil),
		protoShape("ntlm", 40, nil),
		protoShape("md5", 85, nil),
	}
	cs := Identify(table, Input{Normalized: "x"})
	want := []string{"md5", "ntlm", "md2"}
	for i, w := range want {
		if cs[i].Type != w {
			t.Fatalf("position %d = %s, want %s (full: %+v)", i, cs[i].Type, w, cs)
		}
	}
}

func TestSuppressedCandidatesAreUnlikelyAndMarked(t *testing.T) {
	table := []Prototype{
		{Types: []string{"bcrypt"}, Display: "bcrypt", Tier: TierSignature, Exclusive: true,
			Match: func(Input) (Evidence, bool) { return "$2y$", true }, Prevalence: 90, Rationale: "r"},
		protoShape("base64", 30, nil),
	}
	cs := Identify(table, Input{Normalized: "$2y$10$x"})
	c := find(cs, "base64")
	if c == nil || !c.Suppressed || c.Confidence != Unlikely {
		t.Fatalf("base64 = %+v, want suppressed and Unlikely", c)
	}
}

// TestTiedConfidenceOrdersByPrevalence exercises the sort's secondary key on
// an actual tie: two rivalled shape prototypes both at or above
// dominantPrevalence land in the SAME confidence bucket (Likely), so only the
// prevalence tie-break can order them. TestCandidatesAreOrderedByConfidenceThenPrevalence
// does not cover this — its three prototypes fall in three different
// confidence buckets, so the primary key alone determines that test's order.
func TestTiedConfidenceOrdersByPrevalence(t *testing.T) {
	table := []Prototype{
		protoShape("a", 85, nil),
		protoShape("b", 70, nil),
	}
	cs := Identify(table, Input{Normalized: "x"})
	ca, cb := find(cs, "a"), find(cs, "b")
	if ca == nil || cb == nil || ca.Confidence != Likely || cb.Confidence != Likely {
		t.Fatalf("got %+v, want both candidates Likely (a tie)", cs)
	}
	want := []string{"a", "b"}
	for i, w := range want {
		if cs[i].Type != w {
			t.Fatalf("position %d = %s, want %s (full: %+v)", i, cs[i].Type, w, cs)
		}
	}
}
