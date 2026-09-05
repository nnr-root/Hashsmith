package main

import (
	"fmt"
	"hashsmith-go/internal/hashid"
	"strconv"
	"strings"
)

// renderIdentifyHuman formats candidates for a terminal.
//
// Every row carries what the user needs to act: the confidence, the Hashcat
// mode, the John label, the Hashsmith type, and — for the leading candidate —
// a command that can be pasted. A format with no foreign equivalent prints "-",
// which is how Hashsmith's coverage advantage stays visible instead of being
// asserted in documentation.
//
// The trailing command line is chosen by identifyRunnableCommand — see its
// doc comment for the crack/decode/neither logic, which buildIdentifyReport's
// JSON "command" field also uses so the two renderers never drift apart.
func renderIdentifyHuman(input string, cs []hashid.Candidate) string {
	if len(cs) == 0 {
		return "  no candidate identified\n\n  " +
			"The input matched no known format. If it is a container file, try:\n" +
			"      hashsmith identify <file>"
	}

	type row struct{ name, conf, mode, john, typ, note string }
	rows := make([]row, 0, len(cs))
	for _, c := range cs {
		r := row{name: c.Display, conf: c.Confidence.String(), typ: "-t " + c.Type, note: c.Reason}
		if m, ok := universalHashRegistry.hashcatMode(c.Type); ok {
			r.mode = "-m " + strconv.Itoa(m)
		} else {
			r.mode = "-"
		}
		if l, ok := universalHashRegistry.johnLabel(c.Type); ok {
			r.john = l
		} else {
			r.john = "-"
		}
		rows = append(rows, r)
	}

	w := func(sel func(row) string) int {
		max := 0
		for _, r := range rows {
			if n := len(sel(r)); n > max {
				max = n
			}
		}
		return max
	}
	wName, wConf := w(func(r row) string { return r.name }), w(func(r row) string { return r.conf })
	wMode, wJohn := w(func(r row) string { return r.mode }), w(func(r row) string { return r.john })
	wType := w(func(r row) string { return r.typ })

	var sb strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&sb, "  %-*s  %-*s  %-*s  %-*s  %-*s",
			wName, r.name, wConf, r.conf, wMode, r.mode, wJohn, r.john, wType, r.typ)
		if r.note != "" {
			fmt.Fprintf(&sb, "  %s", r.note)
		}
		sb.WriteByte('\n')
	}

	if ev := cs[0].Evidence; ev != "" {
		fmt.Fprintf(&sb, "\n  %s\n", ev)
	}
	if cmd := identifyRunnableCommand(cs[0].Type, input); cmd != "" {
		fmt.Fprintf(&sb, "  %s\n", cmd)
	}
	return sb.String()
}

// identifyRunnableCommand picks the one command a caller can paste for a
// leading candidate of the given type: `crack` when
// universalHashRegistry.crackable reports true, `decode` when decodeText
// genuinely accepts the type (Base64, Morse and the other identify-only
// recognitions have no attack routine — `crack -t base64 ...` fails with
// "unsupported hash algorithm" — so decode is the honest analogue there),
// and "" when neither applies, rather than printing a command that errors.
//
// Both renderIdentifyHuman and buildIdentifyReport call this single
// implementation instead of each carrying their own copy of the branch, so a
// future change to the decode arguments — or a third case — cannot update
// one and silently leave the other advertising a broken command.
func identifyRunnableCommand(typ, input string) string {
	switch {
	case universalHashRegistry.crackable(typ):
		return "hashsmith crack -t " + typ + " " + input
	default:
		if _, err := decodeText(input, typ, 3, "", 2); err == nil {
			return "hashsmith decode -t " + typ + " " + input
		}
		return ""
	}
}

// identifySchemaVersion is versioned from the first release so fields can be
// added later without breaking anything already parsing this output.
const identifySchemaVersion = "hashsmith.identify/1"

// identifyCandidateJSON is one candidate in the machine-readable report.
//
// Hashcat is *int, not int, because 0 is MD5's real mode number: a plain int
// could not distinguish "mode 0" from "no mode", and a consumer would read
// every unknown format as MD5. John is *string for the identical reason:
// "" is not a real John label, but a plain string cannot say so. Measured
// coverage is 395/457 formats with a mode and 65/457 with a label, so an
// absent value is the normal case here, not a rare edge.
//
// No percentage, score, or confidence number appears anywhere in this type:
// Confidence carries exactly the four words the ordinal model defines.
//
// DemotionReason is hashid.Candidate.Reason, documented there as "why it was
// demoted, when it was" — it is not a rationale for the pick (that is what
// Evidence is for), so the JSON key says exactly what the field holds. It
// carries omitempty because the common case, an undemoted candidate, has no
// reason to give; without omitempty every such candidate would ship
// "demotion_reason": "" and a consumer could not tell "nothing to report"
// from "a reason was dropped by a bug".
type identifyCandidateJSON struct {
	Name           string  `json:"name"`
	Type           string  `json:"type"`
	Confidence     string  `json:"confidence"`
	Tier           string  `json:"tier"`
	Hashcat        *int    `json:"hashcat"`
	John           *string `json:"john"`
	Evidence       string  `json:"evidence"`
	DemotionReason string  `json:"demotion_reason,omitempty"`
	Command        string  `json:"command"`
	Suppressed     bool    `json:"suppressed,omitempty"`
}

// identifyReport is the top-level machine-readable payload for one input.
type identifyReport struct {
	Schema     string                  `json:"schema"`
	Input      string                  `json:"input"`
	Normalized string                  `json:"normalized"`
	Candidates []identifyCandidateJSON `json:"candidates"`
}

// buildIdentifyReport renders the same candidates renderIdentifyHuman does,
// as a versioned, script-friendly structure instead of a terminal table.
//
// The printed command comes from identifyRunnableCommand, the single
// implementation renderIdentifyHuman also calls, so the JSON and human
// renderings can never disagree about which of crack/decode/neither applies.
func buildIdentifyReport(input string, cs []hashid.Candidate) identifyReport {
	rep := identifyReport{
		Schema:     identifySchemaVersion,
		Input:      input,
		Normalized: stripShadowUsername(strings.TrimSpace(input)),
		Candidates: make([]identifyCandidateJSON, 0, len(cs)),
	}
	for i, c := range cs {
		item := identifyCandidateJSON{
			Name:           c.Display,
			Type:           c.Type,
			Confidence:     c.Confidence.String(),
			Tier:           c.Tier.String(),
			Evidence:       string(c.Evidence),
			DemotionReason: c.Reason,
			Suppressed:     c.Suppressed,
		}
		if m, ok := universalHashRegistry.hashcatMode(c.Type); ok {
			mode := m
			item.Hashcat = &mode
		}
		if l, ok := universalHashRegistry.johnLabel(c.Type); ok {
			label := l
			item.John = &label
		}
		if i == 0 {
			item.Command = identifyRunnableCommand(c.Type, input)
		}
		rep.Candidates = append(rep.Candidates, item)
	}
	return rep
}

// identifyExitCode lets identify participate in shell chains the way crack
// already does: 0 means the tool is willing to commit to an answer — at
// least one unsuppressed certain or likely candidate — 1 means it is not.
// Exit code 2, for a usage or I/O error, is not computed here; it is
// returned by the caller.
func identifyExitCode(cs []hashid.Candidate) int {
	for _, c := range cs {
		if c.Suppressed {
			continue
		}
		if c.Confidence == hashid.Certain || c.Confidence == hashid.Likely {
			return 0
		}
	}
	return 1
}
