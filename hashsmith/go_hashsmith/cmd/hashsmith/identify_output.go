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
	fmt.Fprintf(&sb, "  hashsmith crack -t %s %s\n", cs[0].Type, input)
	return sb.String()
}
