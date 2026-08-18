package main

// `hashsmith rules <file> [word]` previews and validates a rule file: it
// compiles every rule and shows the candidate each produces for a sample word
// (default "Password"), flagging syntax errors with their line number.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func runRules(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hashsmith rules <rulefile> [sample-word]")
	}
	path := args[0]
	word := "Password"
	if len(args) > 1 {
		word = args[1]
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	accentPrintln(fmt.Sprintf("Rule preview for %q  (base word: %q)", path, word))
	fmt.Println()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lineNo, valid, invalid := 0, 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		p, err := compileRuleLine(line)
		if err != nil {
			invalid++
			clrRed.Fprintf(os.Stderr, "  line %d: %-16s  ✗ %v\n", lineNo, line, err)
			continue
		}
		valid++
		cand, ok := p.apply(word)
		if !ok {
			fmt.Printf("  %-16s  →  %s\n", line, clrYellow.Sprint("(rejected)"))
		} else {
			fmt.Printf("  %-16s  →  %s\n", line, accentSprint(cand))
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	fmt.Println()
	fmt.Printf("%d valid rule(s), %d invalid.\n", valid, invalid)
	return nil
}
