package smith

// `hashsmith rules <file> [word]` previews and validates a rule file: it
// compiles every rule and shows the candidate each produces for a sample word
// (default "Password"), flagging syntax errors with their line number.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func runRules(args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: hashsmith rules <rulefile|bundled-name> [sample-word]")
		fmt.Println()
		fmt.Println("Bundled rulesets (no path needed):")
		for _, n := range builtinRuleNames() {
			src, _ := builtinRuleSource(n)
			count := 0
			for _, line := range strings.Split(src, "\n") {
				t := strings.TrimSpace(line)
				if t != "" && !strings.HasPrefix(t, "#") {
					count++
				}
			}
			fmt.Printf("  %-10s %4d rules\n", n, count)
		}
		fmt.Println()
		fmt.Println("  hashsmith rules best                 preview a bundled set")
		fmt.Println("  hashsmith crack ... --rules best     use it in an attack")
		fmt.Println("  hashsmith crack ... --rules toggles --rules digits   stack two")
		return nil
	}
	path := args[0]
	word := "Password"
	if len(args) > 1 {
		word = args[1]
	}

	// Same resolution as --rules: a readable file first, then a bundled
	// ruleset by bare name. Without this, `hashsmith rules best` reported
	// "no such file" for a ruleset the binary carries.
	src, label, err := openRuleSource(path)
	if err != nil {
		return err
	}
	if c, ok := src.(io.Closer); ok {
		defer c.Close()
	}

	accentPrintln(fmt.Sprintf("Rule preview for %s  (base word: %q)", label, word))
	fmt.Println()

	var lines []string
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return err
	}

	// The preview must agree with what an attack would do, so the dialect is
	// chosen exactly as compileRuleLines chooses it — for the file, from the
	// whole file — and each line is expanded through the same preprocessor.
	john := detectJohnDialect(lines)
	if john {
		fmt.Println("  (read as John the Ripper rules)")
		fmt.Println()
	}
	valid, invalid, expandedTotal := 0, 0, 0
	for lineNo, line := range lines {
		expanded := []string{line}
		if john {
			exp, err := expandJohnRuleLine(line)
			if err != nil {
				invalid++
				clrRed.Fprintf(os.Stderr, "  line %d: %-16s  ✗ %v\n", lineNo+1, line, err)
				continue
			}
			expanded = exp
		}
		expandedTotal += len(expanded)
		for _, one := range expanded {
			p, err := compileRuleLineDialect(one, john)
			if err != nil {
				invalid++
				clrRed.Fprintf(os.Stderr, "  line %d: %-16s  ✗ %v\n", lineNo+1, one, err)
				continue
			}
			valid++
			cand, ok := p.apply(word)
			if !ok {
				fmt.Printf("  %-16s  →  %s\n", one, clrYellow.Sprint("(rejected)"))
			} else {
				fmt.Printf("  %-16s  →  %s\n", one, accentSprint(cand))
			}
		}
	}
	fmt.Println()
	if john && expandedTotal != len(lines) {
		fmt.Printf("%d line(s) expanded to %d rule(s).\n", len(lines), expandedTotal)
	}
	fmt.Printf("%d valid rule(s), %d invalid.\n", valid, invalid)
	return nil
}
