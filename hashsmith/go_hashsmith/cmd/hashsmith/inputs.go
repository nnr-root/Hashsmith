package main

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

// ── Unified positional input handling ──────────────────────────────────────────
//
// Every command takes its input(s) as positional arguments — no -i/-f flags.
// A single argument may be:
//
//   • inline text in single or double quotes  →  hashsmith hash -t md5 "secret"
//   • a comma-separated list of inputs         →  hashsmith hash -t md5 "a, b, c"
//   • a file path (one input per line)         →  hashsmith crack hashes.txt
//
// Multiple positional arguments are all accepted and flattened together, so
// `hashsmith hash -t md5 a b c` and `hashsmith hash -t md5 "a,b,c"` are
// equivalent.

// gatherInputs flattens every positional argument through collectInputs.
func gatherInputs(positional []string) ([]string, error) {
	var out []string
	for _, arg := range positional {
		items, err := collectInputs(arg)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	if len(out) == 0 {
		return nil, errors.New("no input provided — pass text (\"...\"), a comma-list (\"a, b, c\"), or a file path")
	}
	return out, nil
}

// collectInputs resolves one positional argument into one or more inputs.
func collectInputs(arg string) ([]string, error) {
	a := strings.TrimSpace(arg)
	if a == "" {
		return nil, nil
	}
	// A readable file → one input per non-empty, non-comment line.
	if info, err := os.Stat(a); err == nil && !info.IsDir() {
		return readInputLines(a)
	}
	// A comma-separated list → each trimmed, non-empty element.
	if strings.Contains(a, ",") {
		var out []string
		for _, p := range strings.Split(a, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out, nil
	}
	// Otherwise a single literal input.
	return []string{a}, nil
}

// readInputLines returns every non-empty, non-comment (#) line of a file.
func readInputLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("no inputs found in " + path)
	}
	return lines, nil
}
