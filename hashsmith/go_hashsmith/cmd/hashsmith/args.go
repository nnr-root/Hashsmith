package main

import (
	"flag"
	"strings"
)

// parseArgsFlexible parses args into fs while allowing flags and positional
// arguments to appear in any order. Go's standard flag package stops parsing at
// the first positional argument, so `crack hash.txt -w list` would drop -w.
// This reorders the tokens (flags first, positionals last) before parsing, which
// makes all of the following equivalent:
//
//	hashsmith -w=list.txt hash.txt
//	hashsmith hash.txt -w=list.txt
//	hashsmith hash.txt -w list.txt
//	hashsmith hash.txt --wordlist list.txt
//	hashsmith hash.txt --wordlist=list.txt
//
// Boolean flags (which never consume a following value) are detected from fs
// itself, so a token after `-c` is treated as a positional rather than its value.
func parseArgsFlexible(fs *flag.FlagSet, args []string) error {
	boolFlags := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			boolFlags[f.Name] = true
		}
	})
	return fs.Parse(reorderArgs(args, boolFlags))
}

// reorderArgs moves every positional argument after all flags (and their
// values), preserving relative order within each group. boolFlags names the
// flags that do not take a separate value token.
func reorderArgs(args []string, boolFlags map[string]bool) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]

		// "--" ends flag parsing: everything after it is positional.
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}

		// A lone "-" (and empty strings) are positionals, not flags.
		if len(a) < 2 || a[0] != '-' {
			positionals = append(positionals, a)
			continue
		}

		// It's a flag token.
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")

		// Inline value (-w=x / --wordlist=x): nothing more to consume.
		if strings.IndexByte(name, '=') >= 0 {
			continue
		}
		// Boolean flags never take a following value.
		if boolFlags[name] {
			continue
		}
		// Value flag in space form (-w x): pull the next token as its value.
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positionals...)
}
