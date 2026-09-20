package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// ── Per-command help ──────────────────────────────────────────────────────────
//
// Every subcommand builds a flag.FlagSet with flag.ContinueOnError and
// io.Discard output, so `hashsmith crack --help` used to surface the flag
// package's raw sentinel — "Error: flag: help requested" — and exit 2. A CLI
// with sixteen commands, twenty-five crack flags and 1,163 accepted type names
// has to be able to explain itself at the point of use.

// commandHelp is the usage line and one-paragraph description for a command.
type commandHelp struct {
	usage string
	about string
	extra string
}

var commandHelpText = map[string]commandHelp{
	"encode": {
		usage: "hashsmith encode -t <type> [options] INPUT...",
		about: "Encode each INPUT with the named codec. Run `hashsmith encodings` for the catalogue.",
		extra: "INPUT is literal text, \"-\" for standard input, or a file path (one input per line).\nA payload beginning with '-' needs the flag terminator:  hashsmith encode -t base64 -- -hello",
	},
	"decode": {
		usage: "hashsmith decode -t <type> [options] INPUT...",
		about: "Decode each INPUT with the named codec. Run `hashsmith encodings` for the catalogue.",
		extra: "INPUT is literal text, \"-\" for standard input, or a file path (one input per line).\nA payload beginning with '-' needs the flag terminator:  hashsmith decode -t base64 -- -Zm9v",
	},
	"hash": {
		usage: "hashsmith hash -t <type> [options] INPUT...",
		about: "Hash each INPUT with the named algorithm. Run `hashsmith types` for the registry.",
		extra: "-s sets a salt and -S places it (prefix|suffix); -e re-encodes the raw digest bytes.",
	},
	"crack": {
		usage: "hashsmith crack [-t <type|auto>] [options] TARGET...",
		about: "Recover the plaintext behind one or more hashes. With no -t the type is auto-detected.",
		extra: "TARGET is a hash, \"-\" for standard input, or a file of hashes (one per line).\nResults go to stdout as `hash:plaintext`; progress and status go to stderr.\nExit codes: 0 = every target cracked, 1 = some not cracked, 2 = usage or format error.",
	},
	"identify": {
		usage: "hashsmith identify [options] INPUT...",
		about: "Report which hash types an input could be, ranked by confidence, with the Hashcat -m mode and John label for each.",
		extra: "INPUT may also be a container file (.kdbx, .zip, .pdf, ...).\nExit codes: 0 = confident answer, 1 = ambiguous or none, 2 = error.",
	},
	"rules":     {usage: "hashsmith rules <rulefile> [word]", about: "Preview and validate a mangling-rule file against a sample word."},
	"benchmark": {usage: "hashsmith benchmark [-t type] [-p workers]", about: "Measure native throughput. --compare runs the same work through John and Hashcat."},
	"selftest":  {usage: "hashsmith selftest [-t type] [-v] [-gaps]", about: "Verify the built-in known-answer vectors compiled into this binary."},
	"types":     {usage: "hashsmith types", about: "List every supported -t hash type."},
	"encodings": {usage: "hashsmith encodings", about: "List every supported encode/decode -t type."},
	"wordlists": {usage: "hashsmith wordlists [--scan] [--set-default <path>]", about: "Show, search for, and pin the wordlist an omitted -w resolves to."},
	"sessions":  {usage: "hashsmith sessions list | rm <name> | clear", about: "Manage saved resumable sessions."},
	"gpu":        {usage: "hashsmith gpu", about: "Show GPU acceleration status for this build."},
	"extractors": {usage: "hashsmith extractors", about: "List every integrated *2smith extractor and the formats it produces."},
}

func init() {
	// Command aliases share their primary's help text.
	for alias, primary := range map[string]string{
		"codecs": "encodings", "list-encodings": "encodings",
		"list-types": "types", "list-extractors": "extractors",
		"list-wordlists": "wordlists", "self-test": "selftest", "bench": "benchmark",
	} {
		if h, ok := commandHelpText[primary]; ok {
			commandHelpText[alias] = h
		}
	}
}

// flaglessCommands never build a flag.FlagSet, so `--help` would reach them as
// an ordinary positional argument (`rules --help` tried to open a rule file
// called "--help" and exited 2). main intercepts these before dispatch.
var flaglessCommands = map[string]bool{
	"rules": true, "sessions": true, "types": true, "list-types": true,
	"encodings": true, "codecs": true, "list-encodings": true,
	"gpu": true, "extractors": true, "list-extractors": true,
}

// wantsHelp reports whether args asks for help, stopping at the "--"
// terminator so a payload of "-h" is never mistaken for a request.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

// printFlaglessHelp writes usage for a command with no FlagSet and exits 0.
func printFlaglessHelp(name string) { printCommandHelpNamed(name, nil) }

// printCommandHelp writes usage for one command to stdout and exits 0.
func printCommandHelp(fs *flag.FlagSet) { printCommandHelpNamed(fs.Name(), fs) }

// printCommandHelpNamed renders help for name; fs may be nil.
func printCommandHelpNamed(name string, fs *flag.FlagSet) {
	h, ok := commandHelpText[name]
	if !ok {
		h = commandHelp{usage: "hashsmith " + name + " [options]"}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: %s\n", h.usage)
	if h.about != "" {
		fmt.Fprintf(&b, "\n%s\n", h.about)
	}
	if fs != nil {
		var flagBuf strings.Builder
		fs.SetOutput(&flagBuf)
		fs.PrintDefaults()
		if flagBuf.Len() > 0 {
			fmt.Fprintf(&b, "\nFlags:\n%s", flagBuf.String())
		}
	}
	if h.extra != "" {
		fmt.Fprintf(&b, "\n%s\n", h.extra)
	}
	fmt.Fprintf(&b, "\nSee `hashsmith --help` for the full command list.\n")
	fmt.Print(b.String())
	os.Exit(0)
}
