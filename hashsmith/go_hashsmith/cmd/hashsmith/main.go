package main

import (
	"fmt"
	"os"
	"strings"
)

// exitCode is the process exit status for crack/auto runs: 0 = every target
// cracked, 1 = at least one target left uncracked. Real errors exit 2 via fail().
var exitCode int

func main() {
	rawArgs := os.Args[1:]

	// strip global flags before routing
	filtered := rawArgs[:0:len(rawArgs)]
	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		switch {
		case arg == "-N" || arg == "--no-banner":
			noBanner = true
		case arg == "-T" || arg == "--theme":
			if i+1 < len(rawArgs) {
				i++
				setTheme(rawArgs[i])
			}
		case strings.HasPrefix(arg, "-T="):
			setTheme(arg[3:])
		case strings.HasPrefix(arg, "--theme="):
			setTheme(arg[8:])
		default:
			filtered = append(filtered, arg)
		}
	}

	if len(filtered) < 1 {
		renderBanner()
		if err := runInteractive(); err != nil {
			fail(err.Error())
		}
		return
	}

	cmd := filtered[0]
	rest := filtered[1:]

	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		printHelp()
		os.Exit(0)
	}

	renderBanner()

	// -i shortcut: identify a hash given inline or as a file path, e.g.
	//   hashsmith -i 5f4dcc3b5aa765d61d8327deb882cf99
	//   hashsmith -i hash.txt
	if cmd == "-i" {
		if len(rest) == 0 {
			fail("-i requires a hash value or a file path (e.g. hashsmith -i hash.txt)")
		}
		// Rebuild as `-i <value> [flags]` so runIdentify parses it normally.
		if err := runIdentify(append([]string{"-i", rest[0]}, rest[1:]...)); err != nil {
			fail(err.Error())
		}
		return
	}

	switch cmd {
	case "encode":
		if err := runEncode(rest); err != nil {
			fail(err.Error())
		}
	case "decode":
		if err := runDecode(rest); err != nil {
			fail(err.Error())
		}
	case "hash":
		if err := runHash(rest); err != nil {
			fail(err.Error())
		}
	case "crack":
		if err := runCrack(rest); err != nil {
			fail(err.Error())
		}
	case "identify":
		if err := runIdentify(rest); err != nil {
			fail(err.Error())
		}
	case "extractors", "list-extractors":
		printExtractorCatalogue()
	case "selftest", "self-test":
		if err := runSelfTest(rest); err != nil {
			fail(err.Error())
		}
	case "types", "list-types":
		if err := runListTypes(rest); err != nil {
			fail(err.Error())
		}
	case "encodings", "codecs", "list-encodings":
		if err := runListEncodings(rest); err != nil {
			fail(err.Error())
		}
	case "wordlists", "list-wordlists":
		if err := runWordlists(rest); err != nil {
			fail(err.Error())
		}
	case "sessions":
		if err := runSessions(rest); err != nil {
			fail(err.Error())
		}
	case "rules":
		if err := runRules(rest); err != nil {
			fail(err.Error())
		}
	case "benchmark", "bench":
		if err := runBenchmark(rest); err != nil {
			fail(err.Error())
		}
	case "gpu":
		if err := runGPUInfo(rest); err != nil {
			fail(err.Error())
		}
	case "interactive":
		if err := runInteractive(); err != nil {
			fail(err.Error())
		}
	default:
		if extractor, ok := findExtractor(cmd); ok {
			if err := extractor.run(rest); err != nil {
				fail(err.Error())
			}
			break
		}
		// Bare-target shortcut: a bare hash or a file of hashes is
		// auto-detected and cracked. The target may be preceded by flags
		// (e.g. `hashsmith -w list.txt hash.txt`), so route to auto whenever the
		// first token is a flag or itself looks like a crackable target; the
		// whole argument list is handed over and separated by the flag parser.
		if strings.HasPrefix(cmd, "-") || looksLikeAutoTarget(cmd) {
			if err := runAuto(filtered); err != nil {
				fail(err.Error())
			}
		} else {
			fail("unknown command: " + cmd)
		}
	}
	os.Exit(exitCode)
}

func printHelp() {
	fmt.Println("Hashsmith — encoding, decoding, hashing, cracking")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  hashsmith [global-flags] <command> [options]")
	fmt.Println("  hashsmith <hash | hashfile> [crack-options]   auto-detect the type and crack")
	fmt.Println()
	fmt.Println("Commands (INPUT is text, a quoted comma-list \"a, b, c\", or a file with one input per line):")
	fmt.Println("  encode        -t <type> [-s shift] [-k key] [-r rails] [-o out] [-c]  INPUT...")
	fmt.Println("  decode        -t <type> [-s shift] [-k key] [-r rails] [-o out] [-c]  INPUT...")
	fmt.Println("  hash          -t <type> [-s salt] [-S prefix|suffix] [-e encoding] [-o out] [-c]  INPUT...")
	fmt.Println("  crack         [-t <type|auto>] [-M dict|brute|mask|markov|hybrid|combinator|prince] [-w wordlist] [--wordlist2 list2] [--prince-elems N] [-r | --rules <file>...] [--mask ?l?d..] [-1..-4 set] [--increment] [--mask-first] [--stdout]")
	fmt.Println("                [--session <name>] [--restore <name>] [--gpu] [--show] [--no-pot] [--no-auto-wordlist] [-C charset] [-n min] [-x max] [-s salt] [-S mode] [-o out] [-c]  INPUT...")
	fmt.Println("  selftest      [-t type] [-v] [-gaps]   verify built-in known-answer vectors")
	fmt.Println("  types         list every supported -t hash type")
	fmt.Println("  encodings     list every supported encode/decode -t type (alias: codecs)")
	fmt.Println("  identify      [-o out] [-c]  INPUT...")
	fmt.Printf("  extractors    list all %d integrated *2smith extractors and formats\n", len(universalExtractorRegistry))
	fmt.Println("  <name>2smith  -f <file> [-o out] [-c]   extract crack-ready records; see `extractors`")
	fmt.Println("  rules         <rulefile> [word]   preview/validate a mangling-rule file")
	fmt.Println("  benchmark     [-t type] [-p workers]   measure native throughput")
	fmt.Println("                [--compare [--gpu] --candidates N --repeat N --json report.json] compare with John/Hashcat")
	fmt.Println("  gpu           show GPU acceleration status (build: -tags opencl any GPU, or -tags gpu Apple Metal)")
	fmt.Println("  sessions      list | rm <name> | clear   manage saved brute/mask sessions")
	fmt.Println("  wordlists     [--scan]   show where an omitted -w looks for a wordlist (--scan searches the disk)")
	fmt.Println("  interactive   guided interactive mode")
	fmt.Println()
	fmt.Println("Global flags:")
	fmt.Println("  -N, --no-banner   suppress the banner")
	fmt.Println("  -T <theme>        accent colour: cyan green magenta blue yellow red white")
	fmt.Println()
	fmt.Println("Wordlists:  with no -w, an installed rockyou.txt is auto-detected (gzip is read directly);")
	fmt.Println("            $HASHSMITH_WORDLIST pins one, --no-auto-wordlist forces the built-in common.txt,")
	fmt.Println("            and `hashsmith wordlists` shows exactly which file a run would use.")
	fmt.Println()
	fmt.Println("Shortcuts:  -i <hash|file>  →  identify command")
	fmt.Println()
	fmt.Println("Exit codes (crack):  0 = all targets cracked   1 = some not cracked   2 = error")
}

func fail(msg string) {
	clrRed.Fprint(os.Stderr, "Error: ")
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}
