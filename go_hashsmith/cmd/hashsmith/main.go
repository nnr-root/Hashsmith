package main

import (
	"fmt"
	"os"
	"strings"
)

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

	if cmd == "-id" || cmd == "--identify" {
		cmd = "identify"
	}

	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		printHelp()
		os.Exit(0)
	}

	renderBanner()

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
	case "extract-hash", "zip2hash", "zip2smith":
		if err := runExtractHash(rest); err != nil {
			fail(err.Error())
		}
	case "7z2smith":
		if err := runExtract7z(rest); err != nil {
			fail(err.Error())
		}
	case "rar2smith":
		if err := runExtractRAR(rest); err != nil {
			fail(err.Error())
		}
	case "pdf2smith":
		if err := runExtractPDF(rest); err != nil {
			fail(err.Error())
		}
	case "interactive":
		if err := runInteractive(); err != nil {
			fail(err.Error())
		}
	default:
		fail("unknown command: " + cmd)
	}
}

func printHelp() {
	fmt.Println("Hashsmith — encoding, decoding, hashing, cracking")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  hashsmith [global-flags] <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  encode        -t <type> -i <text> [-f file] [-o out] [-c]")
	fmt.Println("  decode        -t <type> -i <text> [-f file] [-o out] [-c]")
	fmt.Println("  hash          -t <type> -i <text> [-f file] [-s salt] [-S prefix|suffix] [-e hex|base58] [-o out] [-c]")
	fmt.Println("  crack         -t <type> -H <hash> -M dict|brute [-w wordlist] [-C charset] [-n min] [-x max] [-s salt] [-S mode] [-o out] [-c]")
	fmt.Println("  identify      -i <text> [-f file] [-o out] [-c]")
	fmt.Println("  zip2smith     -f <zip-file>  [-o out] [-c]   (aliases: extract-hash, zip2hash)")
	fmt.Println("  7z2smith      -f <7z-file>   [-o out] [-c]")
	fmt.Println("  rar2smith     -f <rar-file>  [-o out] [-c]   (RAR4 -hp or RAR5)")
	fmt.Println("  pdf2smith     -f <pdf-file>  [-o out] [-c]")
	fmt.Println("  interactive   guided interactive mode")
	fmt.Println()
	fmt.Println("Global flags:")
	fmt.Println("  -N, --no-banner   suppress the banner")
	fmt.Println("  -T <theme>        accent colour: cyan green magenta blue yellow red white")
	fmt.Println()
	fmt.Println("Shortcuts:  -id / --identify  →  identify command")
}

func fail(msg string) {
	clrRed.Fprint(os.Stderr, "Error: ")
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}
