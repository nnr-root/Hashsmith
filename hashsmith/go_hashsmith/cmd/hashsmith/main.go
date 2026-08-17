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
	case "ssh2smith":
		if err := runExtractSSH(rest); err != nil {
			fail(err.Error())
		}
	case "gpg2smith":
		if err := runExtractGPG(rest); err != nil {
			fail(err.Error())
		}
	case "keepass2smith":
		if err := runExtractKeePass(rest); err != nil {
			fail(err.Error())
		}
	case "office2smith":
		if err := runExtractOffice(rest); err != nil {
			fail(err.Error())
		}
	case "shadow2smith", "unshadow":
		if err := runExtractShadow(rest); err != nil {
			fail(err.Error())
		}
	case "interactive":
		if err := runInteractive(); err != nil {
			fail(err.Error())
		}
	default:
		// John-the-Ripper-style shortcut: a bare hash or a file of hashes is
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
	fmt.Println("  hash          -t <type> [-s salt] [-S prefix|suffix] [-e hex|base58] [-o out] [-c]  INPUT...")
	fmt.Println("  crack         [-t <type|auto>] [-M dict|brute] [-w wordlist] [-C charset] [-n min] [-x max] [-s salt] [-S mode] [-o out] [-c]  INPUT...")
	fmt.Println("  identify      [-o out] [-c]  INPUT...")
	fmt.Println("  zip2smith     -f <zip-file>  [-o out] [-c]   (aliases: extract-hash, zip2hash)")
	fmt.Println("  7z2smith      -f <7z-file>   [-o out] [-c]")
	fmt.Println("  rar2smith     -f <rar-file>  [-o out] [-c]   (RAR4 -hp or RAR5)")
	fmt.Println("  pdf2smith     -f <pdf-file>  [-o out] [-c]")
	fmt.Println("  ssh2smith     -f <ssh-key>   [-o out] [-c]   (OpenSSH / legacy PEM / PKCS#8 keys)")
	fmt.Println("  gpg2smith     -f <gpg-file>  [-o out] [-c]   (gpg -c symmetric encryption)")
	fmt.Println("  keepass2smith -f <kdbx-file> [-o out] [-c]   (KeePass KDBX 3.1 database)")
	fmt.Println("  office2smith  -f <docx/xlsx> [-o out] [-c]   (encrypted Office 2013+ document)")
	fmt.Println("  shadow2smith  <shadow> [passwd] [-o out] [-c]   (unshadow: /etc/shadow → user:hash, any order)")
	fmt.Println("  interactive   guided interactive mode")
	fmt.Println()
	fmt.Println("Global flags:")
	fmt.Println("  -N, --no-banner   suppress the banner")
	fmt.Println("  -T <theme>        accent colour: cyan green magenta blue yellow red white")
	fmt.Println()
	fmt.Println("Shortcuts:  -i <hash|file>  →  identify command")
}

func fail(msg string) {
	clrRed.Fprint(os.Stderr, "Error: ")
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}
