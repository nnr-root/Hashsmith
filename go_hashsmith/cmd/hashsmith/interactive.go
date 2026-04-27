package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

var (
	errQuit = errors.New("quit")
	errBack = errors.New("back")
)

// ── Entry point ───────────────────────────────────────────────────────────────

func runInteractive() error {
	reader := bufio.NewReader(os.Stdin)
	color.New(themeAttr, color.Bold).Fprintln(os.Stderr,
		"interactive mode — [0] quit  [q] quit")

	for {
		printMainMenu()

		input, err := readMenuLine(reader)
		if err != nil || input == "q" || input == "0" {
			color.New(themeAttr, color.Bold).Fprintln(os.Stderr, "Goodbye")
			return nil
		}
		if input == "" {
			input = "1" // default: cryptography & utility
		}

		var execErr error
		switch input {
		case "1":
			execErr = menuCryptography(reader)
		case "2":
			execErr = menuAttack(reader)
		case "3":
			execErr = menuSettings(reader)
		default:
			clrRed.Fprintln(os.Stderr, "invalid selection.")
			continue
		}

		if execErr == errQuit {
			color.New(themeAttr, color.Bold).Fprintln(os.Stderr, "Goodbye")
			return nil
		}
		// errBack and nil both loop back to the main menu.
		if execErr != nil && execErr != errBack {
			clrRed.Fprint(os.Stderr, "error: ")
			fmt.Fprintln(os.Stderr, execErr.Error())
		}
	}
}

// ── Category menus ────────────────────────────────────────────────────────────

// menuCryptography runs the "cryptography & utility" sub-menu loop.
func menuCryptography(reader *bufio.Reader) error {
	entries := []menuEntry{
		{"1", "encode"},
		{"2", "decode"},
		{"3", "hash"},
		{"4", "crack"},
		{"i", "identify"},
	}
	for {
		printSubMenu("cryptography & utility", entries, "1")

		input, err := readMenuLine(reader)
		if err != nil || input == "q" {
			return errQuit
		}
		if input == "0" {
			return errBack
		}
		if input == "" {
			input = "1"
		}

		var execErr error
		switch input {
		case "1":
			execErr = interactiveEncode(reader)
		case "2":
			execErr = interactiveDecode(reader)
		case "3":
			execErr = interactiveHash(reader)
		case "4":
			execErr = interactiveCrack(reader)
		case "i":
			execErr = interactiveIdentify(reader)
		default:
			clrRed.Fprintln(os.Stderr, "invalid selection.")
			continue
		}

		if execErr == errQuit {
			return errQuit
		}
		if execErr != nil && execErr != errBack {
			clrRed.Fprint(os.Stderr, "error: ")
			fmt.Fprintln(os.Stderr, execErr.Error())
		}
	}
}

// menuAttack runs the "attack & crack" sub-menu loop.
// Focused on file-based operations: extracting and cracking ZIP passwords.
// interactiveExtractHash chains into interactiveCrackKnown automatically.
func menuAttack(reader *bufio.Reader) error {
	entries := []menuEntry{
		{"1", "extract-hash   — pull hash from encrypted ZIP, then crack"},
	}
	for {
		printSubMenu("attack & crack", entries, "1")

		input, err := readMenuLine(reader)
		if err != nil || input == "q" {
			return errQuit
		}
		if input == "0" {
			return errBack
		}
		if input == "" {
			input = "1"
		}

		var execErr error
		switch input {
		case "1":
			execErr = interactiveExtractHash(reader)
		default:
			clrRed.Fprintln(os.Stderr, "invalid selection.")
			continue
		}

		if execErr == errQuit {
			return errQuit
		}
		if execErr != nil && execErr != errBack {
			clrRed.Fprint(os.Stderr, "error: ")
			fmt.Fprintln(os.Stderr, execErr.Error())
		}
	}
}

// menuSettings runs the "settings & tools" sub-menu loop.
func menuSettings(reader *bufio.Reader) error {
	entries := []menuEntry{
		{"1", "set theme"},
	}
	for {
		printSubMenu("settings & tools", entries, "1")

		input, err := readMenuLine(reader)
		if err != nil || input == "q" {
			return errQuit
		}
		if input == "0" {
			return errBack
		}
		if input == "" {
			input = "1"
		}

		var execErr error
		switch input {
		case "1":
			execErr = interactiveSetTheme(reader)
		default:
			clrRed.Fprintln(os.Stderr, "invalid selection.")
			continue
		}

		if execErr == errQuit {
			return errQuit
		}
		if execErr != nil && execErr != errBack {
			clrRed.Fprint(os.Stderr, "error: ")
			fmt.Fprintln(os.Stderr, execErr.Error())
		}
	}
}

// ── Menu rendering ────────────────────────────────────────────────────────────

type menuEntry struct {
	key   string
	label string
}

func printMainMenu() {
	ac := color.New(themeAttr, color.Bold).Sprint
	dim := color.New(themeAttr).Sprint

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "%s\n", dim("── categories "+strings.Repeat("─", 40)))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s  cryptography & utility\n", ac("[1]"))
	fmt.Fprintf(os.Stderr, "       %s\n", dim("encode · decode · hash · crack · identify"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s  attack & crack\n", ac("[2]"))
	fmt.Fprintf(os.Stderr, "       %s\n", dim("extract zip passwords"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s  settings & tools\n", ac("[3]"))
	fmt.Fprintf(os.Stderr, "       %s\n", dim("set theme"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s  quit\n", ac("[q]"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Select %s: ", ac("[1]"))
}

func printSubMenu(title string, entries []menuEntry, defaultKey string) {
	ac := color.New(themeAttr, color.Bold).Sprint
	dim := color.New(themeAttr).Sprint

	sep := strings.Repeat("─", max(0, 46-len(title)))

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "%s\n", dim("── "+title+" "+sep))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s  back\n", ac("[0]"))
	for _, e := range entries {
		fmt.Fprintf(os.Stderr, "  %s  %s\n", ac("["+e.key+"]"), e.label)
	}
	fmt.Fprintf(os.Stderr, "  %s  quit\n", ac("[q]"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Select %s: ", ac("["+defaultKey+"]"))
}

// readMenuLine reads one trimmed, lowercased line from the reader.
func readMenuLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.ToLower(line)), nil
}

// ── Sub-actions ───────────────────────────────────────────────────────────────

func interactiveEncode(reader *bufio.Reader) error {
	encTypes := []string{
		"base64", "base64url", "base32", "base85", "quoted-printable",
		"html-entities", "uu", "base58", "base62", "hex", "binary", "decimal", "octal",
		"morse", "nato", "url", "caesar", "rot13", "vigenere", "xor", "atbash",
		"baconian", "leet", "reverse", "brainf*ck", "railfence", "polybius", "unicode",
	}
	encType, err := chooseOption(reader, "Encoding type", encTypes, 1)
	if err != nil {
		return err
	}

	text, err := askInput(reader)
	if err != nil {
		return err
	}

	shift, key, rails, err := askAlgoParams(reader, encType)
	if err != nil {
		return err
	}

	result, err := encodeText(text, encType, shift, key, rails)
	if err != nil {
		return err
	}

	outFile, copyOut, err := askOutput(reader)
	if err != nil {
		return err
	}
	return outputResult(result, outFile, copyOut)
}

func interactiveDecode(reader *bufio.Reader) error {
	decTypes := []string{
		"base64", "base64url", "base32", "base85", "quoted-printable",
		"html-entities", "uu", "base58", "base62", "hex", "binary", "decimal", "octal",
		"morse", "nato", "url", "caesar", "rot13", "vigenere", "xor", "atbash",
		"baconian", "leet", "reverse", "brainf*ck", "railfence", "polybius", "unicode",
	}
	decType, err := chooseOption(reader, "Decoding type", decTypes, 1)
	if err != nil {
		return err
	}

	text, err := askInput(reader)
	if err != nil {
		return err
	}

	shift, key, rails, err := askAlgoParams(reader, decType)
	if err != nil {
		return err
	}

	result, err := decodeText(text, decType, shift, key, rails)
	if err != nil {
		return err
	}

	outFile, copyOut, err := askOutput(reader)
	if err != nil {
		return err
	}
	return outputResult(result, outFile, copyOut)
}

func interactiveHash(reader *bufio.Reader) error {
	hashTypes := []string{
		"md5", "md4", "sha1", "sha224", "sha256", "sha384", "sha512",
		"sha3_224", "sha3_256", "sha3_512", "blake2b", "blake2s", "ripemd160",
		"ntlm", "mysql323", "mysql41", "bcrypt", "argon2", "scrypt",
		"mssql2000", "mssql2005", "mssql2012", "postgres",
	}
	hashType, err := chooseOption(reader, "Hash type", hashTypes, 3) // default sha1
	if err != nil {
		return err
	}

	text, err := askInput(reader)
	if err != nil {
		return err
	}

	salt := ""
	saltMode := "prefix"

	switch hashType {
	case "bcrypt":
		salt, err = askText(reader, "Rounds (cost factor)", "12")
		if err != nil {
			return err
		}
	case "postgres":
		salt, err = askText(reader, "Username (salt)", "")
		if err != nil {
			return err
		}
	default:
		useSalt, e := askYesNo(reader, "Use salt?", false)
		if e != nil {
			return e
		}
		if useSalt {
			salt, err = askText(reader, "Salt value", "")
			if err != nil {
				return err
			}
			saltModeOpt, e := chooseOption(reader, "Salt mode", []string{"prefix", "suffix"}, 1)
			if e != nil {
				return e
			}
			saltMode = saltModeOpt
		}
	}

	outEnc, err := chooseOption(reader, "Output encoding", []string{"hex", "base58"}, 1)
	if err != nil {
		return err
	}

	result, err := hashText(text, hashType, salt, saltMode)
	if err != nil {
		return err
	}
	if outEnc == "base58" {
		hv := result
		if strings.HasPrefix(strings.ToLower(hv), "0x") {
			hv = hv[2:]
		}
		if isHex(hv) && len(hv)%2 == 0 {
			b, e := hex.DecodeString(hv)
			if e == nil {
				result = encodeBase58(b)
			}
		}
	}

	outFile, copyOut, err := askOutput(reader)
	if err != nil {
		return err
	}
	return outputResult(result, outFile, copyOut)
}

func interactiveIdentify(reader *bufio.Reader) error {
	text, err := askInput(reader)
	if err != nil {
		return err
	}
	result := identifyText(strings.TrimSpace(text))
	color.New(themeAttr).Fprintln(os.Stdout, result)
	return nil
}

func interactiveCrack(reader *bufio.Reader) error {
	hashTypes := []string{
		"auto", "md5", "md4", "sha1", "sha224", "sha256", "sha384", "sha512",
		"sha3_224", "sha3_256", "sha3_512", "blake2b", "blake2s", "ripemd160",
		"ntlm", "mysql323", "mysql41", "bcrypt", "argon2", "scrypt",
		"mssql2000", "mssql2005", "mssql2012", "postgres",
	}
	hashType, err := chooseOption(reader, "Hash type", hashTypes, 1) // default auto
	if err != nil {
		return err
	}

	targetHash, err := askText(reader, "Target hash", "")
	if err != nil {
		return err
	}
	if targetHash == "" {
		return errors.New("target hash is required")
	}

	// Preprocessing: normalize Base58/Base64 encoded hash bytes to hex.
	if normalized, enc := normalizeHashInput(targetHash); enc != "" {
		color.New(themeAttr).Fprintf(os.Stderr,
			"Detected %s encoded target — normalizing for attack...\n", enc)
		targetHash = normalized
	}

	// auto-detect
	if hashType == "auto" {
		candidates := detectHashTypes(targetHash)
		if len(candidates) == 0 {
			return errors.New("unable to detect hash type — specify manually")
		}
		if len(candidates) == 1 {
			hashType = candidates[0]
			color.New(themeAttr).Fprintf(os.Stderr, "Detected: %s\n", hashType)
		} else {
			hashType, err = chooseOption(reader, "Detected types", candidates, 1)
			if err != nil {
				return err
			}
		}
	}

	mode, err := chooseOption(reader, "Attack mode", []string{"dict", "brute"}, 1)
	if err != nil {
		return err
	}

	salt := ""
	saltMode := "prefix"
	useSalt, err := askYesNo(reader, "Use salt?", false)
	if err != nil {
		return err
	}
	if useSalt {
		salt, err = askText(reader, "Salt value", "")
		if err != nil {
			return err
		}
		saltModeOpt, e := chooseOption(reader, "Salt mode", []string{"prefix", "suffix"}, 1)
		if e != nil {
			return e
		}
		saltMode = saltModeOpt
	}

	workers := runtime.NumCPU()
	workersStr, err := askText(reader, fmt.Sprintf("Workers [0=auto=%d]", runtime.NumCPU()), "0")
	if err != nil {
		return err
	}
	if n, e := strconv.Atoi(workersStr); e == nil && n > 0 {
		workers = n
	}

	copyOut, err := askYesNo(reader, "Copy cracked password to clipboard?", true)
	if err != nil {
		return err
	}

	if mode == "dict" {
		wlChoice, err := chooseOption(reader, "Wordlist", []string{"wordlists/common.txt", "enter custom path"}, 1)
		if err != nil {
			return err
		}
		wordlist := "wordlists/common.txt"
		if strings.Contains(wlChoice, "custom") || strings.Contains(wlChoice, "enter") {
			wordlist, err = askText(reader, "Wordlist path", "")
			if err != nil {
				return err
			}
		}
		useRules, err := askYesNo(reader, "Use mangling rules? (capitalize, leet, append digits…)", true)
		if err != nil {
			return err
		}
		return doCrack(targetHash, hashType, "dict", wordlist, "",
			1, 1, workers, salt, saltMode, "", copyOut, useRules)
	}

	// brute
	csChoice, err := chooseOption(reader, "Charset", []string{"[a-z0-9] default", "enter custom"}, 1)
	if err != nil {
		return err
	}
	charset := "abcdefghijklmnopqrstuvwxyz0123456789"
	if strings.Contains(csChoice, "custom") || strings.Contains(csChoice, "enter") {
		charset, err = askText(reader, "Charset", "")
		if err != nil {
			return err
		}
	}

	minLen, err := askInt(reader, "Min length", 1)
	if err != nil {
		return err
	}
	maxLen, err := askInt(reader, "Max length", 4)
	if err != nil {
		return err
	}

	return doCrack(targetHash, hashType, "brute", "", charset,
		minLen, maxLen, workers, salt, saltMode, "", copyOut, false)
}

// interactiveExtractHash guides the user through:
//  1. Choosing a ZIP file.
//  2. Extracting the crackable hash from its first encrypted entry.
//  3. Displaying the result and optionally handing off to the crack module.
func interactiveExtractHash(reader *bufio.Reader) error {
	zipPath, err := askText(reader, "ZIP file path", "")
	if err != nil {
		return err
	}
	if zipPath == "" {
		return errors.New("ZIP file path is required")
	}

	clrYellow.Fprintf(os.Stderr, "Extracting hash from %s…\n", zipPath)
	res, err := extractZipHash(zipPath)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	printExtractResult(res)

	copyHash, err := askYesNo(reader, "Copy hash to clipboard?", true)
	if err != nil {
		return err
	}
	if copyHash {
		if copyToClipboard(res.hash) {
			clrGreen.Fprintln(os.Stderr, "Hash copied to clipboard")
		} else {
			clrYellow.Fprintln(os.Stderr, "Unable to copy to clipboard")
		}
	}

	sendToCrack, err := askYesNo(reader, "Send to crack module?", true)
	if err != nil {
		return err
	}
	if !sendToCrack {
		return nil
	}
	return interactiveCrackKnown(reader, res.hashType, res.hash)
}

// interactiveCrackKnown is the crack flow when the hash type and hash string
// are already known (e.g. just extracted from a ZIP).  It skips the hash-type
// and target-hash prompts and starts directly at attack-mode selection.
func interactiveCrackKnown(reader *bufio.Reader, hashType, targetHash string) error {
	color.New(themeAttr).Fprintf(os.Stderr,
		"Hash type: %s\nHash:      %s\n\n", hashType, targetHash)

	mode, err := chooseOption(reader, "Attack mode", []string{"dict", "brute"}, 1)
	if err != nil {
		return err
	}

	workers := runtime.NumCPU()
	workersStr, err := askText(reader, fmt.Sprintf("Workers [0=auto=%d]", runtime.NumCPU()), "0")
	if err != nil {
		return err
	}
	if n, e := strconv.Atoi(workersStr); e == nil && n > 0 {
		workers = n
	}

	copyOut, err := askYesNo(reader, "Copy cracked password to clipboard?", true)
	if err != nil {
		return err
	}

	if mode == "dict" {
		wlChoice, err := chooseOption(reader,
			"Wordlist", []string{"wordlists/common.txt", "enter custom path"}, 1)
		if err != nil {
			return err
		}
		wordlist := "wordlists/common.txt"
		if strings.Contains(wlChoice, "custom") || strings.Contains(wlChoice, "enter") {
			wordlist, err = askText(reader, "Wordlist path", "")
			if err != nil {
				return err
			}
		}
		useRules, err := askYesNo(reader, "Use mangling rules? (capitalize, leet, append digits…)", true)
		if err != nil {
			return err
		}
		return doCrack(targetHash, hashType, "dict", wordlist, "",
			1, 1, workers, "", "prefix", "", copyOut, useRules)
	}

	// brute-force
	csChoice, err := chooseOption(reader,
		"Charset", []string{"[a-z0-9] default", "enter custom"}, 1)
	if err != nil {
		return err
	}
	charset := "abcdefghijklmnopqrstuvwxyz0123456789"
	if strings.Contains(csChoice, "custom") || strings.Contains(csChoice, "enter") {
		charset, err = askText(reader, "Charset", "")
		if err != nil {
			return err
		}
	}
	minLen, err := askInt(reader, "Min length", 1)
	if err != nil {
		return err
	}
	maxLen, err := askInt(reader, "Max length", 6)
	if err != nil {
		return err
	}
	return doCrack(targetHash, hashType, "brute", "", charset,
		minLen, maxLen, workers, "", "prefix", "", copyOut, false)
}

func interactiveSetTheme(reader *bufio.Reader) error {
	themes := []string{"cyan", "green", "magenta", "blue", "yellow", "red", "white"}
	name, err := chooseOption(reader, "Select theme", themes, 1)
	if err != nil {
		return err
	}
	setTheme(name)
	renderBanner()
	color.New(themeAttr).Fprintf(os.Stderr, "Theme set to %s\n", name)
	return nil
}

// ── Prompt helpers ────────────────────────────────────────────────────────────

func chooseOption(reader *bufio.Reader, label string, options []string, defaultIdx int) (string, error) {
	acFn := color.New(themeAttr).Sprint

	fmt.Fprintf(os.Stderr, "\n%s:\n", label)
	fmt.Fprintf(os.Stderr, "  %s  back\n", acFn("[0]"))
	for i, opt := range options {
		fmt.Fprintf(os.Stderr, "  %s  %s\n", acFn(fmt.Sprintf("[%d]", i+1)), opt)
	}
	fmt.Fprintf(os.Stderr, "  %s  quit\n", acFn("[q]"))

	hint := acFn(fmt.Sprintf("[%d]", defaultIdx))
	fmt.Fprintf(os.Stderr, "Select %s: ", hint)

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", errQuit
	}
	input := strings.TrimSpace(line)
	if input == "" {
		input = strconv.Itoa(defaultIdx)
	}

	lower := strings.ToLower(input)
	if lower == "q" || lower == "quit" || lower == "exit" || lower == "bye" {
		return "", errQuit
	}
	if input == "0" {
		return "", errBack
	}

	n, convErr := strconv.Atoi(input)
	if convErr != nil || n < 1 || n > len(options) {
		clrRed.Fprintln(os.Stderr, "Invalid selection.")
		return "", errors.New("invalid selection")
	}
	return options[n-1], nil
}

func askText(reader *bufio.Reader, label, defaultVal string) (string, error) {
	acFn := color.New(themeAttr).Sprint
	if defaultVal != "" {
		fmt.Fprintf(os.Stderr, "%s %s: ", label, acFn("["+defaultVal+"]"))
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", errQuit
	}
	val := strings.TrimSpace(line)
	lower := strings.ToLower(val)
	if lower == "q" || lower == "quit" || lower == "exit" || lower == "bye" {
		return "", errQuit
	}
	if val == "" {
		return defaultVal, nil
	}
	return val, nil
}

func askInt(reader *bufio.Reader, label string, defaultVal int) (int, error) {
	for attempt := 0; attempt < 3; attempt++ {
		raw, err := askText(reader, label, strconv.Itoa(defaultVal))
		if err != nil {
			return 0, err
		}
		n, convErr := strconv.Atoi(raw)
		if convErr != nil {
			clrRed.Fprintln(os.Stderr, "Invalid number, please try again.")
			continue
		}
		return n, nil
	}
	return 0, errors.New("too many invalid attempts")
}

func askYesNo(reader *bufio.Reader, label string, defaultVal bool) (bool, error) {
	hint := "y/N"
	if defaultVal {
		hint = "Y/n"
	}
	acFn := color.New(themeAttr).Sprint
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(os.Stderr, "%s %s: ", label, acFn("["+hint+"]"))
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, errQuit
		}
		val := strings.TrimSpace(strings.ToLower(line))
		if val == "" {
			return defaultVal, nil
		}
		if val == "q" || val == "quit" || val == "exit" || val == "bye" {
			return false, errQuit
		}
		if val == "y" || val == "yes" {
			return true, nil
		}
		if val == "n" || val == "no" {
			return false, nil
		}
		clrRed.Fprintln(os.Stderr, "Please enter y or n.")
	}
	return false, errors.New("too many invalid attempts")
}

// askInput asks the user to either type text or provide a file path.
func askInput(reader *bufio.Reader) (string, error) {
	mode, err := chooseOption(reader, "Input source", []string{"enter text", "use file"}, 1)
	if err != nil {
		return "", err
	}
	if mode == "enter text" {
		return askText(reader, "Text", "")
	}
	// use file
	path, err := askText(reader, "File path", "")
	if err != nil {
		return "", err
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// askOutput collects output options (file + clipboard).
func askOutput(reader *bufio.Reader) (outFile string, copyOut bool, err error) {
	copyOut, err = askYesNo(reader, "Copy output to clipboard?", true)
	if err != nil {
		return
	}
	save, err := askYesNo(reader, "Save output to file?", false)
	if err != nil {
		return
	}
	if save {
		choice, e := chooseOption(reader, "Output file", []string{"output.txt (default)", "enter custom path"}, 1)
		if e != nil {
			err = e
			return
		}
		if strings.Contains(choice, "default") || strings.Contains(choice, "output.txt") {
			outFile = "output.txt"
		} else {
			outFile, err = askText(reader, "Output file path", "output.txt")
		}
	}
	return
}

// askAlgoParams collects algorithm-specific parameters (shift, key, rails)
// only when they are relevant to the chosen type.
func askAlgoParams(reader *bufio.Reader, typ string) (shift int, key string, rails int, err error) {
	shift = 3
	rails = 2

	switch strings.ToLower(typ) {
	case "caesar":
		shift, err = askInt(reader, "Caesar shift", 3)
	case "vigenere", "xor":
		key, err = askText(reader, "Key", "")
		if err == nil && key == "" {
			err = fmt.Errorf("%s requires a key", typ)
		}
	case "railfence":
		rails, err = askInt(reader, "Rails", 2)
		if err == nil && rails < 2 {
			err = errors.New("rails must be >= 2")
		}
	}
	return
}
