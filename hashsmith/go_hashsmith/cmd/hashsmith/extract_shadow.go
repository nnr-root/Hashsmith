package main

// shadow2smith — the John-the-Ripper `unshadow` workflow.
//
// It reads an /etc/shadow file (optionally combined with /etc/passwd, matching
// `unshadow passwd shadow`) and emits one crackable "user:hash" line per account
// that carries a real password hash. Locked, disabled, and password-less
// accounts are skipped. The output feeds straight back into the cracker:
//
//	hashsmith shadow2smith -f shadow -o hashes.txt
//	hashsmith hashes.txt                     # auto-detect crypt type & crack
//
// Supported hash schemes match the crack engine: md5crypt ($1$), sha256crypt
// ($5$), sha512crypt ($6$), bcrypt ($2a/$2b/$2y$), and traditional descrypt.
// Recognised-but-unsupported schemes (yescrypt $y$, etc.) are reported so the
// account isn't silently dropped.

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// shadowEntry is one parsed account with a crackable (or recognised) hash.
type shadowEntry struct {
	user      string
	hash      string
	typeLabel string
	supported bool
}

// runExtractShadow implements the shadow2smith / unshadow command.
func runExtractShadow(args []string) error {
	fs := flag.NewFlagSet("shadow2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	shadowPath := fs.String("f", "", "shadow file path (/etc/shadow)")
	passwdPath := fs.String("p", "", "optional passwd file (/etc/passwd) to merge, unshadow-style")
	outFile := fs.String("o", "", "write hashes to file")
	copyRes := fs.Bool("c", false, "copy hashes to clipboard")

	// An explicit help request prints the command usage and stops.
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			printShadowUsage()
			return nil
		}
	}
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	// Files are normally given positionally in either order — the tool decides
	// which is the shadow file and which is passwd by looking at their contents,
	// so no -f/-p is needed:  `shadow2smith shadow.txt passwd.txt` and
	// `shadow2smith passwd.txt shadow.txt` behave identically.
	assignShadowPasswd(fs.Args(), shadowPath, passwdPath)
	if *shadowPath == "" {
		printShadowUsage()
		return errors.New("shadow2smith needs a shadow file — pass it directly " +
			"(e.g. `shadow2smith shadow.txt passwd.txt`, any order) or with -f <shadow>")
	}

	// Show the tool's decision so the auto-detection is transparent.
	clrYellow.Fprintf(os.Stderr, "Shadow file: %s\n", *shadowPath)
	if *passwdPath != "" {
		clrYellow.Fprintf(os.Stderr, "Passwd file: %s (unshadow merge)\n", *passwdPath)
	}

	hashes, order, err := parseShadowFile(*shadowPath)
	if err != nil {
		return err
	}

	// Optional passwd merge: restrict to (and order by) accounts present in
	// passwd, mirroring `unshadow passwd shadow`.
	if *passwdPath != "" {
		users, perr := parsePasswdUsers(*passwdPath)
		if perr != nil {
			return perr
		}
		var merged []string
		for _, u := range users {
			if _, ok := hashes[u]; ok {
				merged = append(merged, u)
			}
		}
		order = merged
	}

	var entries []shadowEntry
	skipped := 0
	for _, u := range order {
		label, crackable, recognised := classifyCryptHash(hashes[u])
		if !recognised {
			skipped++
			continue
		}
		entries = append(entries, shadowEntry{user: u, hash: hashes[u], typeLabel: label, supported: crackable})
	}

	printShadowResults(entries, skipped)

	// Only supported hashes go into the crackable output.
	var lines []string
	for _, e := range entries {
		if e.supported {
			lines = append(lines, e.user+":"+e.hash)
		}
	}
	if len(lines) == 0 {
		clrYellow.Fprintln(os.Stderr, "No crackable password hashes found.")
		return nil
	}
	return outputResult(strings.Join(lines, "\n"), *outFile, *copyRes)
}

// parseShadowFile reads an /etc/shadow file into a user→hash map plus the list
// of accounts in file order. Accounts whose password field is empty, locked, or
// a placeholder (*, !, !!, x, …) are excluded.
func parseShadowFile(path string) (map[string]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open shadow file %q: %w", path, err)
	}
	defer f.Close()

	out := make(map[string]string)
	var order []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		user, hash := fields[0], fields[1]
		if user == "" || !isRealHashField(hash) {
			continue
		}
		if _, seen := out[user]; !seen {
			order = append(order, user)
		}
		out[user] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return out, order, nil
}

// shadowScore rates how strongly a file looks like an /etc/shadow file (versus
// /etc/passwd). Shadow lines carry a hash or lock marker in the second colon
// field (score +1); passwd lines carry "x" there (score -1). A higher score is
// more shadow-like. An unreadable file scores very low so it never wins.
func shadowScore(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1 << 20
	}
	defer f.Close()

	score, n := 0, 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() && n < 50 {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		n++
		f1 := fields[1]
		switch {
		case strings.HasPrefix(f1, "$"), looksLikeDescrypt(f1),
			f1 == "*", f1 == "!", f1 == "!!", strings.HasPrefix(f1, "!"):
			score++
		case f1 == "x":
			score--
		}
	}
	return score
}

// fileLooksLikeShadow reports whether a file looks more like shadow than passwd.
func fileLooksLikeShadow(path string) bool { return shadowScore(path) > 0 }

// assignShadowPasswd routes positional file arguments into the shadow/passwd
// roles by content, so `shadow.txt passwd.txt` and `passwd.txt shadow.txt` are
// equivalent — the tool decides which file is which rather than trusting order.
// Explicit -f / -p (non-empty) are left untouched and take precedence.
func assignShadowPasswd(pos []string, shadowPath, passwdPath *string) {
	if len(pos) == 0 {
		return
	}
	if *shadowPath != "" {
		// -f already fixed the shadow file; a positional passwd can still fill -p.
		if *passwdPath == "" {
			for _, p := range pos {
				if !fileLooksLikeShadow(p) {
					*passwdPath = p
					break
				}
			}
		}
		return
	}
	if len(pos) == 1 {
		*shadowPath = pos[0]
		return
	}
	// Two or more files: the most shadow-like one is the shadow file; the first
	// of the rest becomes the passwd file (unless -p was already given).
	scores := make([]int, len(pos))
	best := 0
	for i, p := range pos {
		scores[i] = shadowScore(p)
		if scores[i] > scores[best] {
			best = i
		}
	}
	*shadowPath = pos[best]
	if *passwdPath == "" {
		for i, p := range pos {
			if i != best {
				*passwdPath = p
				break
			}
		}
	}
}

// printShadowUsage prints the shadow2smith command reference.
func printShadowUsage() {
	fmt.Println("shadow2smith (alias: unshadow) — extract crackable Unix login hashes")
	fmt.Println()
	fmt.Println("Turn an /etc/shadow file (optionally merged with /etc/passwd, exactly like")
	fmt.Println("John the Ripper's `unshadow passwd shadow`) into one 'user:hash' line per")
	fmt.Println("account, ready to feed straight back into the cracker.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  hashsmith shadow2smith <shadow> [passwd] [-o out] [-c]   files, any order")
	fmt.Println("  hashsmith unshadow     <shadow> [passwd] [-o out] [-c]   (alias)")
	fmt.Println()
	fmt.Println("Just pass the files directly — no -f/-p needed. The two files may be given")
	fmt.Println("in either order; the tool inspects each and decides which is shadow and")
	fmt.Println("which is passwd on its own.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -f <file>   force a file to be treated as the shadow file (optional)")
	fmt.Println("  -p <file>   force a file to be treated as the passwd file (optional)")
	fmt.Println("  -o <file>   write the 'user:hash' lines to a file instead of stdout")
	fmt.Println("  -c          copy the extracted hashes to the clipboard")
	fmt.Println()
	fmt.Println("Supported schemes: md5crypt ($1$), sha256crypt ($5$), sha512crypt ($6$),")
	fmt.Println("  bcrypt ($2a/$2b/$2y$), traditional descrypt (13-char). Locked/disabled")
	fmt.Println("  accounts (*, !, !!) are skipped; yescrypt ($y$) is flagged unsupported.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  hashsmith shadow2smith shadow.txt passwd.txt -o hashes.txt")
	fmt.Println("  hashsmith unshadow passwd.txt shadow.txt -o hashes.txt   # order doesn't matter")
	fmt.Println("  hashsmith shadow2smith shadow.txt                        # shadow alone")
	fmt.Println("  hashsmith hashes.txt                                     # auto-detect & crack")
}

// parsePasswdUsers reads the usernames from an /etc/passwd file in file order.
func parsePasswdUsers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open passwd file %q: %w", path, err)
	}
	defer f.Close()

	var users []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 1 || fields[0] == "" {
			continue
		}
		users = append(users, fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// isRealHashField reports whether a shadow password field holds an actual hash
// (as opposed to a locked/disabled/absent placeholder such as *, !, !!, or "").
func isRealHashField(h string) bool {
	switch h {
	case "", "*", "!", "!!", "!*", "x", "*LK*", "*NP*":
		return false
	}
	// A leading '!' or '*' marks a locked account even when a hash follows.
	if strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*") {
		return false
	}
	return true
}

// classifyCryptHash returns a display label plus whether the scheme is
// crackable by this tool and whether it is a recognised crypt scheme at all.
func classifyCryptHash(h string) (label string, crackable, recognised bool) {
	switch {
	case strings.HasPrefix(h, "$1$"):
		return "md5crypt", true, true
	case strings.HasPrefix(h, "$5$"):
		return "sha256crypt", true, true
	case strings.HasPrefix(h, "$6$"):
		return "sha512crypt", true, true
	case reBcrypt.MatchString(h):
		return "bcrypt", true, true
	case looksLikeDescrypt(h):
		return "descrypt", true, true
	case strings.HasPrefix(h, "$y$") || strings.HasPrefix(h, "$gy$"):
		return "yescrypt (unsupported)", false, true
	case strings.HasPrefix(h, "$7$"):
		return "scrypt-shadow (unsupported)", false, true
	case strings.HasPrefix(h, "$md5$") || strings.HasPrefix(h, "$sha1$"):
		return "Sun crypt (unsupported)", false, true
	}
	return "", false, false
}

// printShadowResults renders the parsed accounts as a table on stderr, so the
// user↔hash mapping stays visible even though the crackable output is bare lines.
func printShadowResults(entries []shadowEntry, skipped int) {
	ac := accentSprint
	fmt.Fprintf(os.Stderr, "\n%s %d account(s) with password hashes", ac("Parsed: "), len(entries))
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "  (%d locked/empty/unknown account(s) skipped)", skipped)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr)
	for _, e := range entries {
		status := clrGreen.Sprint("crackable")
		if !e.supported {
			status = clrYellow.Sprint("not supported")
		}
		fmt.Fprintf(os.Stderr, "  %-16s %-28s %s\n", e.user, e.typeLabel, status)
	}
	fmt.Fprintln(os.Stderr)
}
