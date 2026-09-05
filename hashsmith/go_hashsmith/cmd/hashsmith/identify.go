package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

// ── Compiled regexps (immutable, goroutine-safe) ──────────────────────────────

var (
	reBase64Std = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	reBase64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+=*$`)
	reBase32Std = regexp.MustCompile(`^[A-Z2-7]+=*$`)
	reBase32Hex = regexp.MustCompile(`^[0-9A-V]+=*$`)
	reBase58Pat = regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$`)
	reBase62Pat = regexp.MustCompile(`^[0-9A-Za-z]+$`)
	reBcrypt    = regexp.MustCompile(`^\$2[aby]\$\d{2}\$`)
	reArgon2    = regexp.MustCompile(`^\$argon2(i|d|id)\$`)
	reScrypt    = regexp.MustCompile(`(?i)^scrypt(?:\$|:)`)
	rePostgres  = regexp.MustCompile(`^md5[0-9a-fA-F]{32}$`)
	reMySQL41   = regexp.MustCompile(`^\*[0-9a-fA-F]{40}$`)
	reMSSQLNew  = regexp.MustCompile(`(?i)^0x0100[0-9a-fA-F]{48}$`)
	reMSSQL2012 = regexp.MustCompile(`(?i)^0x0200[0-9a-fA-F]{136}$`)
	reURLEnc    = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	reJSONEsc   = regexp.MustCompile(`\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})`)
	reHexEsc    = regexp.MustCompile(`(?:\\[xX][0-9a-fA-F]{2})`)
	reJWT       = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	reUUID      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ── CLI entry ─────────────────────────────────────────────────────────────────

func runIdentify(args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text := fs.String("i", "", "hash text or file path")
	filePath := fs.String("f", "", "file path (optional; -i also accepts a file)")
	outFile := fs.String("o", "", "output file")
	copyRes := fs.Bool("c", false, "copy to clipboard")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON (schema hashsmith.identify/1)")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	inputs, err := collectIdentifyInputs(*text, *filePath, fs.Args())
	if err != nil {
		return err
	}

	if *asJSON {
		return runIdentifyJSON(inputs, *outFile, *copyRes)
	}

	// Identify every input; when more than one is given (a multi-line file)
	// each result is prefixed with the hash it describes. confident tracks
	// whether every input resolved to at least one unsuppressed certain or
	// likely candidate — identifyExitError(1) is returned when it does not,
	// so `identify` can participate in a shell chain the way `crack` does.
	var sb strings.Builder
	confident := true
	for i, in := range inputs {
		if len(inputs) > 1 {
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "── %s\n", in)
		}
		cs := identifyCandidates(in)
		sb.WriteString(renderIdentifyHuman(strings.TrimSpace(in), cs))
		if identifyExitCode(cs) != 0 {
			confident = false
		}
		if len(inputs) > 1 {
			sb.WriteString("\n")
		}
	}
	result := strings.TrimRight(sb.String(), "\n")

	if *outFile == "" && !*copyRes {
		color.New(themeAttr).Fprintln(os.Stdout, result)
	} else if err := outputResult(result, *outFile, *copyRes); err != nil {
		return err
	}
	if !confident {
		return identifyExitError(1)
	}
	return nil
}

// runIdentifyJSON is --json's rendering path: one identifyReport object per
// input, marshalled with json.MarshalIndent and printed uncoloured so the
// output stays valid JSON for a script to parse. It shares identifyExitError
// with the human path so `identify --json` and `identify` give a caller the
// same 0/1 contract regardless of which rendering it asked for.
func runIdentifyJSON(inputs []string, outFile string, copyRes bool) error {
	var sb strings.Builder
	confident := true
	for i, in := range inputs {
		cs := identifyCandidates(in)
		rep := buildIdentifyReport(strings.TrimSpace(in), cs)
		blob, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.Write(blob)
		sb.WriteString("\n")
		if identifyExitCode(cs) != 0 {
			confident = false
		}
	}
	result := strings.TrimRight(sb.String(), "\n")

	if outFile == "" && !copyRes {
		fmt.Fprintln(os.Stdout, result)
	} else if err := outputResult(result, outFile, copyRes); err != nil {
		return err
	}
	if !confident {
		return identifyExitError(1)
	}
	return nil
}

// identifyExitError carries identify's own exit status (0 or 1 — never 2)
// through the ordinary error-returning path without colliding with a real
// usage/I-O error, which must still exit 2 via fail(). Only main.go unwraps
// it (see handleIdentifyErr); it deliberately reuses runCrack's existing
// mechanism — the package-level exitCode variable read once by the closing
// os.Exit(exitCode) in main — rather than adding a second exit path.
type identifyExitError int

func (e identifyExitError) Error() string {
	return fmt.Sprintf("identify found no certain or likely candidate (exit %d)", int(e))
}

// collectIdentifyInputs resolves the identify target(s). Precedence:
//  1. -f <file>            → every non-empty, non-comment line
//  2. -i <value>           → a file's lines if the value is a readable file,
//     otherwise the literal value itself
//  3. positional argument  → same flexible handling as -i
//
// This lets `-i` accept inline text ('…' / "…") or a file path (hash.txt)
// interchangeably.
func collectIdentifyInputs(iVal, fVal string, positional []string) ([]string, error) {
	if strings.TrimSpace(fVal) != "" {
		return readInputLines(fVal)
	}
	// Gather from the -i value and any positional args, each of which may itself
	// be inline text, a comma-list, or a file path.
	var raw []string
	if strings.TrimSpace(iVal) != "" {
		raw = append(raw, iVal)
	}
	raw = append(raw, positional...)
	if len(raw) == 0 {
		return nil, errors.New("identify requires a hash value, a comma-list, or a file path")
	}
	return gatherInputs(raw)
}

// ── Public API ────────────────────────────────────────────────────────────────

// identifyText renders identify's confidence-ranked, non-percentage output.
func identifyText(value string) string {
	return renderIdentifyHuman(strings.TrimSpace(value), identifyCandidates(value))
}

// ── Format / charset classifiers ──────────────────────────────────────────────

func allPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return false
		}
	}
	return true
}

func isBinaryStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		if len(p) != 8 {
			return false
		}
		for _, c := range p {
			if c != '0' && c != '1' {
				return false
			}
		}
	}
	return true
}

func isDecimalStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isOctalStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '7' {
				return false
			}
			n = n*8 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isMorseStr(s string) bool {
	if s == "" {
		return false
	}
	hasDot, hasDash := false, false
	for _, c := range s {
		switch c {
		case '.':
			hasDot = true
		case '-':
			hasDash = true
		case '/', ' ':
		default:
			return false
		}
	}
	return hasDot || hasDash
}

func isBaconianStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 1 {
		return false
	}
	for _, p := range parts {
		if len(p) != 5 {
			return false
		}
		for _, c := range strings.ToUpper(p) {
			if c != 'A' && c != 'B' {
				return false
			}
		}
	}
	return true
}

func isPolybiusStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 || p[0] < '1' || p[0] > '5' || p[1] < '1' || p[1] > '5' {
			return false
		}
	}
	return true
}

// hasBase62OnlyChar returns true if s contains at least one character that is
// valid in Base62 but absent from the Base58 alphabet: '0', 'O', 'I', 'l'.
// This distinguishes a genuine Base62 string from one that is also valid Base58.
func hasBase62OnlyChar(s string) bool {
	for _, c := range s {
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return true
		}
	}
	return false
}

// isNATOStr checks whether s is a sequence of NATO phonetic words.
// Returns (match, wordCount). A match requires at least 2 tokens AND ≥75% of
// tokens must be valid NATO words (guards against false positives on plain text).
//
// Tokenisation: split on whitespace and commas only so that "X-ray" is kept
// as a single token and matched directly against natoWordSet.  Only when a
// whole-token lookup fails is the token expanded by splitting on dashes,
// enabling inputs like "Alpha-Bravo-Charlie" to be identified correctly.
func isNATOStr(s string) (bool, int) {
	cleaned := strings.ReplaceAll(s, ",", " ")
	rawTokens := strings.Fields(strings.TrimSpace(cleaned))

	// Expand tokens: keep token whole if it matches; dash-split otherwise.
	var tokens []string
	for _, t := range rawTokens {
		if t == "" || t == "/" {
			continue
		}
		if natoWordSet[strings.ToLower(t)] {
			tokens = append(tokens, t)
		} else {
			tokens = append(tokens, strings.Split(t, "-")...)
		}
	}

	natoCount, total := 0, 0
	for _, t := range tokens {
		if t == "" {
			continue
		}
		total++
		if natoWordSet[strings.ToLower(t)] {
			natoCount++
		}
	}
	if total < 2 || natoCount < 2 {
		return false, 0
	}
	if natoCount*100/total < 75 {
		return false, 0
	}
	return true, natoCount
}

// isBrainfuckStr detects Brainf*ck source code: the 8 operators (+ - < > [ ] . ,)
// must constitute at least 60% of all non-whitespace characters.
func isBrainfuckStr(s string) bool {
	if len(s) < 4 {
		return false
	}
	ops, total := 0, 0
	for _, c := range s {
		switch c {
		case ' ', '\t', '\n', '\r':
			// whitespace is not counted
		case '+', '-', '<', '>', '[', ']', '.', ',':
			ops++
			total++
		default:
			total++
		}
	}
	return ops >= 4 && total > 0 && ops*100/total >= 60
}

// isUUStr validates a single UU-encoded line: the first byte encodes the count
// of decoded bytes (count + 0x20), and all subsequent bytes must be in [0x20,0x60].
func isUUStr(s string) bool {
	s = strings.TrimRight(s, "\r\n ")
	if len(s) < 2 {
		return false
	}
	lc := s[0]
	if lc < 0x20 || lc > 0x60 {
		return false
	}
	decodedLen := int(lc - 0x20)
	if decodedLen == 0 {
		return len(s) == 1
	}
	expectedEncLen := ((decodedLen + 2) / 3) * 4
	if len(s) != expectedEncLen+1 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x60 {
			return false
		}
	}
	return true
}

// ── Backward-compat (used by crack auto-detection) ────────────────────────────

// looksLikeCryptHash reports whether s is a bare Unix crypt(3) shadow hash:
// a $-tagged scheme ($1$/$apr1$/$5$/$6$ or bcrypt $2[aby]$) or a 13-char
// descrypt.
func looksLikeCryptHash(s string) bool {
	if strings.HasPrefix(s, "$1$") || strings.HasPrefix(s, "$apr1$") || strings.HasPrefix(s, "$5$") ||
		strings.HasPrefix(s, "$6$") || reBcrypt.MatchString(s) {
		return true
	}
	return looksLikeDescrypt(s)
}

// stripShadowUsername pulls the hash field out of a "user:hash[:...]" line — the
// shape produced by shadow2smith and by raw /etc/shadow entries. It
// only strips when the second colon-separated field is itself a crypt hash, so
// NetNTLM ("user::domain:…") and other colon-bearing formats are left intact.
func stripShadowUsername(s string) string {
	if !strings.Contains(s, ":") {
		return s
	}
	fields := strings.Split(s, ":")
	if len(fields) >= 2 && looksLikeCryptHash(fields[1]) {
		// Don't strip when the first field is itself an md5/sha1 hash — that is a
		// vBulletin/DCC/Redmine "hash:salt", not a "user:crypthash" shadow line.
		if isHex(fields[0]) && (len(fields[0]) == 32 || len(fields[0]) == 40) {
			return s
		}
		return fields[1]
	}
	return s
}

// detectHashTypes returns the candidate -t names for a target, in the order
// crack should try them.
func detectHashTypes(text string) []string {
	types, _ := detectTypesFromTable(text)
	return types
}

func unique(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}
