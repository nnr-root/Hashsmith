package main

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
)

// ── Compiled regexps (immutable, goroutine-safe) ──────────────────────────────

var (
	reBase64Std = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	reBase64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+=*$`)
	reBase32Std = regexp.MustCompile(`^[A-Z2-7]+=*$`)
	reBase58Pat = regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$`)
	reBcrypt    = regexp.MustCompile(`^\$2[aby]\$\d{2}\$`)
	reArgon2    = regexp.MustCompile(`^\$argon2(i|d|id)\$`)
	reScrypt    = regexp.MustCompile(`^scrypt\$`)
	rePostgres  = regexp.MustCompile(`^md5[0-9a-fA-F]{32}$`)
	reMySQL41   = regexp.MustCompile(`^\*[0-9a-fA-F]{40}$`)
	reMSSQLNew  = regexp.MustCompile(`(?i)^0x0100[0-9a-fA-F]{48}$`) // 0x0100 + 4-byte salt + sha1 = 54 chars
	reURLEnc    = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
)

// entropyPool reuses the 256-element frequency buffer across calls — avoids
// repeated heap allocation on the hot path of entropy computation.
var entropyPool = sync.Pool{
	New: func() any { return new([256]int) },
}

// ── Types ─────────────────────────────────────────────────────────────────────

type candidate struct {
	name  string
	score float64 // raw, pre-normalization
}

// ── CLI entry ─────────────────────────────────────────────────────────────────

func runIdentify(args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text     := fs.String("i", "", "text")
	filePath := fs.String("f", "", "file path")
	outFile  := fs.String("o", "", "output file")
	copyRes  := fs.Bool("c", false, "copy to clipboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	value, err := readInput(*text, *filePath)
	if err != nil || strings.TrimSpace(value) == "" {
		return errors.New("identify requires -i text or -f file")
	}
	result := identifyText(strings.TrimSpace(value))
	if *outFile == "" && !*copyRes {
		color.New(themeAttr).Fprintln(os.Stdout, result)
		return nil
	}
	return outputResult(result, *outFile, *copyRes)
}

// ── Public API ────────────────────────────────────────────────────────────────

// identifyText returns a confidence-ranked, percentage-annotated identification
// of the input. Each line is formatted as "%<pct> <name>", sorted descending.
// Percentages sum to 100. Candidates below 5% are suppressed; if the top
// candidate is under 10%, "Unknown / High Entropy Data" is returned.
func identifyText(value string) string {
	cands := scoreCandidates(value)
	if len(cands) == 0 {
		return "%100 Unknown / High Entropy Data"
	}

	total := 0.0
	for _, c := range cands {
		total += c.score
	}
	if cands[0].score/total*100 < 10 {
		return "%100 Unknown / High Entropy Data"
	}

	// Compute rounded percentages for all visible candidates.
	type row struct {
		name string
		pct  int
		raw  float64
	}
	var rows []row
	sumPct := 0
	for _, c := range cands {
		pct := int(math.Round(c.score / total * 100))
		if pct < 5 {
			continue
		}
		rows = append(rows, row{c.name, pct, c.score})
		sumPct += pct
	}
	if len(rows) == 0 {
		return "%100 Unknown / High Entropy Data"
	}

	// Absorb rounding drift on the highest-score entry (first after score sort).
	rows[0].pct += 100 - sumPct

	// Re-sort descending by pct, then by raw score as tiebreaker.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].pct != rows[j].pct {
			return rows[i].pct > rows[j].pct
		}
		return rows[i].raw > rows[j].raw
	})

	var sb strings.Builder
	for i, e := range rows {
		if i > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "%%%d %s", e.pct, e.name)
	}
	return sb.String()
}

// ── Scoring engine ────────────────────────────────────────────────────────────

func scoreCandidates(v string) []candidate {
	if v == "" {
		return nil
	}

	var cands []candidate
	add := func(name string, score float64) {
		if score > 0 {
			cands = append(cands, candidate{name, score})
		}
	}

	// ── Level 0: signature-based (definitive) ────────────────────────────────
	// These produce unambiguous results; bypass all other analysis.
	switch {
	case reBcrypt.MatchString(v):
		return []candidate{{"bcrypt", 1000}}
	case reArgon2.MatchString(v):
		return []candidate{{"argon2", 1000}}
	case reScrypt.MatchString(v):
		return []candidate{{"scrypt", 1000}}
	case rePostgres.MatchString(v):
		return []candidate{{"PostgreSQL MD5", 1000}}
	case reMySQL41.MatchString(v):
		return []candidate{{"MySQL 4.1 / SHA-1", 1000}}
	case reMSSQLNew.MatchString(v):
		return []candidate{{"MSSQL 2005 / 2012", 1000}}
	}

	entropy := shannonEntropy(v)
	lv := len(v)
	hexStr := isHex(v)

	// entropyBonus returns an additive bonus/penalty for hex hash candidates
	// based on Shannon entropy: genuine hashes cluster near 3.8–4.0 bits.
	entropyBonus := func(base float64) float64 {
		switch {
		case entropy > 3.8:
			return base + 30
		case entropy > 3.5:
			return base + 20
		case entropy > 3.0:
			return base + 10
		case entropy > 2.5:
			return base - 10
		default:
			return base - 25 // very low entropy → unlikely to be a real hash
		}
	}

	// ── Level 1: hex hash detection (length + charset + entropy) ─────────────
	if hexStr {
		switch lv {
		case 16:
			add("MySQL 3.x", entropyBonus(75))
		case 32:
			// MD5 is far more prevalent than MD4/NTLM; small weight difference.
			add("MD5",  entropyBonus(80))
			add("NTLM", entropyBonus(68))
			add("MD4",  entropyBonus(58))
		case 40:
			add("SHA-1",      entropyBonus(80))
			add("RIPEMD-160", entropyBonus(62))
		case 56:
			add("SHA-224", entropyBonus(85))
		case 64:
			add("SHA-256",  entropyBonus(85))
			add("SHA3-256", entropyBonus(65))
			add("BLAKE2s",  entropyBonus(58))
		case 96:
			add("SHA-384", entropyBonus(85))
		case 128:
			add("SHA-512",  entropyBonus(85))
			add("SHA3-512", entropyBonus(65))
			add("BLAKE2b",  entropyBonus(58))
		}
	}

	// ── Level 2: encoding detection (charset + decode validation) ────────────
	// When the input matches a known hex-hash length, Base64/Base64URL are
	// almost certainly false positives — skip them entirely.
	hashLenHex := hexStr && knownHashLen(lv)

	// Hex encoding — only meaningful outside of standard hash lengths
	if hexStr && lv%2 == 0 {
		if hashLenHex {
			add("Hex", 8) // present but very low — dominated by hash candidates
		} else {
			s := 30.0
			if entropy < 3.5 {
				s += 20
			}
			add("Hex", s)
		}
	}

	// Base64 standard — skip when input is a known-length hex hash
	if !hashLenHex && reBase64Std.MatchString(v) && lv%4 == 0 {
		s := 25.0
		if dec, err := base64.StdEncoding.DecodeString(v); err == nil {
			s += 20
			if allPrintable(dec) {
				s += 25
			}
		}
		add("Base64", math.Max(s, 0))
	}

	// Base64 URL-safe — skip when input is a known-length hex hash
	if !hashLenHex && reBase64URL.MatchString(v) && !strings.ContainsAny(v, "+/") {
		padding := strings.Repeat("=", (4-lv%4)%4)
		if dec, err := base64.URLEncoding.DecodeString(v + padding); err == nil {
			s := 30.0
			if allPrintable(dec) {
				s += 25
			}
			add("Base64 URL", s)
		}
	}

	// Base32
	upper := strings.ToUpper(v)
	if reBase32Std.MatchString(upper) {
		if dec, err := base32.StdEncoding.DecodeString(upper); err == nil {
			s := 40.0
			if allPrintable(dec) {
				s += 25
			}
			add("Base32", s)
		}
	}

	// Base58 — require minimum length; skip pure-hex (already handled as hash/hex)
	if !hexStr && reBase58Pat.MatchString(v) && lv >= 8 {
		s := 22.0
		if entropy > 4.5 {
			s += 18
		} else if entropy > 3.5 {
			s += 8
		}
		add("Base58", s)
	}

	// Binary — space-separated 8-bit groups
	if isBinaryStr(v) {
		add("Binary", 90)
	}

	// Decimal — space-separated ASCII byte values (0–255)
	if isDecimalStr(v) {
		add("Decimal", 85)
	}

	// Octal — space-separated octal byte values
	if isOctalStr(v) {
		add("Octal", 80)
	}

	// Morse code
	if isMorseStr(v) {
		add("Morse Code", 88)
	}

	// URL-encoded — presence of %XX sequences
	if reURLEnc.MatchString(v) {
		count := len(reURLEnc.FindAllString(v, -1))
		add("URL Encoded", math.Min(30+float64(count)*8, 80))
	}

	// Baconian cipher — space-separated 5-char groups of only A/B
	if isBaconianStr(v) {
		add("Baconian Cipher", 88)
	}

	// Polybius square — space-separated pairs of digits 1–5
	if isPolybiusStr(v) {
		add("Polybius Square", 88)
	}

	// Leet speak — letters mixed with leet digit/symbol substitutions
	if isLeetStr(v) {
		add("Leet Speak", 60)
	}

	// ── Level 3: cipher and plain-text classification ─────────────────────────
	allAlpha := isAllAlpha(v)

	// Substitution cipher (Caesar / Vigenere / ROT13 / Atbash):
	// A string of only alphabetical characters with no spaces is statistically
	// indistinguishable from a monoalphabetic cipher of natural-language input.
	// Entropy drives the balance: repeated-letter patterns (low entropy) lean
	// more toward cipher; high entropy leans more toward long/varied plain text.
	if allAlpha && lv >= 4 {
		var cs float64
		switch {
		case entropy <= 2.0:
			cs = 62
		case entropy <= 2.8:
			cs = 50
		case entropy <= 3.5:
			cs = 30
		case entropy <= 4.2:
			cs = 14
		}
		if cs > 0 {
			add("Substitution Cipher (Caesar / Vigenere / ROT13)", cs)
		}
	}

	// Plain text — reduced when the string is all-alpha without spaces (ambiguous
	// with substitution ciphers) or when the charset overlaps with encodings.
	{
		ratio := printableRatio(v)
		if ratio >= 0.85 {
			s := 18.0
			if strings.ContainsAny(v, " \t") {
				s += 15 // spaces are the strongest plain-text signal
			}
			if hexStr {
				s -= 14
			} else if reBase64Std.MatchString(v) {
				s -= 10
			}
			if allAlpha && !strings.ContainsAny(v, " \t") {
				s -= 8 // no spaces → ambiguous with cipher, reduce plain-text weight
			}
			add("Plain Text", math.Max(s, 4))
		}
	}

	if len(cands) == 0 {
		return nil
	}

	sort.Slice(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})
	return cands
}

// knownHashLen reports whether l is a standard hex-hash output length.
func knownHashLen(l int) bool {
	switch l {
	case 16, 32, 40, 56, 64, 96, 128:
		return true
	}
	return false
}

// ── Shannon entropy (O(n), pool-backed) ──────────────────────────────────────

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	buf := entropyPool.Get().(*[256]int)
	freq := buf
	for i := range freq {
		freq[i] = 0
	}
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	entropyPool.Put(buf)
	return h
}

// ── String classifiers ────────────────────────────────────────────────────────

func allPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
		if c == 0x7f {
			return false
		}
	}
	return true
}

func printableRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			n++
		}
	}
	return float64(n) / float64(len(s))
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

func isAllAlpha(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// isBaconianStr checks for Baconian cipher: space-separated groups of exactly
// 5 characters, each being only 'A' or 'B' (case-insensitive).
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

// isPolybiusStr checks for Polybius square encoding: space-separated pairs of
// digits where each digit is in the range 1–5.
func isPolybiusStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		if p[0] < '1' || p[0] > '5' || p[1] < '1' || p[1] > '5' {
			return false
		}
	}
	return true
}

// isLeetStr checks for leet speak: a mix of alphabetical characters and
// classic leet digit/symbol substitutions (3→e, 0→o, 1→i/l, 4→a, @→a, $→s).
// Pure hex strings are excluded since they overlap in charset.
func isLeetStr(s string) bool {
	if len(s) < 4 || isHex(s) {
		return false
	}
	leet, alpha, other := 0, 0, 0
	for _, c := range s {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			alpha++
		case c == '3' || c == '0' || c == '1' || c == '4' || c == '@' || c == '$' || c == '!':
			leet++
		default:
			other++
		}
	}
	total := leet + alpha + other
	if total == 0 {
		return false
	}
	// At least one leet char, at least one alpha char, and 80%+ are leet/alpha
	return leet >= 1 && alpha >= 1 && (leet+alpha)*100/total >= 80
}

// ── Backward-compat helpers (used by crack auto-detection) ───────────────────

// detectHashTypes returns the cracker-compatible algorithm names for a given
// hash string. Called from interactive.go and crack.go for -t auto.
func detectHashTypes(text string) []string {
	t := strings.TrimSpace(text)

	if reBcrypt.MatchString(t) {
		return []string{"bcrypt"}
	}
	if reArgon2.MatchString(t) {
		return []string{"argon2"}
	}
	if reScrypt.MatchString(t) {
		return []string{"scrypt"}
	}
	if rePostgres.MatchString(t) {
		return []string{"postgres"}
	}
	if reMySQL41.MatchString(t) {
		return []string{"mysql41"}
	}
	if reMSSQLNew.MatchString(t) {
		return []string{"mssql2005", "mssql2012"}
	}
	if !isHex(t) {
		return nil
	}
	switch len(t) {
	case 16:
		return []string{"mysql323"}
	case 32:
		return []string{"md5", "md4", "ntlm"}
	case 40:
		return []string{"sha1", "ripemd160"}
	case 56:
		return []string{"sha224"}
	case 64:
		return []string{"sha256", "sha3_256", "blake2s"}
	case 96:
		return []string{"sha384"}
	case 128:
		return []string{"sha512", "sha3_512", "blake2b"}
	default:
		return nil
	}
}

// unique removes duplicates while preserving insertion order.
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
