package main

import (
	"bufio"
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
	reBase62Pat = regexp.MustCompile(`^[0-9A-Za-z]+$`)
	reBcrypt    = regexp.MustCompile(`^\$2[aby]\$\d{2}\$`)
	reArgon2    = regexp.MustCompile(`^\$argon2(i|d|id)\$`)
	reScrypt    = regexp.MustCompile(`^scrypt\$`)
	rePostgres  = regexp.MustCompile(`^md5[0-9a-fA-F]{32}$`)
	reMySQL41   = regexp.MustCompile(`^\*[0-9a-fA-F]{40}$`)
	reMSSQLNew  = regexp.MustCompile(`(?i)^0x0100[0-9a-fA-F]{48}$`)
	reURLEnc    = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	reJWT       = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	reUUID      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reNATOSep   = regexp.MustCompile(`[\s,]+`)
)

// English letter frequencies (a–z), used for chi-squared analysis.
var englishFreq = [26]float64{
	8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15,
	0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06,
	2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
}

var entropyPool = sync.Pool{
	New: func() any { return new([256]int) },
}

// ── Types ─────────────────────────────────────────────────────────────────────

type candidate struct {
	name   string
	score  float64 // raw, pre-normalization
	reason string
}

// ── CLI entry ─────────────────────────────────────────────────────────────────

func runIdentify(args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text     := fs.String("i", "", "hash text or file path")
	filePath := fs.String("f", "", "file path (optional; -i also accepts a file)")
	outFile  := fs.String("o", "", "output file")
	copyRes  := fs.Bool("c", false, "copy to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	inputs, err := collectIdentifyInputs(*text, *filePath, fs.Args())
	if err != nil {
		return err
	}

	// Identify every input; when more than one is given (a multi-line file)
	// each result is prefixed with the hash it describes.
	var sb strings.Builder
	for i, in := range inputs {
		if len(inputs) > 1 {
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "── %s\n", in)
		}
		sb.WriteString(identifyText(in))
		if len(inputs) > 1 {
			sb.WriteString("\n")
		}
	}
	result := strings.TrimRight(sb.String(), "\n")

	if *outFile == "" && !*copyRes {
		color.New(themeAttr).Fprintln(os.Stdout, result)
		return nil
	}
	return outputResult(result, *outFile, *copyRes)
}

// collectIdentifyInputs resolves the identify target(s). Precedence:
//  1. -f <file>            → every non-empty, non-comment line
//  2. -i <value>           → a file's lines if the value is a readable file,
//                            otherwise the literal value itself
//  3. positional argument  → same flexible handling as -i
//
// This lets `-i` accept inline text ('…' / "…") or a file path (hash.txt)
// interchangeably.
func collectIdentifyInputs(iVal, fVal string, positional []string) ([]string, error) {
	if strings.TrimSpace(fVal) != "" {
		return readHashLines(fVal)
	}

	v := strings.TrimSpace(iVal)
	if v == "" && len(positional) > 0 {
		v = strings.TrimSpace(positional[0])
	}
	if v == "" {
		return nil, errors.New("identify requires a hash value or file path (use -i)")
	}

	if info, statErr := os.Stat(v); statErr == nil && !info.IsDir() {
		return readHashLines(v)
	}
	return []string{v}, nil
}

// readHashLines returns every non-empty, non-comment line of a file.
func readHashLines(path string) ([]string, error) {
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
		return nil, fmt.Errorf("no hashes found in %s", path)
	}
	return lines, nil
}

// ── Public API ────────────────────────────────────────────────────────────────

// identifyText returns a confidence-ranked, percentage-annotated identification.
// Format: "%<pct> <name> (<rationale>)", sorted descending, summing to 100.
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

	type row struct {
		name   string
		reason string
		pct    int
		raw    float64
	}
	var rows []row
	sumPct := 0
	for _, c := range cands {
		pct := int(math.Round(c.score / total * 100))
		if pct < 5 {
			continue
		}
		rows = append(rows, row{c.name, c.reason, pct, c.score})
		sumPct += pct
	}
	if len(rows) == 0 {
		return "%100 Unknown / High Entropy Data"
	}

	rows[0].pct += 100 - sumPct

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
		if e.reason != "" {
			fmt.Fprintf(&sb, "%%%d %s (%s)", e.pct, e.name, e.reason)
		} else {
			fmt.Fprintf(&sb, "%%%d %s", e.pct, e.name)
		}
	}
	return sb.String()
}

// ── Scoring engine ────────────────────────────────────────────────────────────

func scoreCandidates(v string) []candidate {
	if v == "" {
		return nil
	}

	// Level 0 — signature-based (definitive, synchronous)
	if sig := signatureMatch(v); sig != nil {
		return sig
	}

	// Pre-compute shared properties once (O(n) each)
	entropy := shannonEntropy(v)
	lv := len(v)
	hexStr := isHex(v)
	lower := v == strings.ToLower(v)
	upper := v == strings.ToUpper(v)
	hashLenHex := hexStr && knownHashLen(lv)

	// Four parallel analysis groups write candidates to a buffered channel.
	ch := make(chan candidate, 32)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreHashGroup(v, lv, entropy, hexStr, lower, upper, hashLenHex, ch)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreEncodingGroup(v, lv, entropy, hexStr, hashLenHex, ch)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreStructuralGroup(v, entropy, ch)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreCipherTextGroup(v, lv, entropy, hexStr, ch)
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	var cands []candidate
	for c := range ch {
		if c.score > 0 {
			cands = append(cands, c)
		}
	}

	sort.Slice(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})
	return cands
}

// signatureMatch returns a definitive single-candidate result for inputs that
// carry an unambiguous structural signature, bypassing probabilistic scoring.
func signatureMatch(v string) []candidate {
	switch {
	case strings.HasPrefix(v, "$zipcrypto$"):
		return []candidate{{"ZIP (ZipCrypto encrypted)", 1000, "$zipcrypto$ prefix — traditional PKWARE encryption hash"}}
	case strings.HasPrefix(v, "$zipaes128$"):
		return []candidate{{"ZIP (WinZip AES-128 encrypted)", 1000, "$zipaes128$ prefix — WinZip AES-128 hash"}}
	case strings.HasPrefix(v, "$zipaes192$"):
		return []candidate{{"ZIP (WinZip AES-192 encrypted)", 1000, "$zipaes192$ prefix — WinZip AES-192 hash"}}
	case strings.HasPrefix(v, "$zipaes256$"):
		return []candidate{{"ZIP (WinZip AES-256 encrypted)", 1000, "$zipaes256$ prefix — WinZip AES-256 hash"}}
	case strings.HasPrefix(v, "$7z$"):
		return []candidate{{"7-Zip (AES-256 encrypted)", 1000, "$7z$ prefix — 7-Zip AES hash"}}
	case strings.HasPrefix(v, "$rar3$"):
		return []candidate{{"RAR3/RAR4 (AES encrypted)", 1000, "$rar3$ prefix — RAR4 header-encryption hash"}}
	case strings.HasPrefix(v, "$rar5$"):
		return []candidate{{"RAR5 (AES-256 encrypted)", 1000, "$rar5$ prefix — RAR5 PBKDF2 hash"}}
	case strings.HasPrefix(v, "$pdf$"):
		return []candidate{{"PDF (Standard encryption)", 1000, "$pdf$ prefix — PDF Standard security handler"}}
	case strings.HasPrefix(v, "$ssh$"):
		return []candidate{{"SSH private key", 1000, "$ssh$ prefix — encrypted SSH private key"}}
	case strings.HasPrefix(v, "$pkcs8$"):
		return []candidate{{"PKCS#8 encrypted key", 1000, "$pkcs8$ prefix — PBES2 (PBKDF2) private key"}}
	case strings.HasPrefix(v, "$gpg$"):
		return []candidate{{"GPG symmetric", 1000, "$gpg$ prefix — gpg -c symmetric encryption"}}
	case strings.HasPrefix(v, "$office$"):
		return []candidate{{"MS Office (encrypted document)", 1000, "$office$ prefix — Office 2007/2010/2013"}}
	case strings.HasPrefix(v, "$keepass$"):
		return []candidate{{"KeePass database", 1000, "$keepass$ prefix — KDBX 1/2 (AES-KDF)"}}
	case strings.HasPrefix(v, "$krb5asrep$"):
		return []candidate{{"Kerberos 5 AS-REP (etype 23)", 1000, "$krb5asrep$ prefix — AS-REP roastable hash"}}
	case strings.HasPrefix(v, "$krb5tgs$"):
		return []candidate{{"Kerberos 5 TGS-REP (etype 23)", 1000, "$krb5tgs$ prefix — Kerberoastable ticket"}}
	case reBcrypt.MatchString(v):
		return []candidate{{"bcrypt", 1000, "starts with $2[aby]$ cost-factor signature"}}
	case reArgon2.MatchString(v):
		return []candidate{{"argon2", 1000, "starts with $argon2(i|d|id)$ signature"}}
	case reScrypt.MatchString(v):
		return []candidate{{"scrypt", 1000, "starts with scrypt$ signature"}}
	case rePostgres.MatchString(v):
		return []candidate{{"PostgreSQL MD5", 1000, "md5 prefix + 32-char hex"}}
	case reMySQL41.MatchString(v):
		return []candidate{{"MySQL 4.1 / SHA-1", 1000, "* prefix + 40-char hex"}}
	case reMSSQLNew.MatchString(v):
		return []candidate{{"MSSQL 2005 / 2012", 1000, "0x0100 prefix + 48-char hex salt+sha1"}}
	case reJWT.MatchString(v):
		return []candidate{{"JWT (JSON Web Token)", 1000, "eyJ header + 3-part Base64URL structure"}}
	case reUUID.MatchString(v):
		return []candidate{{"UUID", 1000, "8-4-4-4-12 hex groups"}}
	}
	return nil
}

// ── Group 1: Hex hash detection ───────────────────────────────────────────────

func scoreHashGroup(v string, lv int, entropy float64, hexStr, lower, upper, hashLenHex bool, ch chan<- candidate) {
	if !hexStr || !hashLenHex {
		return
	}

	// Entropy bonus/penalty: genuine hash outputs cluster near 3.8–4.0 bits.
	eb := func(base float64) float64 {
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
			return base - 25
		}
	}

	caseLabel := "mixed-case hex"
	if lower {
		caseLabel = "lowercase hex"
	} else if upper {
		caseLabel = "uppercase hex"
	}

	switch lv {
	case 16:
		ch <- candidate{"MySQL 3.x", eb(75), fmt.Sprintf("16-char %s, entropy %.2f", caseLabel, entropy)}

	case 32:
		// NTLM hashes are typically stored as uppercase in Windows credential stores;
		// MD5 is conventionally lowercase in most implementations.
		md5s := eb(80)
		ntlm := eb(68)
		md4s := eb(58)
		if lower {
			md5s += 20
			ntlm -= 15
		} else if upper {
			ntlm += 20
			md5s -= 5
		}
		ch <- candidate{"MD5",  math.Max(md5s, 0), fmt.Sprintf("32-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"NTLM", math.Max(ntlm, 0), fmt.Sprintf("32-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"MD4",  math.Max(md4s, 0), fmt.Sprintf("32-char %s, entropy %.2f", caseLabel, entropy)}

	case 40:
		ch <- candidate{"SHA-1",      eb(80), fmt.Sprintf("40-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"RIPEMD-160", eb(62), fmt.Sprintf("40-char %s, entropy %.2f", caseLabel, entropy)}

	case 56:
		ch <- candidate{"SHA-224", eb(85), fmt.Sprintf("56-char %s, entropy %.2f", caseLabel, entropy)}

	case 64:
		ch <- candidate{"SHA-256",  eb(85), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA3-256", eb(65), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"BLAKE2s",  eb(58), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}

	case 96:
		ch <- candidate{"SHA-384", eb(85), fmt.Sprintf("96-char %s, entropy %.2f", caseLabel, entropy)}

	case 128:
		ch <- candidate{"SHA-512",  eb(85), fmt.Sprintf("128-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA3-512", eb(65), fmt.Sprintf("128-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"BLAKE2b",  eb(58), fmt.Sprintf("128-char %s, entropy %.2f", caseLabel, entropy)}
	}
}

// ── Group 2: Encoding detection ───────────────────────────────────────────────

func scoreEncodingGroup(v string, lv int, entropy float64, hexStr, hashLenHex bool, ch chan<- candidate) {
	// Hex encoding — skip known hash lengths (those are handled by hash group)
	if hexStr && lv%2 == 0 && !hashLenHex {
		s := 30.0
		if entropy < 3.5 {
			s += 20
		}
		ch <- candidate{"Hex", s, fmt.Sprintf("%d-char hex, entropy %.2f", lv, entropy)}
	}

	// Base64 standard — skip all hex strings (hex ⊂ Base64 charset, would always match).
	// Speculative: if decoded bytes length matches a known hash size, label specifically.
	if !hexStr && reBase64Std.MatchString(v) && lv%4 == 0 {
		if dec, err := base64.StdEncoding.DecodeString(v); err == nil {
			if allPrintable(dec) {
				ch <- candidate{"Base64", 70, "decodes to printable text"}
			} else if algos, ok := hashByteLengths[len(dec)]; ok {
				for _, algo := range algos {
					ch <- candidate{
						"Base64-encoded " + algo, 85,
						fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(dec), algo),
					}
				}
			} else {
				ch <- candidate{"Base64", 45, "decodes to binary data"}
			}
		} else {
			ch <- candidate{"Base64", 25, "valid Base64 charset"}
		}
	}

	// Base64 URL-safe — speculative hash detection; suppress generic "decodes successfully".
	if !hexStr && reBase64URL.MatchString(v) && !strings.ContainsAny(v, "+/") {
		padding := strings.Repeat("=", (4-lv%4)%4)
		if dec, err := base64.URLEncoding.DecodeString(v + padding); err == nil {
			if allPrintable(dec) {
				ch <- candidate{"Base64 URL", 55, "decodes to printable text"}
			} else if algos, ok := hashByteLengths[len(dec)]; ok {
				// Require at least one Base64URL-exclusive char (_ or -) to disambiguate
				// from Base58 strings whose charset is a strict subset of Base64URL.
				if strings.ContainsAny(v, "_-") {
					for _, algo := range algos {
						ch <- candidate{
							"Base64 URL-encoded " + algo, 85,
							fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(dec), algo),
						}
					}
				}
			}
			// no generic "decodes to binary" — avoids false positives on arbitrary alphanumeric strings
		}
	}

	// Base32
	upper := strings.ToUpper(v)
	if reBase32Std.MatchString(upper) {
		if dec, err := base32.StdEncoding.DecodeString(upper); err == nil {
			s := 40.0
			reason := "decodes successfully"
			if allPrintable(dec) {
				s += 25
				reason = "decodes to printable text"
			}
			ch <- candidate{"Base32", s, reason}
		}
	}

	// Base58 — speculative: decode and cross-reference byte length against hash registry.
	// Falls back to generic Base58 when no hash length matches.
	if !hexStr && reBase58Pat.MatchString(v) && lv >= 8 {
		speculativeHit := false
		if b, err := decodeBase58(v); err == nil {
			if algos, ok := hashByteLengths[len(b)]; ok {
				speculativeHit = true
				for _, algo := range algos {
					ch <- candidate{
						"Base58-encoded " + algo, 85,
						fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(b), algo),
					}
				}
			}
		}
		if !speculativeHit {
			s := 22.0
			if entropy > 4.5 {
				s += 18
			} else if entropy > 3.5 {
				s += 8
			}
			ch <- candidate{"Base58", s, fmt.Sprintf("valid Base58 charset, entropy %.2f", entropy)}
		}
	}

	// Base62 — [0-9A-Za-z] charset, no +/=_- (distinguishes from Base64/Base64URL).
	// Speculative: if decoded bytes match a known hash size, label specifically.
	// Generic Base62 is only emitted when the string contains chars outside Base58
	// alphabet (0, O, I, l) to avoid shadowing the Base58 candidate.
	if !hexStr && reBase62Pat.MatchString(v) && !strings.ContainsAny(v, "+/=_-") && lv >= 8 {
		if b, err := decodeBase62(v); err == nil {
			if algos, ok := hashByteLengths[len(b)]; ok {
				for _, algo := range algos {
					ch <- candidate{
						"Base62-encoded " + algo, 82,
						fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(b), algo),
					}
				}
			} else if hasBase62OnlyChar(v) {
				// Contains 0/O/I/l → cannot be Base58; emit generic Base62
				s := 30.0
				if entropy > 4.5 {
					s += 18
				} else if entropy > 3.5 {
					s += 8
				}
				ch <- candidate{"Base62", s, fmt.Sprintf("valid Base62 charset (contains Base62-only chars), entropy %.2f", entropy)}
			}
		}
	}

	// Base85 (ASCII85) — '!'–'u' charset, optional <~ ~> delimiters.
	// Without delimiters the charset overlaps heavily with hex, alpha, and Base64,
	// so apply guards to suppress obvious false positives.
	if isBase85, hasDelim := isBase85Str(v); isBase85 {
		if hasDelim {
			ch <- candidate{"Base85 (ASCII85)", 82, "has <~ ~> delimiters"}
		} else if !hexStr && !isAllAlpha(v) &&
			!strings.ContainsAny(v, " \t") &&
			!(reBase64Std.MatchString(v) && lv%4 == 0) &&
			!isBase64URLDecodable(v) {
			ch <- candidate{"Base85 (ASCII85)", 38, "valid ASCII85 charset (!–u)"}
		}
	}

	// UU encoding — length-prefixed lines with ' '–'`' charset
	if isUUStr(v) {
		ch <- candidate{"UU Encoded", 78, "length-prefixed UU line format"}
	}

	// URL-encoded
	if reURLEnc.MatchString(v) {
		count := len(reURLEnc.FindAllString(v, -1))
		ch <- candidate{"URL Encoded",
			math.Min(30+float64(count)*8, 80),
			fmt.Sprintf("%d %%XX sequences", count)}
	}
}

// ── Group 3: Structural / cipher-format detection ─────────────────────────────

func scoreStructuralGroup(v string, entropy float64, ch chan<- candidate) {
	// NATO phonetic alphabet — checked first so multi-word NATO strings are not
	// mis-scored as plain text or substitution cipher.
	if ok, count := isNATOStr(v); ok {
		// Use a high raw score so NATO dominates over plain-text noise.
		// Plain text fires at ~33 pts for space-separated text; at 300 pts
		// NATO reaches ~90% (300/333) even when plain text also fires.
		score := 150.0
		if count > 3 {
			score = 300.0
		}
		ch <- candidate{"NATO Phonetic Alphabet", score,
			fmt.Sprintf("%d phonetic words detected", count)}
	}

	if isBinaryStr(v) {
		ch <- candidate{"Binary", 90, "space-separated 8-bit groups"}
	}
	if isDecimalStr(v) {
		ch <- candidate{"Decimal", 85, "space-separated byte values 0–255"}
	}
	if isOctalStr(v) {
		ch <- candidate{"Octal", 80, "space-separated octal byte values"}
	}
	morseMatch := isMorseStr(v)
	if morseMatch {
		ch <- candidate{"Morse Code", 88, "dot/dash/slash pattern"}
	}
	if isBaconianStr(v) {
		ch <- candidate{"Baconian Cipher", 88, "5-char A/B groups"}
	}
	if isPolybiusStr(v) {
		ch <- candidate{"Polybius Square", 88, "digit-pair groups (1–5)"}
	}
	if isLeetStr(v) {
		ch <- candidate{"Leet Speak", 62, fmt.Sprintf("alpha + leet substitutions, entropy %.2f", entropy)}
	}
	if !morseMatch && isBrainfuckStr(v) {
		ch <- candidate{"Brainf*ck", 85, "BF operator set (+-<>[].,)"}
	}
}

// ── Group 4: Cipher and plain-text analysis ───────────────────────────────────

func scoreCipherTextGroup(v string, lv int, entropy float64, hexStr bool, ch chan<- candidate) {
	allAlpha := isAllAlpha(v)
	hasSpaces := strings.ContainsAny(v, " \t")

	// Substitution cipher (Caesar / Vigenere / ROT13 / Atbash)
	// Signal: purely alphabetical, no spaces or digits.
	// Chi-squared against English letter frequency provides additional signal:
	// monoalphabetic ciphers of English preserve letter frequencies, so a low
	// chi-squared means the input could be either English plain text or a
	// Caesar/Atbash/ROT13 cipher of English; a high chi-squared suggests a
	// key-heavy cipher (Vigenere with random key) or non-English source text.
	if allAlpha && lv >= 4 {
		chiSq := chiSquaredEnglish(v)
		var cs float64
		var cipherReason string

		switch {
		case entropy <= 2.0:
			cs = 65
			cipherReason = fmt.Sprintf("very low entropy %.2f, repetitive pattern", entropy)
		case entropy <= 2.8:
			cs = 52
			cipherReason = fmt.Sprintf("low entropy %.2f", entropy)
		case entropy <= 3.5:
			cs = 33
			cipherReason = fmt.Sprintf("entropy %.2f", entropy)
		case entropy <= 4.2:
			cs = 16
			cipherReason = fmt.Sprintf("entropy %.2f", entropy)
		}

		if chiSq > 250 {
			cs += 18
			cipherReason += fmt.Sprintf(", unusual letter dist χ²=%.0f", chiSq)
		} else if chiSq < 40 {
			cs -= 12 // English-like distribution → plain text more likely
			cipherReason += fmt.Sprintf(", English-like dist χ²=%.0f", chiSq)
		}

		if cs > 0 {
			ch <- candidate{"Substitution Cipher (Caesar / Vigenere / ROT13)", cs, cipherReason}
		}
	}

	// Plain text
	ratio := printableRatio(v)
	if ratio >= 0.85 {
		s := 18.0
		ptReason := "printable ASCII"

		if hasSpaces {
			s += 15
			ptReason = "printable text with spaces"
		}
		if hexStr {
			s -= 14
		} else if reBase64Std.MatchString(v) {
			s -= 10
		}
		if allAlpha && !hasSpaces {
			s -= 8 // ambiguous with substitution cipher
		}

		// Entropy hard filter: for short single-token strings (no whitespace),
		// entropy > 4.2 is a strong signal against plain text.
		if entropy > 4.2 && !hasSpaces {
			s = 4
			ptReason = fmt.Sprintf("high entropy %.2f — likely not plain text", entropy)
		} else if allAlpha {
			chiSq := chiSquaredEnglish(v)
			if chiSq < 30 {
				s += 14
				ptReason += fmt.Sprintf(", English freq match χ²=%.0f", chiSq)
			}
		}

		ch <- candidate{"Plain Text", math.Max(s, 4), ptReason}
	}
}

// ── knownHashLen ──────────────────────────────────────────────────────────────

func knownHashLen(l int) bool {
	switch l {
	case 16, 32, 40, 56, 64, 96, 128:
		return true
	}
	return false
}

// ── Statistical helpers ───────────────────────────────────────────────────────

// shannonEntropy computes Shannon entropy in bits per character (O(n)).
// Uses a pooled buffer to avoid repeated heap allocation.
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

// chiSquaredEnglish computes the chi-squared statistic of a string's letter
// frequency distribution against expected English letter frequencies.
// Lower values indicate closer resemblance to English text.
func chiSquaredEnglish(s string) float64 {
	var freq [26]int
	n := 0
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			freq[c-'a']++
			n++
		case c >= 'A' && c <= 'Z':
			freq[c-'A']++
			n++
		}
	}
	if n == 0 {
		return math.MaxFloat64
	}
	fn := float64(n)
	var chi float64
	for i := 0; i < 26; i++ {
		expected := englishFreq[i] / 100.0 * fn
		if expected == 0 {
			continue
		}
		diff := float64(freq[i]) - expected
		chi += diff * diff / expected
	}
	return chi
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
	return leet >= 1 && alpha >= 1 && (leet+alpha)*100/total >= 80
}

// isBrainfuckStr detects Brainf*ck source code: the 8 operators (+ - < > [ ] . ,)
// must constitute at least 60% of all non-whitespace characters.
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

// isBase85Str validates ASCII85 encoding (range '!'–'u', special 'z'/'y' blocks).
// Returns (isBase85, hasDelimiters) where hasDelimiters indicates <~ ~> wrapping.
func isBase85Str(v string) (bool, bool) {
	s := v
	hasDelim := strings.HasPrefix(s, "<~") && strings.HasSuffix(s, "~>")
	if hasDelim {
		s = s[2 : len(s)-2]
	}
	if len(s) == 0 {
		return false, false
	}
	for _, c := range s {
		switch {
		case c == 'z' || c == 'y':
		case c >= '!' && c <= 'u':
		case c == ' ' || c == '\n' || c == '\r':
		default:
			return false, false
		}
	}
	return true, hasDelim
}

// isUUStr validates a single UU-encoded line: the first byte encodes the count
// of decoded bytes (count + 0x20), and all subsequent bytes must be in [0x20,0x60].
// isBase64URLDecodable returns true if v successfully decodes as Base64URL
// (with auto-padding). Used to suppress Base85 false positives on Base64URL strings.
func isBase64URLDecodable(v string) bool {
	if len(v) < 8 || !reBase64URL.MatchString(v) || strings.ContainsAny(v, "+/") {
		return false
	}
	padding := strings.Repeat("=", (4-len(v)%4)%4)
	_, err := base64.URLEncoding.DecodeString(v + padding)
	return err == nil
}

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

func detectHashTypes(text string) []string {
	t := strings.TrimSpace(text)
	// Archive/file hash formats produced by the *2smith extractors.
	if strings.HasPrefix(t, "$zipcrypto$") {
		return []string{"zipcrypto"}
	}
	if strings.HasPrefix(t, "$zipaes128$") {
		return []string{"zipaes128"}
	}
	if strings.HasPrefix(t, "$zipaes192$") {
		return []string{"zipaes192"}
	}
	if strings.HasPrefix(t, "$zipaes256$") {
		return []string{"zipaes256"}
	}
	if strings.HasPrefix(t, "$7z$") {
		return []string{"7z"}
	}
	if strings.HasPrefix(t, "$rar3$") {
		return []string{"rar4"}
	}
	if strings.HasPrefix(t, "$rar5$") {
		return []string{"rar5"}
	}
	if strings.HasPrefix(t, "$pdf$") {
		return []string{"pdf"}
	}
	if strings.HasPrefix(t, "$ssh$") {
		return []string{"ssh"}
	}
	if strings.HasPrefix(t, "$pkcs8$") {
		return []string{"pkcs8"}
	}
	if strings.HasPrefix(t, "$gpg$") {
		return []string{"gpg"}
	}
	if strings.HasPrefix(t, "$office$") {
		return []string{"office"}
	}
	if strings.HasPrefix(t, "$keepass$") {
		return []string{"keepass"}
	}
	if strings.HasPrefix(t, "$krb5asrep$") {
		return []string{"krb5asrep"}
	}
	if strings.HasPrefix(t, "$krb5tgs$") {
		return []string{"krb5tgs"}
	}
	if isNetNTLMLine(t) {
		// v1 and v2 share the user::domain:… shape; try both.
		return []string{"netntlmv2", "netntlmv1"}
	}
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
