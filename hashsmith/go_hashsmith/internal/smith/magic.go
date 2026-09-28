package smith

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ── Magic: recursive automatic decoding ───────────────────────────────────────
//
// Given a string, try every decoder, keep the results that look like they mean
// something, and repeat on those — so a value that was base64'd, then gzipped,
// then hex'd comes back as text with the chain that produced it named.
//
// Neither John nor Hashcat has anything like this; it is CyberChef's "Magic"
// operation, and it is the one place where having identification and decoding
// in the SAME binary pays off directly: once a layer decodes to something that
// is not plain text, the result is handed to the hash-identification engine,
// so `magic` can end with "this is a bcrypt hash" rather than with bytes.
//
// The search is a beam search, not an exhaustive one. Sixty codecs to depth
// three is 216,000 paths; scoring prunes that to a few hundred by refusing to
// recurse on anything that does not look more meaningful than what it came
// from.

// magicCandidate is one decoded result and the chain of codecs that produced it.
type magicCandidate struct {
	value string
	chain []string
	score float64
	// identified names what the hash-identification engine makes of the value,
	// when it makes anything of it.
	identified string
}

const (
	magicDefaultDepth = 3
	magicBeamWidth    = 12
	magicMaxValueLen  = 1 << 20
	// magicMinScore is the bar a result must clear to be recursed on. Below
	// it, a "decode" has almost certainly produced noise that happens to be
	// well-formed for some alphabet.
	magicMinScore = 0.45
)

// magicCodecs are the decoders magic will try.
//
// Keyed and parameterised codecs are excluded deliberately: caesar, vigenere,
// xor and railfence need a key or a rail count that magic does not have, so
// including them would mean trying one arbitrary parameter and reporting the
// noise it produced as a finding. A tool that guesses and does not say it
// guessed is worse than one that declines.
func magicCodecs() []string {
	skip := map[string]bool{
		"caesar": true, "vigenere": true, "xor": true, "railfence": true,
		"rot5": true, "rot13": true, "rot18": true, "rot47": true,
		"atbash": true, "leet": true, "reverse": true, "upper": true, "lower": true,
		"nato": true, "a1z26": true, "baconian": true, "polybius": true,
		"basen": true, "affine": true, "beaufort": true, "autokey": true,
		"gronsfeld": true, "playfair": true, "bifid": true, "nihilist": true,
		"columnar": true, "scytale": true, "adfgvx": true,
		// Identity-ish and too-permissive alphabets match almost anything and
		// would flood the beam with noise.
		"binary": true, "decimal": true, "octal": true,
		// Raw DEFLATE, LZMA-alone and Brotli carry no magic number, so their
		// decoders accept arbitrary bytes and emit arbitrary bytes. zstd, xz,
		// bzip2, gzip and zlib all start with a signature the decoder checks,
		// which is what makes those safe for a search that tries everything.
		"deflate": true, "lzma": true, "brotli": true,
	}
	var out []string
	for _, g := range codecCatalogue {
		for _, item := range g.items {
			if !skip[item[0]] {
				out = append(out, item[0])
			}
		}
	}
	return out
}

// magicScoreFrom rates a decoded value in the light of what it came from.
//
// The context matters. Reading a run of ASCII hex as UTF-16 produces valid,
// printable CJK, which scores a perfect 1.0 on character statistics alone and
// buried the correct single-step answer underneath four pages of it. A decode
// that turns plain ASCII into a wall of non-Latin script is almost always the
// wrong decode, and saying so needs the input, not just the output.
func magicScoreFrom(out, parent string) float64 {
	score := magicScore(out)
	if isMostlyASCII(parent) && !isMostlyASCII(out) {
		score *= 0.3
	}
	return score
}

// isMostlyASCII reports whether most of a string is plain ASCII.
func isMostlyASCII(s string) bool {
	if s == "" {
		return true
	}
	ascii, total := 0, 0
	for _, r := range s {
		total++
		if r < utf8.RuneSelf {
			ascii++
		}
	}
	return float64(ascii)/float64(total) >= 0.8
}

// magicScore rates how much a string looks like something a person meant.
//
// The score is a fraction in [0,1]. It rewards printable, valid UTF-8 text and
// recognisable structure, and punishes the high-entropy byte soup a wrong
// decode produces.
func magicScore(s string) float64 {
	if s == "" {
		return 0
	}
	if !utf8.ValidString(s) {
		return 0.05
	}

	var printable, letters, spaces, control int
	total := 0
	for _, r := range s {
		total++
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			printable++
		case unicode.IsControl(r):
			control++
		case unicode.IsSpace(r):
			printable++
			spaces++
		default:
			printable++
			if unicode.IsLetter(r) {
				letters++
			}
		}
	}
	if total == 0 {
		return 0
	}
	score := float64(printable) / float64(total)
	score -= 2 * float64(control) / float64(total)

	// Text that a person wrote has spaces and letters in roughly human
	// proportions; a wrong decode that happens to be printable usually has
	// neither.
	letterRatio := float64(letters) / float64(total)
	if letterRatio > 0.3 {
		score += 0.15
	}
	spaceRatio := float64(spaces) / float64(total)
	if spaceRatio > 0.05 && spaceRatio < 0.3 {
		score += 0.2
	}

	// Structure worth naming.
	trimmed := strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}"),
		strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
		score += 0.25 // JSON-shaped
	case strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">"):
		score += 0.2 // markup
	case strings.HasPrefix(trimmed, "-----BEGIN "):
		score += 0.35 // PEM
	case strings.HasPrefix(trimmed, "http://"), strings.HasPrefix(trimmed, "https://"):
		score += 0.3
	}

	// A result that is still obviously an encoding is not the answer, however
	// printable it is. Hex digits and a bare base64 alphabet score 1.0 on
	// printability alone, which would rank an intermediate layer level with
	// the plain text underneath it and hide the chain that actually explains
	// the input.
	if looksStillEncoded(trimmed) {
		score *= 0.55
	}
	// English-looking text is the usual destination, and a couple of common
	// words is a far stronger signal than character statistics.
	if containsCommonWord(s) {
		score += 0.25
	}

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}

// looksStillEncoded reports whether a value looks like another encoding layer
// rather than a destination: a long run drawn from one alphabet, with no
// spaces to break it up.
func looksStillEncoded(s string) bool {
	if len(s) < 8 || strings.ContainsAny(s, " \t\n") {
		return false
	}
	allHex, allB64 := true, true
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		isB64 := isHex || (c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z') ||
			c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
		if !isHex {
			allHex = false
		}
		if !isB64 {
			allB64 = false
		}
		if !allHex && !allB64 {
			return false
		}
	}
	if allHex && len(s)%2 == 0 {
		return true
	}
	return allB64 && len(s) >= 16
}

// magicCommonWords are short, high-frequency English words. Two or more of
// them in a value is strong evidence it is the destination and not another
// layer. Matching is on whole words, so "the" does not fire inside "there".
var magicCommonWords = []string{
	"the", "and", "for", "you", "that", "this", "with", "have", "not",
	"are", "was", "from", "they", "his", "her", "but", "all", "can",
	"password", "user", "name", "key", "secret", "admin", "login",
}

func containsCommonWord(s string) bool {
	lower := strings.ToLower(s)
	hits := 0
	for _, w := range magicCommonWords {
		idx := 0
		for {
			j := strings.Index(lower[idx:], w)
			if j < 0 {
				break
			}
			at := idx + j
			beforeOK := at == 0 || !isWordByte(lower[at-1])
			end := at + len(w)
			afterOK := end >= len(lower) || !isWordByte(lower[end])
			if beforeOK && afterOK {
				hits++
				break
			}
			idx = at + 1
		}
		if hits >= 2 {
			return true
		}
	}
	return hits >= 2
}

func isWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// magicDecode searches for decode chains that turn input into something
// meaningful, best first.
func magicDecode(input string, maxDepth int) []magicCandidate {
	if maxDepth < 1 {
		maxDepth = magicDefaultDepth
	}
	codecs := magicCodecs()

	seen := map[string]bool{input: true}
	frontier := []magicCandidate{{value: input, score: magicScore(input)}}
	var results []magicCandidate

	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		var next []magicCandidate
		for _, cur := range frontier {
			for _, codec := range codecs {
				// magic's own ceiling, not the standalone decoder's: anything
				// larger is discarded below, so inflating it first is waste.
				out, err := decodeTextLimited(cur.value, codec, 3, "", 2, magicMaxValueLen)
				if err != nil || out == "" || out == cur.value {
					continue
				}
				if len(out) > magicMaxValueLen || seen[out] {
					continue
				}
				seen[out] = true

				cand := magicCandidate{
					value: out,
					chain: append(append([]string{}, cur.chain...), codec),
					score: magicScoreFrom(out, cur.value),
				}
				// A decode that made the value LESS meaningful is noise.
				if cand.score < magicMinScore && cand.score <= cur.score {
					continue
				}
				cand.identified = magicIdentify(out)
				results = append(results, cand)
				next = append(next, cand)
			}
		}
		sort.SliceStable(next, func(i, j int) bool { return next[i].score > next[j].score })
		if len(next) > magicBeamWidth {
			next = next[:magicBeamWidth]
		}
		frontier = next
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].score != results[j].score {
			return results[i].score > results[j].score
		}
		// Prefer the shorter chain when two results score the same: a single
		// decode that explains the input beats three that also happen to.
		return len(results[i].chain) < len(results[j].chain)
	})
	return results
}

// magicIdentify asks the hash-identification engine what a decoded value is.
// This is the payoff for having identification and decoding in one binary: a
// chain can end at "that is a bcrypt hash" rather than at bytes.
func magicIdentify(s string) string {
	t := strings.TrimSpace(s)
	if t == "" || len(t) > 4096 {
		return ""
	}
	types := detectHashTypes(t)
	if len(types) == 0 {
		return ""
	}
	if len(types) > 3 {
		types = types[:3]
	}
	return strings.Join(types, ", ")
}

// formatMagicChain renders a chain for display.
func formatMagicChain(chain []string) string {
	if len(chain) == 0 {
		return "(none)"
	}
	return strings.Join(chain, " -> ")
}

// magicPreview shortens a value for a one-line report.
func magicPreview(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", "\\n"), "\t", "\\t")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func runMagic(args []string) error {
	if len(args) == 0 || wantsHelp(args) {
		fmt.Println("Usage: hashsmith magic [--depth N] [--all] INPUT...")
		fmt.Println()
		fmt.Println("Try every decoder, keep what looks meaningful, and repeat — so a value")
		fmt.Println("that was base64'd then gzipped comes back as text with the chain named.")
		fmt.Println("A result that looks like a hash is identified rather than left as bytes.")
		fmt.Println()
		fmt.Println("  --depth N   how many layers to peel (default 3)")
		fmt.Println("  --all       show every candidate, not just the best few")
		return nil
	}
	depth := magicDefaultDepth
	showAll := false
	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--depth", "-d":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &depth)
			}
		case "--all":
			showAll = true
		default:
			positional = append(positional, args[i])
		}
	}
	inputs, err := gatherInputsOpts(positional, payloadInputOpts())
	if err != nil {
		return err
	}

	for _, in := range inputs {
		accentPrintln(fmt.Sprintf("magic %q", magicPreview(in, 60)))
		results := magicDecode(in, depth)
		if len(results) == 0 {
			clrYellow.Println("  nothing decoded to anything more meaningful than the input")
			continue
		}
		shown := results
		if !showAll && len(shown) > 8 {
			shown = shown[:8]
		}
		for _, r := range shown {
			fmt.Printf("  %-34s %.2f  %s\n", formatMagicChain(r.chain), r.score, magicPreview(r.value, 60))
			if r.identified != "" {
				clrGreen.Printf("  %-34s       identified as: %s\n", "", r.identified)
			}
		}
		if !showAll && len(results) > len(shown) {
			fmt.Printf("  (%d more — pass --all)\n", len(results)-len(shown))
		}
	}
	return nil
}
