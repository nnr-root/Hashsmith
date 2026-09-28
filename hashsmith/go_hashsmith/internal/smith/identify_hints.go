package smith

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"hashsmith-go/internal/hashid"
)

// hintTags maps a user-supplied --hint keyword to the canonical Hashsmith
// types that keyword is consistent with.
//
// A hint is provenance the USER already knows about the input — "this came
// out of /etc/shadow", "this is a Windows SAM dump" — not new structural
// evidence about the hash string itself. That is why applyHints (below) may
// only reorder within a candidate's existing confidence band and may
// annotate its Reason; it must never promote a Candidate.Confidence value,
// which would assert proof the detection engine did not actually produce.
// This is the same discipline hash_john_labels.go applies to John labels and
// Prototype.Rationale applies to prevalence: a claim about the world needs a
// basis, and "the user typed a word" is provenance, not structural proof.
//
// TestHintTagsNameRealFormats proves every value here names a type that
// exists in universalHashRegistry. It does not and cannot prove the mapping
// is exhaustive or that no other type is also consistent with a tag — these
// lists are deliberately conservative starting points, not closed sets.
var hintTags = map[string][]string{
	"shadow": {"md5crypt", "apr1", "sha256crypt", "sha512crypt", "yescrypt", "bcrypt", "descrypt", "sha1crypt"},
	"linux":  {"md5crypt", "apr1", "sha256crypt", "sha512crypt", "yescrypt", "bcrypt", "descrypt", "sha1crypt"},
	"unix":   {"md5crypt", "apr1", "sha256crypt", "sha512crypt", "yescrypt", "bcrypt", "descrypt", "sha1crypt"},

	"windows": {"ntlm", "lm"},
	"sam":     {"ntlm", "lm"},
	"ad":      {"ntlm", "netntlmv1", "netntlmv2", "dcc", "dcc2"},
	"domain":  {"ntlm", "netntlmv1", "netntlmv2", "dcc", "dcc2"},

	"mysql":    {"mysql323", "mysql41"},
	"mssql":    {"mssql2000", "mssql2005", "mssql2012"},
	"postgres": {"postgres"},
	"oracle":   {"oracle11g", "oracle12c"},
	"database": {"mysql323", "mysql41", "mssql2000", "mssql2005", "mssql2012", "postgres", "oracle11g", "oracle12c"},

	"cisco":   {"cisco-pix", "cisco-asa", "cisco4", "cisco-ise"},
	"juniper": {"juniper", "juniper-ive"},
	"aruba":   {"arubaos"},

	"wifi": {"wpa", "wpa-pmk", "wpa-hccapx-pmk"},
	"wpa":  {"wpa", "wpa-pmk", "wpa-hccapx-pmk"},

	"kerberos":  {"krb5tgs", "krb5asrep", "krb5pa"},
	"ad-ticket": {"krb5tgs", "krb5asrep", "krb5pa"},

	"macos": {"macos"},
	"mac":   {"macos"},

	"cms":       {"phpass", "drupal7", "mediawiki", "vbulletin", "django"},
	"wordpress": {"phpass"},
	"drupal":    {"drupal7"},

	"wallet": {"bitcoin", "ethereum", "monero"},
	"crypto": {"bitcoin", "ethereum", "monero"},

	"archive": {"zipcrypto", "zipaes256", "7z", "rar4", "rar5"},
	"office":  {"office"},
	"pdf":     {"pdf"},

	"disk":        {"luks", "truecrypt", "veracrypt", "dmg", "bitlocker", "ecryptfs"},
	"bitlocker":   {"bitlocker"},
	"diskcryptor": {"diskcryptor-xts512", "diskcryptor-xts1024", "diskcryptor-xts1536"},
	"ecryptfs":    {"ecryptfs"},

	"ike":   {"ike"},
	"ipsec": {"ike"},
	"vpn":   {"ike"},

	"snmp":    {"snmpv3"},
	"tacacs":  {"tacacs-plus"},
	"radius":  {"radius"},
	"routing": {"hsrp", "vtp", "eigrp", "ospf"},

	"aix":       {"aix"},
	"as400":     {"as400-ssha1", "as400-des"},
	"ibmi":      {"as400-ssha1", "as400-des"},
	"mainframe": {"racf", "racf-kdfaes"},
	"zos":       {"racf", "racf-kdfaes"},

	"sap": {
		"sap-b", "sap-fg", "sap-b-rfc-read-table", "sap-fg-rfc-read-table",
		"sap-issha512", "sap-issha1", "sap-issha256", "sap-issha384", "sappse",
	},

	"keychain": {
		"keepass", "keepass-keyfile", "bitwarden", "1password", "1password-cloud",
		"1password8", "lastpass", "lastpass-lp", "lastpass-cli", "dashlane", "pwsafe",
	},

	"ssh":      {"ssh"},
	"telegram": {"telegram-passcode", "telegram-desktop"},
	"signal":   {"signal"},
	"chap":     {"chap"},
	"iscsi":    {"chap"},

	"peoplesoft": {"peoplesoft", "peoplesoft-token"},
	"fortigate":  {"fortigate", "fortigate256"},
	"fortinet":   {"fortigate", "fortigate256"},
	"redmine":    {"redmine"},
}

// filenameHintPatterns maps a whole filename TOKEN (not a substring — see
// inferHintsFromFilename) to the hintTags key(s) it implies. Every value here
// must be a real hintTags key; TestFilenameHintPatternsUseRealTags proves it,
// the same way TestHintTagsNameRealFormats proves hintTags' own values name
// real formats.
//
// This is automatic --hint inference: a dump named "shadow_backup.txt" or
// "ntds.dit" carries the same provenance a user would otherwise type by
// hand, so identify infers it instead of making them type it — see
// inferHintsFromFilename's doc comment for why token matching, not
// substring matching, is what keeps this safe.
var filenameHintPatterns = map[string][]string{
	"shadow": {"shadow"},
	"sam":    {"windows"},
	"ntds":   {"windows"},

	"mysql":      {"mysql"},
	"postgres":   {"postgres"},
	"postgresql": {"postgres"},
	"oracle":     {"oracle"},
	"mssql":      {"mssql"},
	"sqlserver":  {"mssql"},

	"cisco":   {"cisco"},
	"juniper": {"juniper"},
	"aruba":   {"aruba"},
	"radius":  {"radius"},
	"tacacs":  {"tacacs"},

	"kerberos": {"kerberos"},
	"krb5":     {"kerberos"},
	"wpa":      {"wpa"},
	"ike":      {"ike"},
	"ipsec":    {"ipsec"},
	"vpn":      {"vpn"},
	"snmp":     {"snmp"},

	"telegram":  {"telegram"},
	"signal":    {"signal"},
	"dashlane":  {"keychain"},
	"lastpass":  {"keychain"},
	"bitwarden": {"keychain"},
	"keepass":   {"keychain"},
	"kdbx":      {"keychain"},
	"pwsafe":    {"keychain"},

	"office": {"office"},
	"pdf":    {"pdf"},

	"bitcoin":  {"wallet"},
	"ethereum": {"wallet"},
	"monero":   {"wallet"},
	"wallet":   {"wallet"},

	"wordpress":  {"wordpress"},
	"drupal":     {"drupal"},
	"peoplesoft": {"peoplesoft"},
	"fortigate":  {"fortigate"},
	"fortinet":   {"fortinet"},
	"redmine":    {"redmine"},
	"sap":        {"sap"},
	"aix":        {"aix"},
	"racf":       {"mainframe"},

	"diskcryptor": {"diskcryptor"},
	"ecryptfs":    {"ecryptfs"},
	"bitlocker":   {"bitlocker"},
	"ssh":         {"ssh"},
	"chap":        {"chap"},
	"iscsi":       {"iscsi"},
}

// candidateFilePathForHints picks the same source collectIdentifyInputs
// would (-f first, then -i or the first positional argument if either names
// a readable file), purely so inferHintsFromFilename has a basename to work
// from. It does not need to be — and deliberately is not — wired into
// collectIdentifyInputs itself: getting the "usual" file right is enough for
// an inference that only ever reorders, never asserts anything.
func candidateFilePathForHints(fVal, iVal string, positional []string) string {
	if strings.TrimSpace(fVal) != "" {
		return fVal
	}
	if strings.TrimSpace(iVal) != "" {
		if fi, err := os.Stat(iVal); err == nil && !fi.IsDir() {
			return iVal
		}
	}
	for _, p := range positional {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// inferHintsFromFilename reads provenance out of a path's basename the same
// way a user would read it themselves before typing --hint by hand.
//
// It matches whole TOKENS (the basename split on every non-alphanumeric
// byte), never substrings — "example.txt" tokenises to ["example", "txt"],
// neither of which is "sam", so it does not false-positive on "sam" merely
// appearing inside a longer word the way a bare substring search would.
// "ntds.dit" tokenises to ["ntds", "dit"] and matches on "ntds" exactly.
func inferHintsFromFilename(path string) []string {
	if path == "" {
		return nil
	}
	base := strings.ToLower(filepath.Base(path))
	tokens := strings.FieldsFunc(base, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})

	var out []string
	seen := make(map[string]bool)
	for _, tok := range tokens {
		for _, tag := range filenameHintPatterns[tok] {
			if !seen[tag] {
				seen[tag] = true
				out = append(out, tag)
			}
		}
	}
	sort.Strings(out)
	return out
}

// parseHintFlag splits --hint's comma-separated value into lower-cased,
// trimmed, de-duplicated tags. An empty flag value yields nil, not [""].
func parseHintFlag(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return unique(out)
}

// printHintWarnings reports, on stderr, every distinct --hint problem
// hintReorder surfaced (an unknown tag, or a tag that matched no candidate).
// stderr, not stdout, because --json's stdout must stay valid JSON and the
// human path's stdout is the report itself — a warning is neither.
func printHintWarnings(warnings []string) {
	for _, w := range unique(warnings) {
		fmt.Fprintln(os.Stderr, "identify: "+w)
	}
}

// printAutoHintInfo tells the user which --hint tags were inferred from the
// input's filename and applied automatically — an inferred hint changes the
// ranking exactly as much as one the user typed, so it must not be silent.
// --no-auto-hint turns this (and the inference itself) off.
func printAutoHintInfo(tags []string, path string) {
	if len(tags) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "identify: inferred --hint %s from filename %q (use --no-auto-hint to disable)\n",
		strings.Join(tags, ","), filepath.Base(path))
}

// printHintTags lists every known --hint tag and what it favors, so
// `identify --hint-tags` is the tag table's own source of truth instead of a
// list that can drift from hintTags in documentation.
func printHintTags() {
	tags := make([]string, 0, len(hintTags))
	for t := range hintTags {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	for _, t := range tags {
		types := append([]string(nil), hintTags[t]...)
		sort.Strings(types)
		fmt.Printf("  %-10s %s\n", t, strings.Join(types, ", "))
	}
}

// closestHintTag finds the hintTags key nearest to an unrecognized tag by
// Levenshtein distance, for a "did you mean" suggestion. Two guards keep a
// wrong suggestion from being worse than none: a tag shorter than 3 bytes
// never suggests at all (there is no such thing as a confident typo
// correction for "q"), and otherwise the distance must be at most a third of
// the tag's own length, rounded down, with a floor of 1 — loose enough for a
// real typo ("wnidows" -> "windows", distance 2 of 7) but not loose enough
// for an unrelated short word to land near an arbitrary tag.
func closestHintTag(tag string) (string, bool) {
	if len(tag) < 3 {
		return "", false
	}
	best, bestDist := "", -1
	for t := range hintTags {
		d := levenshtein(tag, t)
		if bestDist == -1 || d < bestDist {
			best, bestDist = t, d
		}
	}
	threshold := len(tag) / 3
	if threshold < 1 {
		threshold = 1
	}
	if bestDist < 0 || bestDist > threshold {
		return "", false
	}
	return best, true
}

// levenshtein is the standard single-row dynamic-programming edit distance,
// operating on bytes (every hintTags key and every --hint value is
// lower-cased ASCII, so byte-wise is exact here, not an approximation).
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

// hintReorder stable-reorders cs so that candidates matching any of the given
// hint tags come before the ones that don't, WITHIN each existing confidence
// band — a hint never moves a candidate from one Confidence value to
// another, only forward or back among peers that already share one. It
// returns the reordered slice and, for each hint tag that matched zero
// currently-listed candidates, a warning naming it (a likely typo or an
// irrelevant hint, either worth surfacing rather than silently doing
// nothing).
func hintReorder(cs []hashid.Candidate, hints []string) ([]hashid.Candidate, []string) {
	if len(hints) == 0 || len(cs) == 0 {
		return cs, nil
	}

	want := make(map[string]bool)
	var warnings []string
	for _, h := range hints {
		types, ok := hintTags[h]
		if !ok {
			msg := "unknown --hint tag \"" + h + "\""
			if suggestion, ok := closestHintTag(h); ok {
				msg += " (did you mean \"" + suggestion + "\"?)"
			}
			warnings = append(warnings, msg)
			continue
		}
		matched := false
		for _, t := range types {
			want[t] = true
		}
		for _, c := range cs {
			if want[c.Type] {
				matched = true
				break
			}
		}
		if !matched {
			warnings = append(warnings, "no candidate matches --hint "+h)
		}
	}
	if len(want) == 0 {
		return cs, warnings
	}

	out := make([]hashid.Candidate, len(cs))
	copy(out, cs)
	stableSortByBandThenHint(out, want)
	return out, warnings
}

// stableSortByBandThenHint keeps cs grouped by Confidence in its existing
// order (identify.Identify already sorted certain > likely > possible >
// unlikely, prevalence breaking ties) and, within each band only, moves
// hint-matched candidates ahead of the rest. Go's sort.SliceStable with a
// less function that only ever compares within a band would also work, but
// walking bands explicitly makes the "never crosses a Confidence boundary"
// guarantee visible in the code rather than implicit in a comparator.
func stableSortByBandThenHint(cs []hashid.Candidate, want map[string]bool) {
	start := 0
	for start < len(cs) {
		end := start + 1
		for end < len(cs) && cs[end].Confidence == cs[start].Confidence {
			end++
		}
		band := cs[start:end]
		matched := make([]hashid.Candidate, 0, len(band))
		rest := make([]hashid.Candidate, 0, len(band))
		for _, c := range band {
			if want[c.Type] {
				matched = append(matched, c)
			} else {
				rest = append(rest, c)
			}
		}
		copy(band, append(matched, rest...))
		start = end
	}
}
