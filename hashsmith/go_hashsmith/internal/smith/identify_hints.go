package smith

import (
	"fmt"
	"os"
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
			warnings = append(warnings, "unknown --hint tag \""+h+"\"")
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
