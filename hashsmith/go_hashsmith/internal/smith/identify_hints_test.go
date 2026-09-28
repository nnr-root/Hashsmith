package smith

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
)

// TestHintTagsNameRealFormats mirrors TestJohnLabelSeedNamesRealFormats: it
// proves every type hintTags names actually exists in universalHashRegistry.
// It says nothing about whether a mapping is complete or correct — that is a
// claim about the world, not about this registry, and has to be checked by
// hand the way hash_john_labels.go's own header asks for its labels.
func TestHintTagsNameRealFormats(t *testing.T) {
	for tag, types := range hintTags {
		for _, typ := range types {
			if _, ok := universalHashRegistry.formats[typ]; !ok {
				t.Errorf("hintTags[%q] names unknown format %q", tag, typ)
			}
		}
	}
}

func TestParseHintFlag(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"windows", []string{"windows"}},
		{"Windows, MySQL , windows", []string{"windows", "mysql"}},
	}
	for _, c := range cases {
		got := parseHintFlag(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseHintFlag(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

// TestHintReorderNeverPromotesConfidence is the core guarantee: a hint is
// user-supplied provenance, not structural evidence, so it may reorder
// candidates within a confidence band but must never move one from a weaker
// band to a stronger one (that would assert proof the detection engine did
// not produce).
func TestHintReorderNeverPromotesConfidence(t *testing.T) {
	cs := []hashid.Candidate{
		{Type: "md5", Confidence: hashid.Likely},
		{Type: "ntlm", Confidence: hashid.Likely},
		{Type: "md4", Confidence: hashid.Possible},
		{Type: "lm", Confidence: hashid.Unlikely},
	}
	before := map[hashid.Confidence]int{}
	for _, c := range cs {
		before[c.Confidence]++
	}

	out, _ := hintReorder(cs, []string{"windows"})

	after := map[hashid.Confidence]int{}
	for _, c := range out {
		after[c.Confidence]++
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("hint changed the confidence-band population: before %v, after %v", before, after)
	}

	// "windows" -> ntlm, lm. Within the Likely band, ntlm (hint-matched)
	// must now lead md5 (not hint-matched); lm cannot move out of Unlikely
	// to sit ahead of md5/ntlm even though it is also hint-matched.
	if out[0].Type != "ntlm" {
		t.Errorf("expected ntlm first within the Likely band, got %q", out[0].Type)
	}
	if out[len(out)-1].Type != "lm" {
		t.Errorf("expected lm to stay in its own (Unlikely) band, got it at %v", out)
	}
}

func TestHintReorderNoHintsIsNoOp(t *testing.T) {
	cs := []hashid.Candidate{
		{Type: "md5", Confidence: hashid.Likely},
		{Type: "ntlm", Confidence: hashid.Likely},
	}
	out, warns := hintReorder(cs, nil)
	if !reflect.DeepEqual(out, cs) {
		t.Errorf("nil hints reordered candidates: %v", out)
	}
	if warns != nil {
		t.Errorf("nil hints produced warnings: %v", warns)
	}
}

func TestHintReorderUnknownTagWarns(t *testing.T) {
	cs := []hashid.Candidate{{Type: "md5", Confidence: hashid.Likely}}
	_, warns := hintReorder(cs, []string{"not-a-real-tag"})
	if len(warns) != 1 {
		t.Fatalf("expected one warning for an unknown tag, got %v", warns)
	}
}

func TestHintReorderNoMatchWarns(t *testing.T) {
	cs := []hashid.Candidate{{Type: "md5", Confidence: hashid.Likely}}
	// "wpa" only ever matches wpa/wpa-pmk/wpa-hccapx-pmk, none of which is md5.
	_, warns := hintReorder(cs, []string{"wpa"})
	if len(warns) != 1 {
		t.Fatalf("expected one warning for a hint matching no candidate, got %v", warns)
	}
}

// TestHintReorderIntegration exercises the real detection engine end to end:
// a bare 32-char hex string is genuinely ambiguous between MD5 and NTLM, and
// --hint windows must move NTLM to the front without changing its confidence
// word.
func TestHintReorderIntegration(t *testing.T) {
	cs := identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99")
	unhinted, _ := hintReorder(cs, nil)
	if unhinted[0].Type != "md5" {
		t.Fatalf("test assumption broken: expected md5 to lead unhinted, got %q", unhinted[0].Type)
	}

	hinted, warns := hintReorder(cs, []string{"windows"})
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if hinted[0].Type != "ntlm" {
		t.Fatalf("expected ntlm to lead after --hint windows, got %q", hinted[0].Type)
	}
	if hinted[0].Confidence != unhintedConfidenceFor(unhinted, "ntlm") {
		t.Fatalf("--hint windows changed ntlm's confidence")
	}
}

func unhintedConfidenceFor(cs []hashid.Candidate, typ string) hashid.Confidence {
	for _, c := range cs {
		if c.Type == typ {
			return c.Confidence
		}
	}
	return hashid.Unlikely
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"windows", "windows", 0},
		{"windows", "wnidows", 2}, // transposition = 2 single-char edits
		{"", "abc", 3},
		{"abc", "", 3},
		{"mysql", "mysqll", 1},
		{"kitten", "sitting", 3},
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestClosestHintTagSuggestsPlausibleTypos(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"wnidows", "windows"},
		{"mysqll", "mysql"},
		{"shado", "shadow"},
		{"kerberoz", "kerberos"},
	}
	for _, c := range cases {
		got, ok := closestHintTag(c.in)
		if !ok || got != c.want {
			t.Errorf("closestHintTag(%q) = (%q, %v), want (%q, true)", c.in, got, ok, c.want)
		}
	}
}

// TestClosestHintTagRefusesUnrelatedInput is the guard that matters most: a
// suggestion for a tag that isn't a plausible typo of anything is worse than
// no suggestion — it tells the user something false about what --hint knows.
func TestClosestHintTagRefusesUnrelatedInput(t *testing.T) {
	for _, in := range []string{"xkcd", "q", "zzzzzzzzzz", "banana"} {
		if got, ok := closestHintTag(in); ok {
			t.Errorf("closestHintTag(%q) = (%q, true), want no suggestion", in, got)
		}
	}
}

// TestHintReorderSuggestsTypoInWarning is the integration path: the
// suggestion actually reaches hintReorder's warning text.
func TestHintReorderSuggestsTypoInWarning(t *testing.T) {
	cs := []hashid.Candidate{{Type: "md5", Confidence: hashid.Likely}}
	_, warns := hintReorder(cs, []string{"wnidows"})
	if len(warns) != 1 || !strings.Contains(warns[0], `did you mean "windows"?`) {
		t.Fatalf("expected a windows suggestion in the warning, got %v", warns)
	}
}

// TestFilenameHintPatternsUseRealTags mirrors TestHintTagsNameRealFormats:
// every value filenameHintPatterns maps to must be a real hintTags key, or
// an inferred hint would silently do nothing (or worse, warn about itself).
func TestFilenameHintPatternsUseRealTags(t *testing.T) {
	for token, tags := range filenameHintPatterns {
		for _, tag := range tags {
			if _, ok := hintTags[tag]; !ok {
				t.Errorf("filenameHintPatterns[%q] names unknown hint tag %q", token, tag)
			}
		}
	}
}

func TestInferHintsFromFilename(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"shadow_dump.txt", []string{"shadow"}},
		{"/etc/shadow", []string{"shadow"}},
		{"ntds.dit", []string{"windows"}},
		{"sam.hiv", []string{"windows"}},
		{"mysql_users.txt", []string{"mysql"}},
		{"example.txt", nil},        // "sam" must NOT match inside "example"
		{"samsung_backup.txt", nil}, // same guard, a different real word
		{"", nil},
		{"plain-hashes.txt", nil},
	}
	for _, c := range cases {
		got := inferHintsFromFilename(c.path)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("inferHintsFromFilename(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestCandidateFilePathForHints(t *testing.T) {
	dir := t.TempDir()
	realFile := dir + "/shadow.txt"
	if err := os.WriteFile(realFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// -f wins even if it doesn't exist (matches collectIdentifyInputs'
	// own precedence — -f is trusted at face value).
	if got := candidateFilePathForHints("some-f-value", "", nil); got != "some-f-value" {
		t.Errorf("got %q, want the -f value", got)
	}
	// -i is only used when it is actually a readable file, not literal text.
	if got := candidateFilePathForHints("", "5f4dcc3b5aa765d61d8327deb882cf99", nil); got != "" {
		t.Errorf("literal -i text should not be treated as a path, got %q", got)
	}
	if got := candidateFilePathForHints("", realFile, nil); got != realFile {
		t.Errorf("got %q, want %q", got, realFile)
	}
	// A positional argument that is a real file is used when neither -f nor
	// -i apply.
	if got := candidateFilePathForHints("", "", []string{"not-a-file", realFile}); got != realFile {
		t.Errorf("got %q, want %q", got, realFile)
	}
}
