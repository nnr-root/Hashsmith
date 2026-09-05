package main

import (
	"encoding/json"
	"testing"

	"hashsmith-go/internal/hashid"
)

func TestJSONReportShape(t *testing.T) {
	rep := buildIdentifyReport("5f4dcc3b5aa765d61d8327deb882cf99",
		identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99"))
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back["schema"] != "hashsmith.identify/1" {
		t.Errorf("schema = %v, want hashsmith.identify/1", back["schema"])
	}
	cands, ok := back["candidates"].([]any)
	if !ok || len(cands) == 0 {
		t.Fatalf("candidates = %v, want a non-empty array", back["candidates"])
	}
	first := cands[0].(map[string]any)
	for _, k := range []string{"name", "type", "confidence", "tier", "hashcat", "john", "evidence", "rationale", "command"} {
		if _, present := first[k]; !present {
			t.Errorf("candidate is missing key %q", k)
		}
	}
	if first["hashcat"] != float64(0) {
		t.Errorf("md5 hashcat = %v, want 0", first["hashcat"])
	}
}

// A missing mode must be null, never 0 — 0 is a real Hashcat mode (MD5).
//
// bubblebabble is used as the no-mode/no-label fixture rather than the
// brief's suggested "hmailserver": the registry already maps hmailserver to
// Hashcat mode 1421 (hash_extra.go), so asserting it has none would assert a
// falsehood about current, correct behaviour. bubblebabble carries neither a
// Hashcat mode nor a John label (verified against hashcatMode/johnLabel),
// which is what this test needs to exist.
func TestMissingHashcatModeIsNull(t *testing.T) {
	rep := buildIdentifyReport("x", []hashid.Candidate{{
		Type: "bubblebabble", Display: "Bubble Babble", Confidence: hashid.Certain,
	}})
	blob, _ := json.Marshal(rep)
	var back map[string]any
	_ = json.Unmarshal(blob, &back)
	first := back["candidates"].([]any)[0].(map[string]any)
	if first["hashcat"] != nil {
		t.Errorf("hashcat = %v, want null; 0 is MD5's real mode and must not double as 'absent'", first["hashcat"])
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		cs   []hashid.Candidate
		want int
	}{
		{"certain", []hashid.Candidate{{Confidence: hashid.Certain}}, 0},
		{"likely", []hashid.Candidate{{Confidence: hashid.Likely}}, 0},
		{"possible only", []hashid.Candidate{{Confidence: hashid.Possible}}, 1},
		{"unlikely only", []hashid.Candidate{{Confidence: hashid.Unlikely}}, 1},
		{"none", nil, 1},
	}
	for _, c := range cases {
		if got := identifyExitCode(c.cs); got != c.want {
			t.Errorf("%s: exit = %d, want %d", c.name, got, c.want)
		}
	}
}
