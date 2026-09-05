package main

import (
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
)

func TestHumanOutputCarriesModeAndCommand(t *testing.T) {
	out := renderIdentifyHuman("5f4dcc3b5aa765d61d8327deb882cf99",
		identifyCandidates("5f4dcc3b5aa765d61d8327deb882cf99"))

	for _, want := range []string{"MD5", "likely", "-m 0", "raw-md5", "-t md5"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	if !strings.Contains(out, "hashsmith crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99") {
		t.Errorf("output missing the runnable crack command\n---\n%s", out)
	}
}

// A format Hashcat and John do not have must still be listed, with the gap
// shown rather than hidden. This is the coverage advantage made visible.
func TestFormatsWithoutForeignNamesPrintADash(t *testing.T) {
	out := renderIdentifyHuman("x", []hashid.Candidate{{
		Type: "hmailserver", Display: "hMailServer",
		Confidence: hashid.Certain, Tier: hashid.TierSignature,
		Evidence: "record prefix",
	}})
	// A bare "-" as its own whitespace-delimited column. Checking for "-"
	// anywhere would pass on "-t hmailserver" and assert nothing.
	hasDashColumn := false
	for _, f := range strings.Fields(out) {
		if f == "-" {
			hasDashColumn = true
			break
		}
	}
	if !hasDashColumn {
		t.Errorf("expected a standalone \"-\" column for the missing Hashcat mode\n---\n%s", out)
	}
	if strings.Contains(out, "-m 0") {
		t.Errorf("invented a Hashcat mode for a format that has none\n---\n%s", out)
	}
}

func TestBcryptIsASingleCertainAnswer(t *testing.T) {
	cs := identifyCandidates("$2y$10$3sBoTsNRXqMqQyvIsIWKPuJTfBjZTUgKBHVYPPYHIWpDXHJcaqTZS")
	if len(cs) == 0 || cs[0].Type != "bcrypt" || cs[0].Confidence != hashid.Certain {
		t.Fatalf("bcrypt = %+v, want a single certain bcrypt candidate", cs)
	}
}

func TestUnrecognizedInputSaysSo(t *testing.T) {
	out := renderIdentifyHuman("not a hash at all", identifyCandidates("not a hash at all"))
	if !strings.Contains(strings.ToLower(out), "no candidate") {
		t.Errorf("expected an explicit no-candidate message\n---\n%s", out)
	}
}
