package smith

import (
	"strings"
	"testing"
)

// hashcat's published -m 33800 example.
const wbb4PublishedRecord = "$2a$08$hashcatohohohohohohohegk6PN.SFkoXxDIkacAGKFN9AF8nx.Hi"

func TestWBB4NestsBcryptUnderOneSalt(t *testing.T) {
	const password = "hashcat"

	ok, err := verifyCandidate(password, wbb4PublishedRecord, "wbb4", "", "")
	if err != nil {
		t.Fatalf("published record rejected: %v", err)
	}
	if !ok {
		t.Fatal("the published -m 33800 record did not crack with its own password")
	}

	for _, wrong := range []string{"hashca", "hashcatt", "", "Hashcat"} {
		if ok, err := verifyCandidate(wrong, wbb4PublishedRecord, "wbb4", "", ""); err != nil || ok {
			t.Errorf("wrong password %q accepted (ok=%v err=%v)", wrong, ok, err)
		}
	}
}

// The nesting is the whole format, and it is invisible in the record. This
// pins that plain bcrypt does NOT crack a WBB4 record with the right password
// — which is the trap a user falls into, and the reason the catalogue entry
// says -t is required.
func TestWBB4IsNotPlainBcrypt(t *testing.T) {
	ok, err := verifyCandidate("hashcat", wbb4PublishedRecord, "bcrypt", "", "")
	if err != nil {
		t.Fatalf("bcrypt rejected the record outright: %v", err)
	}
	if ok {
		t.Error("plain bcrypt cracked a WBB4 record, so the two formats are not actually " +
			"distinct here and the nested implementation is doing nothing")
	}
}

// Auto-detection must keep offering bcrypt and must NOT offer wbb4: the record
// shapes are identical, so proposing both would double the bcrypt work on
// every bcrypt target to cover one forum product. The choice is deliberate and
// is recorded in recognition_test.go's detectableFloor comment; this pins it
// so it cannot drift either way unnoticed.
func TestWBB4RecordDetectsAsBcrypt(t *testing.T) {
	got := detectHashTypes(wbb4PublishedRecord)
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "bcrypt") {
		t.Errorf("a WBB4 record no longer detects as bcrypt at all: %v", got)
	}
	for _, typ := range got {
		if typ == "wbb4" {
			t.Errorf("auto-detection now offers wbb4, which doubles bcrypt work on every "+
				"bcrypt target; if that is intended, update detectableFloor's comment: %v", got)
		}
	}
}

// A record that is not a bcrypt crypt string at all must be reported as
// malformed rather than silently failing to match.
func TestWBB4RejectsNonBcryptRecords(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash", "$1$salt$hash",
		"$2a$08$tooshort",
		"5f4dcc3b5aa765d61d8327deb882cf99",
	} {
		if _, err := verifyCandidate("hashcat", bad, "wbb4", "", ""); err == nil {
			t.Errorf("non-bcrypt record accepted as WBB4: %q", bad)
		}
	}
}
