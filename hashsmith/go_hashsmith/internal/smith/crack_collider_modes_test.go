package smith

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Hashcat splits MS Office 97-2003 and PDF revision 2 into two modes each.
// The first (-m 9710, 9810, 10410) recovers a five-byte intermediate, and the
// second (-m 9720, 9820, 10420) takes that answer — appended to the record
// after a colon — and finds the password behind it.
//
// Hashsmith recovers the password from the bare record in one pass, so the
// first stage is not offered as a mode: it asks for a key fragment, not a
// password, and pointing it at a password cracker would report a mode as
// supported while never returning what its user wants. Hashcat's own example
// answer for 9710 is $HEX[91b2e062b9], which is not a password at all.
//
// The RECORD those modes produce is accepted, so an existing hashcat workflow
// runs here unchanged. These vectors are hashcat's published examples.
var colliderVectors = []struct {
	name     string
	typ      string
	record   string
	fragment string
	password string
}{
	{
		name:     "oldoffice-md5",
		typ:      "9720",
		record:   "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2",
		fragment: "91b2e062b9",
		password: "hashcat",
	},
	{
		name:     "oldoffice-sha1",
		typ:      "9820",
		record:   "$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd",
		fragment: "b8f63619ca",
		password: "hashcat",
	},
	{
		name:     "pdf-r2",
		typ:      "10420",
		record:   "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000",
		fragment: "6a8aedccb7",
		password: "hashcat",
	},
}

func TestColliderRecordsCrackAndUseTheirAnswer(t *testing.T) {
	for _, v := range colliderVectors {
		t.Run(v.name, func(t *testing.T) {
			withAnswer := v.record + ":" + v.fragment

			// The record must crack with its answer attached...
			ok, err := verifyCandidate(v.password, withAnswer, v.typ, "", "")
			if err != nil {
				t.Fatalf("collider record rejected: %v", err)
			}
			if !ok {
				t.Errorf("%s did not crack its own collider record", v.typ)
			}

			// ...and without it, because the answer is an optimisation and
			// never a requirement.
			ok, err = verifyCandidate(v.password, v.record, v.typ, "", "")
			if err != nil {
				t.Fatalf("bare record rejected: %v", err)
			}
			if !ok {
				t.Errorf("%s did not crack the record without the collider answer, so the "+
					"answer has become a requirement rather than a shortcut", v.typ)
			}

			// A WRONG answer must reject. Without this the pre-filter could
			// be silently skipped — the record would still crack, the test
			// would still pass, and the optimisation would do nothing.
			wrong := v.record + ":00000000ff"
			ok, err = verifyCandidate(v.password, wrong, v.typ, "", "")
			if err != nil {
				t.Fatalf("record with a wrong collider answer rejected with an error: %v", err)
			}
			if ok {
				t.Errorf("%s cracked a record whose collider answer is wrong, so the answer is "+
					"being ignored rather than checked", v.typ)
			}

			// The wrong password must fail either way.
			for _, target := range []string{v.record, withAnswer} {
				ok, err := verifyCandidate("definitely-not-it-9137", target, v.typ, "", "")
				if err != nil {
					t.Fatalf("wrong-password check errored: %v", err)
				}
				if ok {
					t.Errorf("%s accepted a wrong password", v.typ)
				}
			}
		})
	}
}

// The first-stage modes must stay unmapped. Mapping them would make Hashsmith
// answer a different question from the one they ask, and would report a mode
// as supported while never returning what its user wants.
func TestColliderFirstStageModesAreNotClaimed(t *testing.T) {
	for _, mode := range []string{"9710", "9810", "10410"} {
		if canonical, ok := universalHashRegistry.aliases[mode]; ok {
			t.Errorf("mode %s is mapped to %q, but it recovers a key fragment rather than a "+
				"password — hashcat's own example answer for it is a $HEX[...] value", mode, canonical)
		}
	}
}

// The six mode numbers this work added, each pinned to the format it resolves
// to, so a future alias edit cannot quietly repoint one.
func TestNewlyMappedHashcatModes(t *testing.T) {
	for mode, want := range map[string]string{
		"9720":  "office-old-md5",
		"9820":  "office-old-sha1",
		"10420": "pdf",
		"22600": "telegram-desktop",
		"24500": "telegram-desktop",
		"23100": "macos-keychain",
	} {
		got, ok := universalHashRegistry.aliases[mode]
		if !ok {
			t.Errorf("hashcat mode %s is no longer mapped", mode)
			continue
		}
		if got != want {
			t.Errorf("hashcat mode %s resolves to %q; want %q", mode, got, want)
		}
	}
}

// splitColliderAnswer must not mistake ordinary record text for a collider
// answer. A ten-hex-character tail after a colon is the signature; anything
// else leaves the record whole so it fails with a message about its own
// fields rather than about colliders.
func TestColliderSplitLeavesOrdinaryRecordsAlone(t *testing.T) {
	for _, target := range []string{
		"$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2",
		"$pdf$1*2*40*-1*0*16*0122*32*27c3*32*0000",
		"nocolonhere",
		"trailing:notlongenough",
		"trailing:zzzzzzzzzz",
		"trailing:0123456789abcdef",
	} {
		rec, frag, err := splitColliderAnswer(target)
		if err != nil {
			t.Fatalf("%q: %v", target, err)
		}
		if rec != target || frag != nil {
			t.Errorf("%q was split into %q + %x; it carries no collider answer", target, rec, frag)
		}
	}
	rec, frag, err := splitColliderAnswer("$oldoffice$0*a*b*c:91b2e062b9")
	if err != nil {
		t.Fatal(err)
	}
	if rec != "$oldoffice$0*a*b*c" || strings.ToLower(hex.EncodeToString(frag)) != "91b2e062b9" {
		t.Errorf("a real collider answer was not split off: record=%q fragment=%x", rec, frag)
	}
}
