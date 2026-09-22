package main

import (
	"strings"
	"testing"
)

// TestNetCaptureFamily runs each of the six formats a captured line can be,
// in both spellings, against John's own vectors.
func TestNetCaptureFamily(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"netlm", "netlm"},
		{"netlm", "netlm $netlm$"},
		{"nethalflm", "nethalflm"},
		{"nethalflm", "nethalflm $nethalflm$"},
		{"netlmv2", "netlmv2"},
		{"netlmv2", "netlmv2 $netlmv2$"},
		{"mschapv2", "MSCHAPv2"},
		{"mschapv2", "MSCHAPv2 $mschapv2$"},
		{"mschapv2", "mschapv2-naive"},
		{"netntlmv1", "netntlm"},
		{"netntlmv1", "netntlm $netntlm$"},
		{"netntlmv2", "netntlmv2"},
		{"netntlmv2", "netntlmv2 $netntlmv2$"},
		// A capture that carries the domain inside the user field.
		{"netntlmv2", "ntlmv2-opencl"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.format, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.format, ok, err)
		}
		// The wrong candidate differs at the FRONT, not the end: half-LM
		// answers for the first seven characters only, and LM for the first
		// fourteen, so appending to a long password changes nothing either
		// of them looks at.
		if bad, _ := verifyCandidate("x"+pass, record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.format)
		}
	}
}

// TestHalfLMAnswersForSevenCharacters pins what the half response can and
// cannot tell you. It depends on the first seven characters of the password
// and nothing else, so it confirms those seven and says nothing about the
// rest — which is the format, not a weakness in the check.
func TestHalfLMAnswersForSevenCharacters(t *testing.T) {
	record, pass := johnVector(t, "nethalflm $nethalflm$")
	if len(pass) <= 7 {
		t.Fatalf("this test needs a password longer than seven characters, got %q", pass)
	}
	for _, candidate := range []string{pass, pass[:7], pass[:7] + "anything at all"} {
		if ok, err := verifyCandidate(candidate, record, "nethalflm", "", "prefix"); err != nil || !ok {
			t.Errorf("%q: rejected although its first seven characters are right: ok=%v err=%v",
				candidate, ok, err)
		}
	}
	if bad, _ := verifyCandidate("x"+pass[1:], record, "nethalflm", "", "prefix"); bad {
		t.Error("accepted a candidate differing inside the first seven characters")
	}
}

// TestNetCaptureShapes pins the reading of a captured line's shape, which is
// the only thing that tells six formats sharing one layout apart.
func TestNetCaptureShapes(t *testing.T) {
	const (
		chal8  = "1122334455667788"
		chal16 = "5B5D7C7D7B3F2F3E3C2C602132262628"
		r16    = "6F64C5C1E35F68DD80388C0F00F34406"
		r24    = "6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD"
	)
	for _, tc := range []struct {
		name, line string
		want       []string
	}{
		{"MS-CHAPv2: two 16-byte challenges around a 24-byte response",
			"User:::" + chal16 + ":" + r24 + ":" + chal16, []string{"mschapv2"}},
		{"LMv2: an 8-byte client challenge where v2 keeps a blob",
			"D\\u:::" + chal8 + ":" + r16 + ":" + chal8, []string{"netlmv2"}},
		{"NTLMv2: a blob longer than a challenge",
			"u::d:" + chal8 + ":" + r16 + ":0101000000000000BB50305495AACA01", []string{"netntlmv2"}},
		{"half-LM: nothing in the NT field",
			"u:::" + r24 + "::" + chal8, []string{"nethalflm"}},
		{"both responses present, so either reading",
			"u:::" + r24 + ":" + r24 + ":" + chal8, []string{"netntlmv1", "netlm"}},
		{"a placeholder where the NT response would be",
			"u:::" + r24 + ":ntlm-hash:" + chal8, []string{"netlm"}},
		{"a placeholder where the LM response would be",
			"u:::lm-hash:" + r24 + ":" + chal8, []string{"netntlmv1"}},
	} {
		got := netCaptureTypes(tc.line)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: read as %v, want %v", tc.name, got, tc.want)
		}
	}
	// Lines that are not a capture at all.
	for _, line := range []string{
		"", "user::domain:only:four", "user:notempty:domain:11:22:33",
		"aad3b435b51404eeaad3b435b51404ee",
	} {
		if got := netCaptureTypes(line); got != nil {
			t.Errorf("%q: claimed as %v", line, got)
		}
	}
}

// TestNetIdentity pins where the account name comes from. NTLMv2 hashes
// upper(user) followed by the domain verbatim, and a capture may state the
// two separately or as one "DOMAIN\user" field.
func TestNetIdentity(t *testing.T) {
	for _, tc := range []struct{ user, domain, want string }{
		{"USER1", "Domain", "USER1Domain"},
		{"user1", "Domain", "USER1Domain"},
		{"TESTWORKGROUP\\NTlmv2", "", "NTLMV2TESTWORKGROUP"},
		{"user", "", "USER"},
	} {
		if got := netIdentity(tc.user, tc.domain); got != tc.want {
			t.Errorf("netIdentity(%q, %q) = %q, want %q", tc.user, tc.domain, got, tc.want)
		}
	}
}
