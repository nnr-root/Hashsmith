package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"hashsmith-go/internal/hashid"
)

func fieldValue(fs []explainField, label string) string {
	for _, f := range fs {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

func TestExplainKerberosTGS(t *testing.T) {
	rec := "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01.corp.local:1433*$" +
		strings.Repeat("a", 32) + "$" + strings.Repeat("b", 64)
	fs := explainRecord(rec, hashid.Candidate{Type: "krb5tgs", Display: "Kerberos 5 TGS-REP"})

	if got := fieldValue(fs, "etype"); !strings.HasPrefix(got, "23") {
		t.Errorf("etype = %q, want it to start with 23", got)
	}
	if got := fieldValue(fs, "user"); got != "svc_sql" {
		t.Errorf("user = %q, want svc_sql", got)
	}
	if got := fieldValue(fs, "realm"); got != "CORP.LOCAL" {
		t.Errorf("realm = %q, want CORP.LOCAL", got)
	}
}

func TestExplainJWTSurfacesAlg(t *testing.T) {
	// {"alg":"HS256","typ":"JWT"} . {"sub":"1"} . sig
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2ln"
	fs := explainRecord(jwt, hashid.Candidate{Type: "jwt", Display: "JSON Web Token"})
	if got := fieldValue(fs, "alg"); got != "HS256" {
		t.Errorf("alg = %q, want HS256", got)
	}
}

// An unsigned JWT is a finding, not a detail, and must be called out.
func TestExplainJWTFlagsAlgNone(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
	fs := explainRecord(jwt, hashid.Candidate{Type: "jwt", Display: "JSON Web Token"})
	for _, f := range fs {
		if f.Label == "alg" && f.Note != "" {
			return
		}
	}
	t.Error(`alg "none" was reported without a note flagging it`)
}

func TestExplainUnknownFormatReturnsNothing(t *testing.T) {
	if fs := explainRecord("5f4dcc3b5aa765d61d8327deb882cf99",
		hashid.Candidate{Type: "md5", Display: "MD5"}); len(fs) != 0 {
		t.Errorf("a raw digest has no internal fields, got %v", fs)
	}
}

// Vector from selftest_vectors.go / detect_golden.txt: etypes 17/18 use a
// TGS-REP shape with NO asterisk bracket at all — $krb5tgs$<etype>$user$realm
// $<checksum>$<edata> — unlike etype 23's *user$realm$spn* form. This pins
// that the non-bracketed shape still surfaces user and realm, which matters
// precisely because these are the AES tickets more common in modern
// environments.
func TestExplainKerberosTGSAESShapeSurfacesUserAndRealm(t *testing.T) {
	rec := "$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e"
	fs := explainRecord(rec, hashid.Candidate{Type: "krb5tgs"})
	if got := fieldValue(fs, "user"); got != "user" {
		t.Errorf("user = %q, want %q", got, "user")
	}
	if got := fieldValue(fs, "realm"); got != "realm" {
		t.Errorf("realm = %q, want %q", got, "realm")
	}
	if got := fieldValue(fs, "etype"); !strings.HasPrefix(got, "17") {
		t.Errorf("etype = %q, want it to start with 17", got)
	}
}

// A record too thin to validate an account structure ($krb5tgs$23$ has
// nothing after the etype; $krb5tgs$23$*svc$ has an opening '*' with no
// closing one) must not print the etype's "worth attacking" note — that
// judgement has no basis over an unvalidated structure — while still
// printing the etype value itself, which is read from a fixed, unambiguous
// position and is never wrong regardless of what follows it.
func TestExplainKerberosBailSuppressesNoteButKeepsEtypeValue(t *testing.T) {
	for _, rec := range []string{"$krb5tgs$23$", "$krb5tgs$23$*svc$"} {
		fs := explainRecord(rec, hashid.Candidate{Type: "krb5tgs"})
		if len(fs) != 1 || fs[0].Label != "etype" {
			t.Fatalf("%s: want exactly one etype field, got %v", rec, fs)
		}
		if !strings.HasPrefix(fs[0].Value, "23") {
			t.Errorf("%s: etype value = %q, want it to start with 23", rec, fs[0].Value)
		}
		if fs[0].Note != "" {
			t.Errorf("%s: etype note = %q, want it suppressed since the account structure never validated", rec, fs[0].Note)
		}
	}
}

// TestExplainMalformedRecordsDoNotPanicOrFabricate is the regression coverage
// for the defensive-decoding guarantee this task exists to provide: a
// truncated or corrupt record must never panic, and must never report a
// field it could not actually validate. Earlier work here found the parsing
// bug in explainKerberos and hand-verified a wider battery against these
// same guarantees, but that battery was discarded before commit — this
// restores permanent coverage for at least one malformed case per branch.
func TestExplainMalformedRecordsDoNotPanicOrFabricate(t *testing.T) {
	safe := func(rec string) (fs []explainField) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("explainRecord(%q) panicked: %v", rec, r)
			}
		}()
		return explainRecord(rec, hashid.Candidate{})
	}

	// krb5tgs asterisk branch (etype 23 shape): opening '*' with no closer.
	if fs := safe("$krb5tgs$23$*svc$"); len(fs) != 1 || fs[0].Label != "etype" {
		t.Errorf("krb5tgs unterminated asterisk: want etype only, got %v", fs)
	}
	// krb5tgs branch: etype only, nothing at all after it.
	if fs := safe("$krb5tgs$23$"); len(fs) != 1 || fs[0].Label != "etype" {
		t.Errorf("krb5tgs etype-only: want etype only, got %v", fs)
	}
	// krb5tgs non-asterisk branch (etype 17/18 shape): user present, realm missing.
	if fs := safe("$krb5tgs$17$user"); len(fs) != 1 || fs[0].Label != "etype" {
		t.Errorf("krb5tgs AES-shape missing realm: want etype only, got %v", fs)
	}
	// krb5asrep branch: no ':' separating the account from the checksum.
	if fs := safe("$krb5asrep$23$nouserrealm"); len(fs) != 1 || fs[0].Label != "etype" {
		t.Errorf("krb5asrep missing ':': want etype only, got %v", fs)
	}

	// Truncated JWT: only two dot-parts.
	if fs := safe("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"); fs != nil {
		t.Errorf("two-part JWT: want nil, got %v", fs)
	}

	// JWT whose header decodes fine but whose payload is valid base64url and
	// invalid JSON: the header-derived alg must still be reported, and the
	// unparseable payload must not be treated as claims data.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	badPayload := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	fs := safe(header + "." + badPayload + ".sig")
	if got := fieldValue(fs, "alg"); got != "HS256" {
		t.Errorf("JWT with invalid-JSON payload: alg = %q, want HS256 (header still decodes)", got)
	}
	for _, f := range fs {
		if f.Label == "sub" || f.Label == "iss" || f.Label == "aud" {
			t.Errorf("JWT with invalid-JSON payload: fabricated claim %+v", f)
		}
	}

	// PEM with no END line: only the header that's actually present may be
	// reported.
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK8wJgKZ\n"
	fs = safe(pem)
	if got := fieldValue(fs, "block"); got != "RSA PRIVATE KEY" {
		t.Errorf("PEM with no END line: block = %q, want %q", got, "RSA PRIVATE KEY")
	}
	if got := fieldValue(fs, "encrypted"); got != "no" {
		t.Errorf("PEM with no END line: encrypted = %q, want %q (no Proc-Type/DEK-Info present)", got, "no")
	}
}

// TestExplainOffLeavesDefaultIdentifyOutputUnchanged drives the real
// runIdentify entry point, not just explainRecord, so a future change to the
// blank-line handling around the --explain block in runIdentify cannot leak
// a stray newline into the default (no --explain) path without failing a
// test instead of only being caught by inspection.
func TestExplainOffLeavesDefaultIdentifyOutputUnchanged(t *testing.T) {
	without := captureStdout(t, func() error {
		return runIdentify([]string{"5f4dcc3b5aa765d61d8327deb882cf99"})
	})
	with := captureStdout(t, func() error {
		return runIdentify([]string{"--explain", "5f4dcc3b5aa765d61d8327deb882cf99"})
	})
	if with != without {
		t.Errorf("--explain changed output for a record with no internal structure to decode:\nwithout:\n%q\nwith:\n%q", without, with)
	}
}
