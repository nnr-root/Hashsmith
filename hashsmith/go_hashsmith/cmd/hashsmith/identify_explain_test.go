package main

import (
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
