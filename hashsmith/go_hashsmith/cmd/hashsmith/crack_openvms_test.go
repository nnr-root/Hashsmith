package main

import "testing"

// John's three vectors, which between them cover the only variant anyone has
// a published digest for and both settings of the case flag.
func TestOpenVMS(t *testing.T) {
	for _, tc := range []struct{ record, pass string }{
		{"$V$9AYXUd5LfDy-aj48Vj54P-----", "USER"},
		{"$V$p1UQjRZKulr-Z25g5lJ-------", "service"},
		{"$V$S44zI913bBx-UJrcFSC------D", "President#44"},
	} {
		if ok, err := verifyOpenVMS(tc.record, tc.pass); err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v", tc.record, ok, err)
		}
	}
}

// Two of the three accounts have the case flag clear, which means VMS
// upper-cases the password before hashing and "user" is the same password as
// "USER". The third has it set. That difference is the whole of what the flag
// does, and it halves or does not halve the keyspace accordingly.
func TestOpenVMSCaseFlag(t *testing.T) {
	const insensitive = "$V$9AYXUd5LfDy-aj48Vj54P-----"
	for _, pass := range []string{"USER", "user", "UsEr"} {
		if ok, err := verifyOpenVMS(insensitive, pass); err != nil || !ok {
			t.Errorf("%q should verify against a case-insensitive account: ok=%v err=%v", pass, ok, err)
		}
	}
	const sensitive = "$V$S44zI913bBx-UJrcFSC------D"
	if ok, _ := verifyOpenVMS(sensitive, "PRESIDENT#44"); ok {
		t.Error("a case-sensitive account accepted the upper-cased password")
	}
}

// The username is part of the hash and is carried inside the record, packed
// three characters to a sixteen-bit word. Reading it back is the only way to
// know which account a record belongs to.
func TestOpenVMSCarriesItsUsername(t *testing.T) {
	for _, tc := range []struct{ record, user string }{
		{"$V$9AYXUd5LfDy-aj48Vj54P-----", "UCX$FTP"},
		{"$V$p1UQjRZKulr-Z25g5lJ-------", "FIELD"},
		{"$V$S44zI913bBx-UJrcFSC------D", "OBAMA"},
	} {
		r, err := openVMSFields(tc.record)
		if err != nil {
			t.Fatalf("%s: %v", tc.record, err)
		}
		if r.username != tc.user {
			t.Errorf("%s: username = %q, want %q", tc.record, r.username, tc.user)
		}
	}
}
