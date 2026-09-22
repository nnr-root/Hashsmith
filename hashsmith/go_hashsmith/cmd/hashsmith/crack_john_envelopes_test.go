package main

import (
	"strings"
	"testing"
)

// TestJohnDynamicEnvelopes runs each of John's named records through the
// expression its number spells, against John's own test vector.
func TestJohnDynamicEnvelopes(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"eigrp", "eigrp $eigrp$"},
		{"ipb2", "ipb2 $ipb2$"},
		{"net-md5", "net-md5 $netmd5$"},
		{"net-sha1", "net-sha1 $netsha1$"},
		{"osc", "osc $osc$"},
		{"tcp-md5", "tcp-md5 $tcpmd5$"},
		{"wbb3", "wbb3 $wbb3$"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.typ, tc.typ, types)
		}
		if ok, err := verifyJohnDynamicEnvelope(tc.typ, record, pass); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.typ, ok, err)
		}
		if bad, _ := verifyJohnDynamicEnvelope(tc.typ, record, pass+"x"); bad {
			t.Errorf("%s: accepted a wrong password", tc.typ)
		}
		// One record must not be read as another's format.
		for _, other := range johnDynamicEnvelopeOrder() {
			if other == tc.typ {
				continue
			}
			if _, _, err := readJohnDynamicEnvelope(other, record); err == nil {
				t.Errorf("%s: also read as %s", tc.typ, other)
			}
		}
	}
}

// TestJohnDynamicEnvelopeVariants pins what these readers refuse. The routing
// formats in particular carry an algorithm field, and a record naming an
// algorithm Hashsmith does not run must be refused rather than answered with
// the one it does.
func TestJohnDynamicEnvelopeVariants(t *testing.T) {
	record, pass := johnVector(t, "eigrp $eigrp$")
	f := strings.Split(record, "$")
	// $eigrp$<algorithm>$<packet>$<extra salt flag>$<extra salt>$<digest>
	f[2] = "3" // HMAC-SHA-256 rather than MD5
	if _, err := verifyJohnDynamicEnvelope("eigrp", strings.Join(f, "$"), pass); err == nil {
		t.Error("answered an EIGRP record naming an algorithm it does not run")
	}
	f[2] = "2"
	f[4] = "1" // an extra salt is appended to the password
	if _, err := verifyJohnDynamicEnvelope("eigrp", strings.Join(f, "$"), pass); err == nil {
		t.Error("answered an EIGRP record carrying an extra salt it ignores")
	}
	// A truncated record is refused rather than read short.
	if _, err := verifyJohnDynamicEnvelope("ipb2", "$IPB2$2e75504633", pass); err == nil {
		t.Error("answered a record missing its digest")
	}
	// A digest that is not hex is not a digest.
	if _, err := verifyJohnDynamicEnvelope("osc", "$OSC$2020$not-a-digest-at-all-no", pass); err == nil {
		t.Error("answered a record whose digest is not hex")
	}
}

// TestJohnBareDigestWrappers covers the envelopes that carry nothing but a
// digest, where the envelope is the only thing naming the algorithm.
func TestJohnBareDigestWrappers(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"ntlm", "NT $nt$"},
		{"keccak512", "Raw-Keccak $keccak$"},
		{"radmin2", "RAdmin $radmin2$"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.typ, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.typ, ok, err)
		}
		if bad, _ := verifyCandidate(pass+"x", record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.typ)
		}
	}
}
