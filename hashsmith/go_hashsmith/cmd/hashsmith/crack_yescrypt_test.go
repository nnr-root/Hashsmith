package main

import (
	"strings"
	"testing"
)

// TestYescryptIsTheShadowDefault covers the scheme every current Linux
// distribution writes into /etc/shadow, which this tool used to have to
// report as unsupported.
func TestYescryptIsTheShadowDefault(t *testing.T) {
	// yescrypt's own published vector.
	const record = "$y$j9T$e8R9q85ZuzUkArEUurdtS.$esON.7y6H.u3UCPVCpbRFueRpAut2n2cMf1EhpjbuiC"
	if types := detectHashTypes(record); !containsString(types, "yescrypt") {
		t.Errorf("detectHashTypes did not offer yescrypt: %v", types)
	}
	if ok, err := verifyYescrypt(record, "pleaseletmein"); err != nil || !ok {
		t.Errorf("rejected the right password: ok=%v err=%v", ok, err)
	}
	for _, wrong := range []string{"pleaseletmei", "pleaseletmeinn", "", "PLEASELETMEIN"} {
		if bad, _ := verifyYescrypt(record, wrong); bad {
			t.Errorf("accepted %q", wrong)
		}
	}

	// gost-yescrypt is a different hash — Streebog where yescrypt uses
	// SHA-256 — so it must be refused rather than read as this one.
	if _, err := verifyYescrypt("$gy$j9T$e8R9q85ZuzUkArEUurdtS.$esON.7y6H.u3UCPVCpbRFueRpAut2n2cMf1EhpjbuiC", "x"); err == nil {
		t.Error("read a gost-yescrypt record as yescrypt")
	}
	if isYescrypt("$gy$j9T$abc$def") {
		t.Error("claimed a gost-yescrypt record")
	}

	// A record missing a field is not one.
	for _, bad := range []string{"$y$j9T$e8R9q85ZuzUkArEUurdtS.", "$y$j9T$$x", "$y$", "$6$abc$def"} {
		if isYescrypt(bad) {
			t.Errorf("%q: claimed", bad)
		}
	}
}

// TestShadowReaderNoLongerCallsThemUnsupported pins the other half of the
// change: the shadow reader classified yescrypt and scrypt lines as
// unsupported, which for yescrypt meant telling the user their entire
// /etc/shadow was unreadable.
func TestShadowReaderNoLongerCallsThemUnsupported(t *testing.T) {
	for _, tc := range []struct{ hash, wantLabel string }{
		{"$y$j9T$e8R9q85ZuzUkArEUurdtS.$esON.7y6H.u3UCPVCpbRFueRpAut2n2cMf1EhpjbuiC", "yescrypt"},
		{"$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D", "scrypt"},
	} {
		label, crackable, recognised := classifyCryptHash(tc.hash)
		if !recognised {
			t.Errorf("%s: not recognised at all", tc.wantLabel)
		}
		if !crackable {
			t.Errorf("%s: still reported as not crackable", tc.wantLabel)
		}
		if !strings.Contains(label, tc.wantLabel) || strings.Contains(label, "unsupported") {
			t.Errorf("label = %q, want it to name %s and not say unsupported", label, tc.wantLabel)
		}
	}
	// gost-yescrypt is still honestly unsupported.
	if _, crackable, _ := classifyCryptHash("$gy$j9T$abc$def"); crackable {
		t.Error("gost-yescrypt is reported as crackable")
	}
}
