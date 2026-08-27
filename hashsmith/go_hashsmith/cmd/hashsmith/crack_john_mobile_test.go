package main

import "testing"

func TestJohnMobilePublishedVectors(t *testing.T) {
	tests := []struct {
		typ, password, target string
	}{
		{"signal", "openwall", signalPublishedRecord},
		{"macos-keychain", "password", keychainPublishedRecord},
		{"telegram-desktop", "openwall123", telegramDesktopPublishedRecord},
	}
	for _, tc := range tests {
		t.Run(tc.typ, func(t *testing.T) {
			ok, err := verifyCandidate(tc.password, tc.target, tc.typ, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong-password", tc.target, tc.typ, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong-password rejection: ok=%v err=%v", bad, err)
			}
			if got := detectHashTypes(tc.target); len(got) != 1 || got[0] != tc.typ {
				t.Fatalf("detection=%v, want [%s]", got, tc.typ)
			}
		})
	}
}
