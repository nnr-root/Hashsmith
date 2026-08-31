//go:build slowtest

package main

import "testing"

// The slow half of the TestHashcatCryptHeaderPublishedVectors split:
// verifyCandidate at production iteration counts. See
// crack_hashcat_crypt_headers_test.go for the fast mode-alias assertion
// (TestHashcatCryptHeaderAliases) that remains in the default suite, and for
// the shared hashcatCryptHeaderPublishedCases table.
func TestHashcatCryptHeaderPublishedVectors(t *testing.T) {
	for _, tc := range hashcatCryptHeaderPublishedCases {
		t.Run(tc.mode, func(t *testing.T) {
			ok, err := verifyCandidate(tc.password, tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("published vector: ok=%v err=%v", ok, err)
			}
		})
	}
}
