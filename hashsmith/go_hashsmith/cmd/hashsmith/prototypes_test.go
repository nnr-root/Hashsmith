package main

import (
	"reflect"
	"testing"
)

// tableCoverageCase asserts a branch is served by the PROTOTYPE TABLE, not by
// the legacy cascade fall-through. Without this, a broken port would silently
// fall through, the golden test would stay green, and the bug would ship.
type tableCoverageCase struct {
	name  string
	input string
	want  []string
}

func runTableCoverage(t *testing.T, cases []tableCoverageCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, served := detectTypesFromTable(tc.input)
			if !served {
				t.Fatalf("%q was not matched by the prototype table (it fell through to the legacy cascade)", tc.input)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("types = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTableCoverageBatchA(t *testing.T) {
	runTableCoverage(t, []tableCoverageCase{
		{"sha1crypt", "$sha1$64000$sfUsIAcX$k17MgwsyBQlYlr8bXCEuXkQmn5Rc", []string{"sha1crypt"}},
		{"md5crypt", "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/", []string{"md5crypt"}},
		{"apr1", "$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", []string{"apr1"}},
		{"sha256crypt", "$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", []string{"sha256crypt"}},
		{"sha512crypt", "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", []string{"sha512crypt"}},
		{"crc32 pair", "c762de4a:00000000", []string{"crc32-hashcat", "crc32c-hashcat", "murmurhash", "murmur3-seeded", "skip32"}},
		{"64-bit pair", "1234567890abcdef:fedcba0987654321", []string{"murmur64a", "crc64-jones"}},
	})
}
