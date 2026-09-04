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
		{"dnssec-nsec3", "pi6a89u8tca930h8mvolklmesefc5gmn:.fnmlbsik.net:35537886:1", []string{"dnssec-nsec3"}},
		{"sha1crypt", "$sha1$64000$sfUsIAcX$k17MgwsyBQlYlr8bXCEuXkQmn5Rc", []string{"sha1crypt"}},
		{"md5crypt", "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/", []string{"md5crypt"}},
		{"apr1", "$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", []string{"apr1"}},
		{"sha256crypt", "$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", []string{"sha256crypt"}},
		{"sha512crypt", "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", []string{"sha512crypt"}},
		{"blake2", "$BLAKE2$2b51353016a512b60e587bea98d799c2de243468085ca6cd67f983b2e55bfb67:2353288289", []string{"blake2b256-pass-salt", "blake2b256-salt-pass"}},
		{"hmailserver", "aB3xY9f7e20052c00664fe2b773123e52b8cdd393bcb09518b63ea390fe30eefa11688", []string{"hmailserver"}},
		{"pwsafe", "$pwsafe$*3*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*2048*6f2ad9b3cebdaa86a663f2a202b3d0b00e471ce104995ee07255e2d3edb31a37", []string{"pwsafe"}},
		{"pfx", "$pfx$*sha1*2048*005070587dcdb26f1bf120f0e0889794*930ba72f5f6cfe1982771f3ac4f31cc2c3038319*3082098e308203fa06092a864886f70d010706", []string{"pfx"}},
		{"episerver", "$episerver$*0*MjEwNDE5NzcyNg==*aKdKfczl/7l2BtCK8vtVQ0sZoMQ=", []string{"episerver"}},
		{"azuresync", "v1;PPH1_MD4,10920c8b4d1f2a3b,100,112751a58105737a61461ec5c0ea567c068b154e5e89e723b1f2b80997557f16", []string{"azuresync"}},
		{"siphash", "033631dbbb8abefa:2:4:000102030405060708090a0b0c0d0e0f", []string{"siphash"}},
		{"crc32 pair", "c762de4a:00000000", []string{"crc32-hashcat", "crc32c-hashcat", "murmurhash", "murmur3-seeded", "skip32"}},
		{"64-bit pair", "1234567890abcdef:fedcba0987654321", []string{"murmur64a", "crc64-jones"}},
	})
}
