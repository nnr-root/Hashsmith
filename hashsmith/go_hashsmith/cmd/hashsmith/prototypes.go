package main

import (
	"hashsmith-go/internal/hashid"
	"strings"
	"sync"
)

// The prototype table is Hashsmith's single detection vocabulary. Both
// `identify` and `crack` read it, which is what makes it impossible for them
// to disagree about what a hash is.
//
// TABLE ORDER IS LOAD-BEARING. It reproduces the precedence of the cascade it
// replaces: the first Exclusive match wins outright and suppresses the rest.
// Reordering entries changes which type crack tries first. testdata/
// detect_golden.txt is the guard on that; do not regenerate it to make a
// reordering pass.
//
// Prototypes live here rather than in internal/hashid because their Match
// functions close over predicates like isPwsafe and isLDAP, which belong
// beside their own formats' cracking code in crack_pwsafe.go and crack_ldap.go.

var (
	prototypeTableOnce sync.Once
	prototypeTableVal  []hashid.Prototype
)

func prototypeTable() []hashid.Prototype {
	prototypeTableOnce.Do(func() {
		prototypeTableVal = append(prototypeTableVal, batchAPrototypes()...)
		prototypeTableVal = append(prototypeTableVal, batchBPrototypes()...)
		prototypeTableVal = append(prototypeTableVal, batchCPrototypes()...)
		prototypeTableVal = append(prototypeTableVal, batchDPrototypes()...)
		prototypeTableVal = append(prototypeTableVal, batchEPrototypes()...)
	})
	return prototypeTableVal
}

// hasPrefixProto builds the commonest prototype shape: an unambiguous record
// prefix that identifies exactly one format.
func hasPrefixProto(prefix, display string, prevalence uint8, rationale string, types ...string) hashid.Prototype {
	return hashid.Prototype{
		Types: types, Display: display, Tier: hashid.TierSignature, Exclusive: true,
		Match: func(in hashid.Input) (hashid.Evidence, bool) {
			if strings.HasPrefix(in.Normalized, prefix) {
				return hashid.Evidence("record prefix " + prefix), true
			}
			return "", false
		},
		Prevalence: prevalence, Rationale: rationale,
	}
}

// predicateProto wraps an existing boolean predicate as an exclusive signature.
// tier must reflect what the predicate actually verifies: a full parse behind
// a fixed prefix is TierSignature, but a predicate that only checks length and
// character composition (no fixed prefix) is no stronger than TierStructural —
// hardcoding TierSignature for every predicate would overstate confidence for
// the latter kind.
func predicateProto(fn func(string) bool, display string, tier hashid.Tier, evidence string, prevalence uint8, rationale string, types ...string) hashid.Prototype {
	return hashid.Prototype{
		Types: types, Display: display, Tier: tier, Exclusive: true,
		Match: func(in hashid.Input) (hashid.Evidence, bool) {
			if fn(in.Normalized) {
				return hashid.Evidence(evidence), true
			}
			return "", false
		},
		Prevalence: prevalence, Rationale: rationale,
	}
}

func batchAPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// NSEC3 is checked against the RAW input, before shadow-line peeling,
		// because its colon-delimited domain can itself look like a 13-char
		// DES crypt token. This ordering is why hashid.Input carries both Raw
		// and Normalized.
		{
			Types: []string{"dnssec-nsec3"}, Display: "DNSSEC NSEC3",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isNSEC3Record(in.Raw) {
					return "complete NSEC3 record", true
				}
				return "", false
			},
			Prevalence: 20, Rationale: "narrow DNSSEC use; rare outside zone-walking work",
		},
		hasPrefixProto("$sha1$", "sha1crypt", 25, "NetBSD crypt(3); uncommon outside BSD systems", "sha1crypt"),
		hasPrefixProto("$1$", "md5crypt", 60, "the historic Unix crypt default; still widespread on legacy systems", "md5crypt"),
		hasPrefixProto("$apr1$", "Apache apr1", 45, "the Apache htpasswd default before bcrypt", "apr1"),
		hasPrefixProto("$5$", "sha256crypt", 55, "common on Linux distributions that predate the yescrypt default", "sha256crypt"),
		hasPrefixProto("$6$", "sha512crypt", 80, "the default /etc/shadow scheme on most Linux distributions", "sha512crypt"),
		{
			Display: "BLAKE2 family", Tier: hashid.TierSignature, Exclusive: true,
			Compute: func(in hashid.Input) ([]string, bool) {
				types := detectBlake2HashcatTypes(in.Normalized)
				return types, len(types) > 0
			},
			Prevalence: 20, Rationale: "BLAKE2 is rare as a password digest outside specific applications",
		},
		// isHMailServer has no fixed prefix — it only checks overall length plus
		// hex/non-hex composition of the two halves — so it is TierStructural,
		// not the TierSignature a record prefix would earn.
		predicateProto(isHMailServer, "hMailServer", hashid.TierStructural, "70-char record with a non-hex 6-char salt followed by a hex digest", 10, "single-product format; rare in the wild", "hmailserver"),
		// isPwsafe fully parses the $pwsafe$* record (prefix, version, salt,
		// iteration count, digest all validated), so a match is TierSignature.
		predicateProto(isPwsafe, "Password Safe v3", hashid.TierSignature, "parses as a Password Safe v3 hash", 20, "desktop password manager; appears in forensic work", "pwsafe"),
		// isPKCS12 fully parses the $pfx$* record (prefix, algorithm, iteration
		// count, salt, MAC and data all validated), so TierSignature.
		predicateProto(isPKCS12, "PKCS#12 keystore", hashid.TierSignature, "parses as a PKCS#12 keystore hash", 35, "common wherever TLS client certificates are issued", "pfx"),
		// isEpiserver fully parses the $episerver$* record (prefix, version,
		// salt, digest all validated), so TierSignature.
		predicateProto(isEpiserver, "EPiServer", hashid.TierSignature, "parses as an EPiServer password hash", 10, "single-CMS format", "episerver"),
		// isAzureSync checks the "v1;PPH1_MD4," prefix plus decodes salt,
		// iteration count and digest, so TierSignature.
		predicateProto(isAzureSync, "Azure AD Connect sync", hashid.TierSignature, "parses as an Azure AD Connect sync hash", 15, "narrow to hybrid-AD deployments", "azuresync"),
		// isSipHash has no fixed prefix — it only checks field count, the
		// 16-char hex tag length and hex composition — so TierStructural.
		predicateProto(isSipHash, "SipHash", hashid.TierStructural, "16-char hex tag field and hex key field, colon-delimited", 15, "a MAC, not a password hash; seldom a cracking target", "siphash"),
		{
			Types:   []string{"crc32-hashcat", "crc32c-hashcat", "murmurhash", "murmur3-seeded", "skip32"},
			Display: "32-bit checksum with seed", Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isHexPair(in.Normalized, 8, 8) {
					return "two 8-char hex fields", true
				}
				return "", false
			},
			Prevalence: 20, Rationale: "checksums, not password hashes; the group is inherently ambiguous",
		},
		{
			Types:   []string{"murmur64a", "crc64-jones"},
			Display: "64-bit checksum with seed", Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isHexPair(in.Normalized, 16, 16) {
					return "two 16-char hex fields", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "checksums, not password hashes",
		},
	}
}

// detectTypesFromTable runs the prototype table only. The bool reports whether
// the table served the input, which is what the per-batch coverage tests
// assert; without it a broken port would silently fall through to the legacy
// cascade and the golden test would still pass.
func detectTypesFromTable(text string) ([]string, bool) {
	in := hashid.Input{Raw: strings.TrimSpace(text)}
	in.Normalized = stripShadowUsername(in.Raw)
	types := hashid.DetectTypes(prototypeTable(), in)
	return types, len(types) > 0
}
