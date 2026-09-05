package main

import (
	"hashsmith-go/internal/hashid"
	"strings"
)

// saltedPrototypes ports the generic salted-construction, Kerberos and
// regex-single branches of the legacy cascade: detectCompatSaltedTypes
// through the 50-char arubaos branch (original lines 1978-2054). This batch
// sits near the END of the cascade, behind roughly 150 higher-precedence
// branches already in the table from batches A-G, which is why
// detectCompatSaltedTypes below is expressed as a Compute prototype AT ITS
// OWN TABLE POSITION rather than a call from detectTypesFromTable outside
// the table: the latter would run it first and silently steal matches from
// every higher-precedence entry already in the table.
func saltedPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// detectCompatSaltedTypes returns the generic hash:salt candidate list
		// for a digest of qualifying length (32/40/56/64/96/128 hex chars)
		// before the last colon. The legacy branch then PREPENDS more specific
		// app-specific candidates, in this exact order, when their own
		// predicate also holds — each successive match lands at the FRONT of
		// the list, so the precedence a user sees is the reverse of check
		// order (aes128/des group first if matched, then symfony-legacy, then
		// netwitness-sha256, then vbulletin/dcc, then redmine, then the
		// generic list). That prepend logic is copied verbatim below, in the
		// same order, because the order IS the precedence and the golden file
		// checks it.
		//
		// No fixed prefix distinguishes a bare hash:salt record from any
		// other colon-delimited pair, so TierStructural.
		{
			Display: "Salted digest construction", Tier: hashid.TierStructural, Exclusive: true,
			Compute: func(in hashid.Input) ([]string, bool) {
				t := in.Normalized
				generic := detectCompatSaltedTypes(t)
				if len(generic) == 0 {
					return nil, false
				}
				// App-specific formats share the same outer hash:salt structure.
				// Their established precedence is preserved by prepending, exactly
				// as the cascade did.
				if isRedmine(t) {
					generic = append([]string{"redmine"}, generic...)
				}
				if isVBulletin(t) {
					generic = append([]string{"vbulletin", "dcc"}, generic...)
				}
				if isNetWitnessSHA256Record(t) {
					generic = append([]string{"netwitness-sha256"}, generic...)
				}
				if fields := strings.SplitN(t, ":", 2); len(fields) == 2 && len(fields[0]) == 64 && isHex(fields[0]) {
					generic = append([]string{"symfony-legacy"}, generic...)
				}
				if isHexPair(t, 32, 32) {
					generic = append([]string{"aes128-ecb-nokdf", "aes192-ecb-nokdf", "aes256-ecb-nokdf"}, generic...)
				}
				// This isHexPair(t, 16, 16) prepend is dead code, inherited
				// verbatim from the legacy cascade: detectCompatSaltedTypes only
				// returns non-nil when compatSaltedHashParts finds a digest
				// (everything up to the LAST colon) of length 32, 40, 56, 64, 96
				// or 128 — and compatSaltedHashParts itself already requires that
				// digest to be all-hex, so a colon inside it would have failed
				// the isHex check. That means whenever `generic` is non-empty, t
				// contains EXACTLY one colon, and isHexPair's own split on that
				// same colon can only agree with compatSaltedHashParts's split.
				// So isHexPair(t, 16, 16) would need the digest to be 16 hex
				// chars long, but 16 is not in {32,40,56,64,96,128} — the two
				// requirements can never both hold. Kept for cascade fidelity;
				// see TestTableCoverageBatchH's comment for the same conclusion
				// from the test side.
				if isHexPair(t, 16, 16) {
					generic = append([]string{"des-plaintext", "3des-plaintext"}, generic...)
				}
				return generic, true
			},
			Prevalence: 35, Rationale: "a bare hash:salt pair of a qualifying digest length is the generic shape several concrete apps build on (Redmine, vBulletin); with no app-specific marker present there is no basis for attributing it to one of those apps instead of a plain construction, and no corpus data distinguishes the base rate of an unmarked pair from a marked one",
		},
		// krb5asrep is nested: a record additionally prefixed "$23$" (RC4)
		// selects the etype-23 candidate pair; any other "$krb5asrep$" record
		// gets only the general type. Both are plain literal-prefix checks, so
		// TierSignature; the more specific "$23$" form is listed first so
		// table order reproduces the nested precedence.
		hasPrefixProto("$krb5asrep$23$", "Kerberos 5 AS-REP (etype 23, RC4)", 30,
			"AS-REP roasting via Impacket GetNPUsers/Rubeus requests RC4 (etype 23) by default against accounts with Kerberos pre-authentication disabled, making this the most commonly captured AS-REP shape", "krb5asrep", "krb5asrep-nt"),
		hasPrefixProto("$krb5asrep$", "Kerberos 5 AS-REP (other etype)", 8,
			"an AES-encrypted (etype 17/18) AS-REP only appears once RC4 has been disabled domain-wide, a hardening step most Active Directory environments have not yet applied", "krb5asrep"),
		// krb5tgs is nested the same way: "$23$" selects the etype-23
		// (Kerberoastable) candidate pair, any other "$krb5tgs$" record gets
		// only the general type.
		hasPrefixProto("$krb5tgs$23$", "Kerberos 5 TGS-REP (etype 23, RC4)", 30,
			"Kerberoasting via Rubeus/Impacket GetUserSPNs requests RC4 (etype 23) service tickets by default against unhardened AD, making this the most commonly captured Kerberoast shape", "krb5tgs", "krb5tgs-nt"),
		hasPrefixProto("$krb5tgs$", "Kerberos 5 TGS-REP (other etype)", 8,
			"an AES-encrypted (etype 17/18) service ticket only appears once RC4 has been disabled for the target SPN's service account, a minority of AD environments today", "krb5tgs"),
		hasPrefixProto("$krb5pa$", "Kerberos 5 pre-authentication", 6,
			"$krb5pa$ pre-authentication hashes require an active network capture of the AS-REQ exchange rather than an LDAP/DCSync-style offline dump, a narrower collection scenario than AS-REP or Kerberoast hashes above", "krb5pa"),
		// isNetNTLMLine has no fixed prefix — it only checks a 6-field colon
		// split, an empty second field, and hex composition of the last three
		// fields — so TierStructural. It always returns both types in this
		// fixed order (v2 before v1), so a plain predicateProto with two
		// Types suffices; there is no conditional output to express with
		// Compute.
		predicateProto(isNetNTLMLine, "NetNTLM captured challenge/response", hashid.TierStructural,
			"user::domain:hex:hex:hex — 6 colon-delimited fields with an empty second field and the last three hex",
			25, "NetNTLM captures from Responder/relay tooling remain a routine finding in internal network penetration tests, with NetNTLMv2 the modern default most current Windows clients negotiate", "netntlmv2", "netntlmv1"),
		// reBcrypt, reArgon2, reScrypt, rePostgres and reMySQL41 are compiled
		// regexps rather than predicate functions, but a *regexp.Regexp's
		// MatchString method already has the func(string) bool shape
		// predicateProto wants, so each is wrapped directly.
		//
		// reBcrypt (`^\$2[aby]\$\d{2}\$`) anchors on a literal $2a$/$2b$/$2y$
		// scheme tag, so TierSignature.
		predicateProto(reBcrypt.MatchString, "bcrypt", hashid.TierSignature,
			`record prefix $2a$, $2b$ or $2y$ followed by a 2-digit cost`,
			40, "bcrypt is a widely adopted password-storage default across modern web frameworks (Rails, Laravel, Django's bcrypt backend), giving it broad real-world exposure", "bcrypt"),
		// reArgon2 (`^\$argon2(i|d|id)\$`) anchors on a literal $argon2i$/
		// $argon2d$/$argon2id$ scheme tag, so TierSignature.
		predicateProto(reArgon2.MatchString, "Argon2", hashid.TierSignature,
			`record prefix $argon2i$, $argon2d$ or $argon2id$`,
			25, "Argon2 is the Password Hashing Competition winner and OWASP's current recommended default, increasingly seen in newer applications though not yet as ubiquitous as bcrypt", "argon2"),
		// reScrypt (`(?i)^scrypt(?:\$|:)`) anchors on the literal word
		// "scrypt" (case-insensitive) followed by a $ or :, so TierSignature.
		predicateProto(reScrypt.MatchString, "scrypt", hashid.TierSignature,
			`record prefix "scrypt" (case-insensitive) followed by $ or :`,
			12, "scrypt sees real but narrower adoption than bcrypt/argon2, mostly in cryptocurrency wallets and a handful of frameworks that pre-date Argon2's standardization", "scrypt"),
		// rePostgres (`^md5[0-9a-fA-F]{32}$`) anchors on the literal 3-letter
		// word "md5" — a real, distinctive marker, the same reasoning that
		// made "AK1" (batchF's fortigate) and "0xc007" (batchG's Sybase ASE)
		// TierSignature rather than TierStructural — so TierSignature, not
		// merely a shape check.
		predicateProto(rePostgres.MatchString, "PostgreSQL md5 password", hashid.TierSignature,
			"record prefix md5 followed by 32 hex chars",
			15, "PostgreSQL's md5-prefixed pg_shadow/pg_authid hash remains the default credential format on any Postgres instance that hasn't opted into the newer SCRAM-SHA-256 authentication method", "postgres"),
		// reMySQL41 (`^\*[0-9a-fA-F]{40}$`) anchors on a single leading "*".
		// Unlike md5's 3-letter word above, a lone asterisk is not a
		// distinctive marker — it is pure punctuation reused as a field
		// delimiter throughout this codebase (vbulletin, mysql8's $mysql$A$,
		// countless others) — so its evidentiary weight is no better than
		// batchF's citrix ("49-char record starting with '1'"), which the
		// same reasoning kept at TierStructural. The real signal here is the
		// shape (a lone punctuation char plus 40 hex chars), so TierStructural.
		predicateProto(reMySQL41.MatchString, "MySQL 4.1+ (mysql_native_password)", hashid.TierStructural,
			"record prefix * (a single punctuation marker, not a distinctive word) followed by 40 hex chars",
			10, "the MySQL 4.1+ *SHA1(SHA1(pass)) hash is still what mysql.user stores under the mysql_native_password plugin, which remains widely deployed despite MySQL 8's caching_sha2_password default", "mysql41"),
		// The legacy cascade's nested 0x0200 check was dead code: reMSSQLNew
		// (`(?i)^0x0100[0-9a-fA-F]{48}$`) anchors on the literal digits
		// "0x0100" — digits are unaffected by the (?i) case-fold, which only
		// touches a-f — so no string reMSSQLNew matches could ever also start
		// "0x0200". That left mssql2012 (SQL Server 2012+, a 0x0200-tagged,
		// 4-byte-salt + 64-byte-SHA512 record, 142 chars total: "0x0200" plus
		// 136 hex chars) undetectable by auto-detection even though hashing
		// and verification for it were correct. Task 15 is the one task
		// allowed to change detection, so this is a real, separately anchored
		// matcher rather than a repaired version of the old nested check —
		// reMSSQL2012 (`(?i)^0x0200[0-9a-fA-F]{136}$`) has its own literal
		// prefix and fixed length, so TierSignature, matching reMSSQLNew's own
		// reasoning below.
		{
			Types: []string{"mssql2012"}, Display: "SQL Server 2012+ password hash",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if reMSSQL2012.MatchString(in.Normalized) {
					return "record prefix 0x0200 (case-insensitive) with a fixed 142-char total length", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "0x0200-tagged SQL Server 2012+ password hashes are what current SQL Server master..sys.sql_logins dumps and password-audit tooling produce",
		},
		// reMSSQLNew anchors on the literal "0x0100" prefix plus a fixed
		// 54-char total length, so TierSignature, matching batchG's Sybase ASE
		// ("0xc007" prefix plus fixed length) reasoning. It cannot collide
		// with reMSSQL2012 above (disjoint literal prefixes), so unlike the
		// legacy cascade this branch no longer needs to exclude "0x0200"
		// itself.
		{
			Types: []string{"mssql2005"}, Display: "SQL Server 2000/2005 password hash",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if reMSSQLNew.MatchString(in.Normalized) {
					return "record prefix 0x0100 (case-insensitive) with a fixed 54-char total length", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "0x0100-tagged SQL Server 2000/2005 password hashes still turn up in old MSSQL master..sysxlogins dumps and password-audit tooling that hasn't been retired",
		},
		// looksLikeDescrypt checks only an exact length (13) and uniform
		// membership in the crypt-64 alphabet, nothing else — no sub-field
		// split, no distinguished marker character, no exclusion of a
		// narrower alphabet the way cisco-pix below additionally excludes
		// hex. That is genuinely "length and alphabet only, nothing more", so
		// TierShape rather than TierStructural.
		predicateProto(looksLikeDescrypt, "Traditional DES crypt(3)", hashid.TierShape,
			"exactly 13 chars, all from the crypt-64 alphabet",
			15, "the original 13-char DES crypt(3) hash still appears in legacy Unix and embedded-device shadow files that predate the MD5/SHA2/yescrypt crypt schemes", "descrypt"),
		// Compound: an exact length (16) AND isPixToken (crypt-64 alphabet)
		// AND NOT isHex. The added exclusion of the hex subset is a second,
		// different alphabet fact beyond plain "length + alphabet" — the same
		// reasoning that kept batchA's isHMailServer (hex/non-hex composition
		// of two halves) at TierStructural rather than the weaker TierShape —
		// so TierStructural, unlike looksLikeDescrypt/isDahuaAuthToken, which
		// check only one alphabet with no exclusion.
		{
			Types: []string{"cisco-pix"}, Display: "Cisco PIX MD5",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				t := in.Normalized
				if len(t) == 16 && isPixToken(t) && !isHex(t) {
					return "exactly 16 chars, all from the crypt-64 alphabet, and not purely hex (which would instead be an ambiguous mysql323/cisco-pix/half-md5 candidate)", true
				}
				return "", false
			},
			Prevalence: 10, Rationale: "Cisco PIX's original MD5-based enable/user secret is a narrower target than its ASA successor (batchG's cisco-asa), appearing mainly in decommissioned or unmigrated PIX device configs",
		},
		// isDahuaAuthToken checks only an exact length (8) and uniform
		// membership in the Dahua alphabet, nothing else — the same "length
		// and alphabet only" shape as looksLikeDescrypt above, so TierShape.
		predicateProto(isDahuaAuthToken, "Dahua/Besder IP camera auth token", hashid.TierShape,
			"exactly 8 chars, all from the Dahua digest alphabet (0-9, A-Z, a-z)",
			6, "Dahua/Besder IP camera 8-char auth tokens are specific to one IoT camera vendor family, a narrow niche compared to general-purpose OS or web-application credential stores", "dahua-auth-md5", "besder-auth-md5"),
		// Compound: an exact length (50) AND a case-insensitive 2-char
		// comparison at a fixed offset (t[8:10] == "01"). The legacy branch
		// only reached this check after an earlier `if !isHex(t) { return nil
		// }` guard (which sat immediately ahead of the switch len(t) shape
		// fallback, now shapePrototypes() in prototypes_shape.go), so an
		// isHex(t) check is added here to reproduce that precondition
		// faithfully for this now-standalone table entry. The 2-char literal
		// at a fixed offset is an embedded marker, but a much shorter and weaker one
		// than batchG's Juniper (6 position-pinned literal chars) or SAP
		// RFC_READ_TABLE (20-char literal zero-padding) entries, which earned
		// TierSignature — it is closer in strength to batchF's citrix (a
		// single literal leading char), which stayed TierStructural. So
		// TierStructural.
		{
			Types: []string{"arubaos"}, Display: "ArubaOS local-manager hash",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				t := in.Normalized
				if len(t) == 50 && isHex(t) && strings.EqualFold(t[8:10], "01") {
					return "exactly 50 hex chars, with chars 9-10 equal to \"01\" (case-insensitive)", true
				}
				return "", false
			},
			Prevalence: 5, Rationale: "ArubaOS's local-manager hash is specific to one enterprise WLAN vendor's controller product line, a narrow slice of network-device forensic casework",
		},
	}
}
