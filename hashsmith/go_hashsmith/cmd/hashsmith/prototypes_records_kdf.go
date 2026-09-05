package main

import (
	"hashsmith-go/internal/hashid"
)

// kdfPrototypes ports the KDF, directory and enterprise-predicate branches
// of the legacy cascade: isGenericPBKDF2 through the bare parseOracleH guard
// (original lines 1470-1548), stopping immediately before
// detectCompatSaltedTypes. This batch is almost entirely named predicates
// rather than literal prefixes, which makes tier selection — not the Match
// logic — the dominant judgement call; every entry below is commented with
// what the underlying predicate actually verifies and why that earns the
// tier it gets.
//
// isCiscoASA is nested in the legacy cascade (it always yields cisco-asa,
// and additionally appends oracle-h when parseOracleH also succeeds against
// the same record), so it becomes one Compute prototype reproducing that
// conditional append exactly, rather than two Types prototypes as the
// $vbox$/$ethereum$/phpass nested branches in earlier batches did — returning
// both types unconditionally would be a behaviour change the golden file
// would catch. The bare parseOracleH guard at the end of this range is a
// separate, later branch in the cascade (not the O$-specific one from
// batchD) and is ported in its own right at its own position, even though it
// can never win a table evaluation — see its comment below.
func kdfPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// isGenericPBKDF2 splits on ":" into exactly 4 fields, requires
		// field 0 to name a known hash algorithm (md5/sha1/sha224/sha256/
		// sha384/sha512), field 1 to parse as an in-range iteration count,
		// and fields 2/3 to be valid, size-bounded base64. Field count,
		// lengths and encodings all agree, but there is no fixed literal
		// prefix distinguishing this generic algo:iter:salt:dk shape from
		// any other 4-field colon record with a hash-algorithm-shaped first
		// field — the same reasoning that makes isTOTPRecord and
		// isOnePassword below TierStructural rather than TierSignature.
		predicateProto(isGenericPBKDF2, "Generic PBKDF2 (algo:iter:salt:dk)", hashid.TierStructural,
			"colon-delimited record with exactly 4 fields: a known hash-algorithm name (md5, sha1, sha224, sha256, sha384 or sha512), an in-range iteration count, and base64 salt and digest fields",
			15, "the generic algo:iter:salt:dk shape is Hashcat/John's fallback PBKDF2 export format for ad-hoc and custom applications rather than one product's default, giving it broad but shallow real-world exposure", "pbkdf2"),
		// isPasslibPBKDF2 requires the record to start with "$" (parts[0]
		// == ""), the second field to be the literal identifier pbkdf2 or
		// pbkdf2-sha1/sha256/sha512, then decodes rounds and Passlib-base64
		// salt/digest fields with the digest length pinned to the named
		// hash's output size. A literal identifier plus decoded fields, so
		// TierSignature.
		predicateProto(isPasslibPBKDF2, "Passlib PBKDF2", hashid.TierSignature,
			"$-delimited record whose second field is the literal identifier pbkdf2 or pbkdf2-sha1/sha256/sha512, followed by a round count and base64 salt/digest fields, with the digest decoding to exactly the named hash's output size",
			12, "Passlib's pbkdf2_sha1/256/512 hashers are a common opt-in choice for Flask and other lightweight Python web apps that don't default to Django's own hasher, but Django's own password hasher (below) remains the more common Python-framework password store", "passlib-pbkdf2"),
		// isWerkzeug splits on "$" into exactly 3 parts, then requires the
		// method field to start with the literal keyword "pbkdf2:" or
		// "scrypt:" (via a colon-split switch with no default case), and
		// decodes rounds/N/r/p and a hex digest whose length matches the
		// named digest or scrypt output size. A literal keyword plus
		// decoded fields, so TierSignature.
		predicateProto(isWerkzeug, "Werkzeug password hash", hashid.TierSignature,
			"record of the form <method>$<salt>$<hex digest>, where method begins with the literal keyword pbkdf2: or scrypt: followed by its parameters, and the hex digest's length matches the named digest or scrypt output size",
			20, "Werkzeug's generate_password_hash() (pbkdf2 by default, scrypt optionally) is the password hasher built into Flask, so it recurs in any Flask application that hasn't swapped in its own hashing library", "werkzeug"),
		// isASPNetIdentity base64-decodes the whole record, then switches on
		// the first decoded byte: 0 selects a fixed 49-byte v2 payload, 1
		// selects a variable-length v3 payload with its own iteration/salt-
		// length/digest-length range checks. That leading byte is a
		// 1-byte binary marker with only two valid values, not a multi-char
		// literal prefix — the same weak-discriminator situation as
		// isCitrix's single leading '1' char and citrix-sha512's single
		// leading '2' char elsewhere in this table, both TierStructural —
		// so this is TierStructural too, despite the otherwise full field
		// parse.
		predicateProto(isASPNetIdentity, "ASP.NET Identity", hashid.TierStructural,
			"base64-decoded payload beginning with a 1-byte format-version marker (0 for the fixed 49-byte v2 layout, 1 for the variable-length v3 layout), followed by iteration-count, salt-length and digest fields whose sizes and ranges all validate",
			20, "ASP.NET Identity is the default membership/password subsystem for ASP.NET Core and legacy ASP.NET MVC applications, so this format recurs wherever a Microsoft-stack web application's user database is extracted", "aspnet-identity"),
		// isGRUB2 splits on "." into exactly 6 parts and requires the
		// literal markers "grub", "pbkdf2" and "sha512" as the first three,
		// then decodes an iteration count and hex salt/digest fields.
		// Three literal markers plus decoded fields, so TierSignature.
		predicateProto(isGRUB2, "GRUB2 PBKDF2-SHA512", hashid.TierSignature,
			"dot-delimited record with the literal markers grub, pbkdf2 and sha512 as its first three fields, followed by an iteration count and hex salt/digest fields",
			6, "a GRUB2 boot-password hash only exists when an administrator has explicitly enabled password protection on the bootloader, an optional hardening step most Linux installs leave off", "grub2"),
		// isOnePassword splits on ":" into exactly 3 fields: a numeric
		// iteration count, a 16-char hex salt, and a hex data field whose
		// length is a multiple of 32. No fixed prefix distinguishes this
		// generic iter:salt:data shape from any other 3-field colon record,
		// so TierStructural — the same reasoning as isGenericPBKDF2 above.
		predicateProto(isOnePassword, "1Password Agile Keychain", hashid.TierStructural,
			"colon-delimited record with exactly 3 fields: a numeric iteration count, a 16-char hex salt, and a hex data field whose length is a multiple of 32 (at least 64 chars)",
			8, "1Password's original Agile Keychain format was superseded by OPVault and then the 1Password 8 vault format years ago, so this record now only appears in older exported or legacy vaults", "1password"),
		// isIKE requires exactly 9 colon-delimited fields, each non-empty,
		// of even length and hex, with the final field exactly 32 or 40 hex
		// chars. No fixed prefix; purely field count, length and hex
		// composition, so TierStructural.
		predicateProto(isIKE, "IKE aggressive-mode PSK", hashid.TierStructural,
			"9 colon-delimited hex fields, each non-empty and of even length, with the final field exactly 32 or 40 hex chars (a 16- or 20-byte HASH_R)",
			5, "IKE aggressive-mode PSK hashes require capturing an active VPN handshake on the wire, a narrower and more situational scenario than recovering an on-disk credential store", "ike"),
		// isDCC2 is a named predicate wrapping a literal prefix check
		// ($DCC2$), nothing more, so TierSignature.
		predicateProto(isDCC2, "Domain Cached Credentials 2 (mscash2)", hashid.TierSignature,
			"record prefix $DCC2$",
			20, "DCC2 (mscash2) has been the cached-domain-credential hash on every domain-joined Windows machine since Vista, so it recurs routinely wherever Windows offline credential caches are extracted", "dcc2"),
		hasPrefixProto("SCRAM-SHA-256$", "PostgreSQL SCRAM-SHA-256", 20,
			"SCRAM-SHA-256 has been PostgreSQL's default password authentication method since PostgreSQL 10 (2017), so it now recurs on the majority of currently deployed PostgreSQL instances", "scram"),
		hasPrefixProto("$cram_md5$", "CRAM-MD5", 6,
			"most modern IMAP/SMTP servers have deprecated CRAM-MD5 in favor of stronger SASL mechanisms, so this challenge-response record now mostly surfaces on older, unmigrated mail-server configurations", "cram-md5"),
		// isCitrix checks an exact total length (49), a literal leading '1'
		// byte, and hex composition of the rest. The single leading byte is
		// the same weak discriminator as citrix-sha512's leading '2' in
		// batchD (also TierStructural), not a multi-char literal prefix.
		predicateProto(isCitrix, "Citrix NetScaler SHA-1", hashid.TierStructural,
			"49-char record starting with '1', the remaining 48 chars hex (an 8-char salt and a 40-char SHA-1 digest)",
			10, "Citrix NetScaler's SHA-1 admin/local-user password hash recurs wherever a NetScaler configuration is captured, though Citrix ADC is one of several competing enterprise application-delivery-controller products", "citrix"),
		// isCiscoASA is nested in the legacy cascade: it always yields
		// cisco-asa, and additionally appends oracle-h when the same record
		// also parses as an Oracle H digest:username pair via parseOracleH.
		// That is a conditional candidate list depending on the input, so
		// it is expressed with Compute rather than Types, mirroring the
		// legacy cascade's own conditional append exactly (returning both
		// types unconditionally would be a behaviour change the golden file
		// would catch). isCiscoASA itself only checks a colon-split field
		// count (2), an exact 16-char length and crypt-64-alphabet
		// membership on field 0, and non-emptiness on field 1 — no fixed
		// prefix, so TierStructural.
		{
			Display: "Cisco PIX/ASA MD5 (with conditional Oracle H)",
			Tier:    hashid.TierStructural, Exclusive: true,
			Compute: func(in hashid.Input) ([]string, bool) {
				if !isCiscoASA(in.Normalized) {
					return nil, false
				}
				candidates := []string{"cisco-asa"}
				if _, _, ok := parseOracleH(in.Normalized); ok {
					candidates = append(candidates, "oracle-h")
				}
				return candidates, true
			},
			Prevalence: 12, Rationale: "Cisco PIX/ASA's MD5-based local credential hash is still the format used by any ASA firewall that hasn't been reconfigured to the newer type-8/9 PBKDF2/scrypt secret encodings, so it recurs in ASA configuration-file forensics",
		},
		// isIPMI requires exactly 2 colon-delimited fields: field 0 more
		// than 40 hex chars of even length (a RAKP salt blob), field 1
		// exactly 40 hex chars (an HMAC-SHA1 digest). No fixed prefix, so
		// TierStructural.
		predicateProto(isIPMI, "IPMI2 RAKP (HMAC-SHA1)", hashid.TierStructural,
			"colon-delimited record with exactly 2 fields: the first more than 40 hex chars of even length (a RAKP salt blob), the second exactly 40 hex chars (an HMAC-SHA1 digest)",
			5, "IPMI2 RAKP HMAC-SHA1 authentication requires capturing a live BMC RAKP exchange on the network, a narrower target than an on-disk credential dump", "ipmi"),
		// isIPMIMD5 requires exactly 2 colon-delimited fields: field 0
		// exactly 32 hex chars, field 1 between 116 and 148 hex chars of
		// even length. No fixed prefix, so TierStructural.
		predicateProto(isIPMIMD5, "IPMI2 RAKP (HMAC-MD5)", hashid.TierStructural,
			"colon-delimited record with exactly 2 fields: the first exactly 32 hex chars (an HMAC-MD5 digest), the second 116-148 hex chars of even length (a RAKP packet blob)",
			3, "the older HMAC-MD5 RAKP variant only appears on IPMI 2.0 implementations still permitting the weaker of the two offered cipher suites, a shrinking population as BMC firmware defaults to the SHA1 suite", "ipmi-md5"),
		// isAIX is an OR of four literal prefixes ({smd5}, {ssha1},
		// {ssha256}, {ssha512}), nothing more, so TierSignature.
		predicateProto(isAIX, "AIX smd5/ssha* shadow hash", hashid.TierSignature,
			"record prefix {smd5}, {ssha1}, {ssha256} or {ssha512}",
			6, "AIX's smd5/ssha* password schemes are specific to IBM AIX systems, a much smaller and shrinking population of Unix deployments compared to Linux", "aix"),
		// isRedHat389PBKDF2 checks the literal prefix {PBKDF2_SHA256}, then
		// base64-decodes the remainder and requires it to be exactly 324
		// bytes (a 4-byte iteration count, a 64-byte salt, a 256-byte
		// digest) with the iteration count at least 2048. A literal prefix
		// plus decoded fields, so TierSignature.
		predicateProto(isRedHat389PBKDF2, "Red Hat 389-DS PBKDF2-SHA256", hashid.TierSignature,
			"record prefix {PBKDF2_SHA256} followed by a base64 payload that decodes to exactly 324 bytes (a 4-byte big-endian iteration count of at least 2048, a 64-byte salt and a 256-byte digest)",
			10, "Red Hat/389 Directory Server's PBKDF2_SHA256 scheme is the current default on RHDS/FreeIPA directory servers, giving it real recurring exposure specifically within that directory-server family", "ldap-pbkdf2"),
		// isLDAP is an OR of ten literal scheme-tag prefixes ({SSHA512}
		// through {MD5}) or the literal prefix {CRYPT} plus a
		// looksLikeCryptHash check on the remainder. A prefix (or set of
		// prefixes) plus, for the {CRYPT} branch, a further shape check, so
		// TierSignature.
		predicateProto(isLDAP, "LDAP salted digest (RFC 2307)", hashid.TierSignature,
			"record prefix from the {SSHA512}/{SSHA384}/{SSHA256}/{SSHA}/{SMD5}/{SHA512}/{SHA384}/{SHA256}/{SHA}/{MD5} family, or record prefix {CRYPT} followed by a body that looks like a crypt(3) hash",
			25, "the RFC 2307 {SSHA}/{SMD5}/{SHA}/{MD5} family plus {CRYPT} remains the standard userPassword encoding across OpenLDAP and 389 Directory Server, so it recurs routinely wherever an LDAP directory database is extracted", "ldap"),
		// isSybaseASE checks the literal 6-char prefix "0xc007" plus an
		// exact total length (86) and hex composition of the rest — the
		// same "short literal prefix + fixed length" shape as fortigate256
		// (batchD, TierSignature), unlike citrix-sha512/isCitrix's single-
		// char markers above, so TierSignature.
		predicateProto(isSybaseASE, "Sybase ASE", hashid.TierSignature,
			"record prefix 0xc007 with a fixed 86-char total length, the remaining 80 chars hex (an 8-byte salt and a 32-byte SHA-256 digest)",
			4, "Sybase ASE's installed base has shrunk sharply since SAP folded it into the SAP ASE product line, making its salted SHA-256 login hash a narrow legacy-database target", "sybase"),
		// isSAPCodvnFGRFCReadTable requires a user$digest shape (no
		// additional $ before the last one) with a 40-char hex digest whose
		// last 20 chars must equal the literal zero-padding
		// "00000000000000000000". That literal fixed-value substring is an
		// embedded signature marker, the same reasoning that made
		// web2py-pbkdf2's embedded ",sha512)$" substring TierSignature in
		// batchD, even though it isn't at the record's start. Checked
		// before the more general isSAPCodvnFG below, reproducing the
		// cascade's own precedence (both would otherwise match the same
		// record).
		predicateProto(isSAPCodvnFGRFCReadTable, "SAP CODVN F/G (RFC_READ_TABLE truncated)", hashid.TierSignature,
			"user$digest record (no additional $ before the last one) with a 40-char hex digest whose last 20 chars are the literal zero-padding 00000000000000000000",
			4, "this record only appears when the RFC_READ_TABLE information-disclosure technique was used against USR02 specifically, a narrower extraction scenario than a direct SAP password-hash dump", "sap-fg-rfc-read-table"),
		// isSAPCodvnBRFCReadTable is the same embedded-literal-marker shape
		// as isSAPCodvnFGRFCReadTable above, but over a 16-char hex digest
		// whose last 8 chars must equal the literal "00000000". Checked
		// before the more general isSAPCodvnB below, reproducing the
		// cascade's own precedence.
		predicateProto(isSAPCodvnBRFCReadTable, "SAP CODVN B (RFC_READ_TABLE truncated)", hashid.TierSignature,
			"user$digest record (no additional $ before the last one) with a 16-char hex digest whose last 8 chars are the literal zero-padding 00000000",
			3, "this record combines the same narrow RFC_READ_TABLE extraction scenario with SAP's oldest and most deprecated password scheme, making it the least commonly encountered of the SAP branches in this batch", "sap-b-rfc-read-table"),
		// isSAPCodvnFG requires only a user$digest shape (no additional $
		// before the last one) with a 40-char hex digest — no literal
		// marker distinguishes it from any other user$40-hex record, so
		// TierStructural, unlike its RFC_READ_TABLE sibling above.
		predicateProto(isSAPCodvnFG, "SAP CODVN F/G (PASSCODE)", hashid.TierStructural,
			"user$digest record (no additional $ before the last one) with a 40-char hex digest",
			12, "SAP CODVN F/G (PASSCODE) has been SAP's standard USR02 password hash since NetWeaver 7.0, so it recurs wherever a current SAP system's user table is dumped directly", "sap-fg"),
		// isJuniper requires a user$body shape with a 30-char body in the
		// Juniper base64 alphabet, additionally requiring the literal
		// obfuscation characters 'n','r','c','s','t','n' at fixed positions
		// 0, 6, 12, 17, 23 and 29. Those six position-pinned literal chars
		// are an embedded signature (astronomically unlikely to occur by
		// chance in an arbitrary base64 string), the same reasoning as the
		// SAP RFC_READ_TABLE entries above, so TierSignature.
		predicateProto(isJuniper, "Juniper NetScreen (ScreenOS)", hashid.TierSignature,
			"user$body record with a 30-char body in the Juniper base64 alphabet, carrying the literal obfuscation characters n, r, c, s, t, n at fixed positions 0, 6, 12, 17, 23 and 29",
			5, "Juniper's ScreenOS/NetScreen product line reached end-of-life in 2015, so this password hash now surfaces mainly in legacy network-device configuration backups", "juniper"),
		// isSAPCodvnB requires only a user$digest shape (no additional $
		// before the last one) with a 16-char hex digest — no literal
		// marker, so TierStructural, the same reasoning as isSAPCodvnFG
		// above. Checked after isJuniper, reproducing the cascade's own
		// order.
		predicateProto(isSAPCodvnB, "SAP CODVN B (BCODE)", hashid.TierStructural,
			"user$digest record (no additional $ before the last one) with a 16-char hex digest",
			4, "SAP CODVN B (BCODE) predates CODVN F/G, which superseded it back in the R/3 4.6C era, so it now appears only on very old, unpatched SAP systems", "sap-b"),
		// isMediaWiki checks the literal prefix $B$, then splits the
		// remainder on "$" into exactly 2 parts and requires the second to
		// be exactly 32 hex chars. A literal prefix plus a decoded field,
		// so TierSignature.
		predicateProto(isMediaWiki, "MediaWiki $B$", hashid.TierSignature,
			"record prefix $B$ followed by a $-delimited salt field and a 32-char hex digest field",
			15, "MediaWiki powers Wikipedia and thousands of other wikis, and $B$ has been its default password scheme across a long-supported range of MediaWiki versions, giving it broad real-world exposure", "mediawiki"),
		// The bare parseOracleH guard is a separate, later branch in the
		// legacy cascade from the one nested inside isCiscoASA above (and
		// from batchD's earlier, O$-specific "oracle-h (O$ form)" entry):
		// it fires for either an O$<username>#<digest> record or a bare
		// <digest>:<username> colon record, with no requirement that any
		// other predicate also match. Because parseOracleH's own Match here
		// is an OR of a prefix test (O$) and a no-prefix test (the colon
		// form), the tier must cover the weaker disjunct, so TierStructural
		// — the general rule established for isLegacyPMKID's OR in batchE.
		//
		// This entry can never win a table evaluation. Its O$-prefixed form
		// is always caught first by batchD's earlier, more specific
		// "oracle-h (O$ form)" entry (parseOracleH succeeds AND HasPrefix
		// O$). Its colon-delimited digest:username form is always also a
		// valid isCiscoASA match: parseOracleH requires the record to split
		// into exactly one ":" with a 16-char hex field 0 and a non-empty
		// field 1, and isCiscoASA requires the same 2-field split with a
		// 16-char field 0 that is a valid crypt-64 token — every hex digit
		// is itself a member of the crypt-64 alphabet
		// ("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
		// so a valid parseOracleH digest is always a valid isCiscoASA pix
		// token, and parseOracleH's non-empty-username requirement always
		// satisfies isCiscoASA's non-empty-salt requirement. So the
		// isCiscoASA Compute entry above — earlier in table order, matching
		// the cascade's own order — always wins first, and its own nested
		// parseOracleH check already appends oracle-h when applicable.
		// Kept anyway for cascade fidelity, not because this occurrence is
		// independently reachable; see TestTableCoverageBatchG's comment
		// for the same conclusion from the test side.
		{
			Types: []string{"oracle-h"}, Display: "Oracle H-type (colon or O$ form)",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if _, _, ok := parseOracleH(in.Normalized); ok {
					return "parses via parseOracleH as either an O$<username>#<16-hex digest> record or a bare <16-hex digest>:<username> colon record, with a username of 1-30 bytes", true
				}
				return "", false
			},
			Prevalence: 3, Rationale: "Oracle 7-10g H-type DES hashes recur in legacy Oracle database forensic work; the bare digest:username colon form this entry additionally accepts is the less common of the two record shapes, since most extraction tooling preserves the John-style O$ marker captured by the earlier, more specific entry",
		},
	}
}
