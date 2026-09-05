package main

import (
	"hashsmith-go/internal/hashid"
	"strings"
)

// walletsPrototypes ports the wallet, wireless and web-framework branches of
// the legacy cascade: WPA*01*/WPA*02*/isLegacyPMKID through sha1-cx (original
// lines 1470-1554), the first half of that range; a second batch (F) picks up
// at isMySQL8.
//
// This half ports 27 single-type branches plus two nested ones ($ethereum$
// and $blockchain$, each split into two prototypes with the more specific
// form listed first), for 28 total: detectWPAPMKIDRecord (original lines
// 1473-1475) is a genuine, currently-unported branch inside this range that
// has no entry in the golden-inputs convenience file, which otherwise lists
// exactly 27 branches for this half — see the task report for the full
// explanation of that discrepancy. Confirmed against
// testdata/detect_golden.txt lines 239-240 (wpa-pmk, wpa-pmkid).
func walletsPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// The legacy branch ORs three conditions for one type: two literal
		// prefixes (WPA*01*, WPA*02*, the modern hc22000 form) plus
		// isLegacyPMKID, which has no fixed prefix at all — it only checks
		// that the record splits into 4 asterisk-delimited fields of length
		// 32/12/12/nonempty, all hex. Because a match can come from either
		// path, and one path carries no literal marker, the whole prototype
		// is TierStructural rather than TierSignature: reporting the
		// isLegacyPMKID path as an unrivalled "certain" match would overstate
		// its evidence.
		{
			Types: []string{"wpa"}, Display: "WPA/WPA2 PMKID and EAPOL (hc22000)",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "WPA*01*") || strings.HasPrefix(in.Normalized, "WPA*02*") || isLegacyPMKID(in.Normalized) {
					return "record prefix WPA*01* or WPA*02*, or (isLegacyPMKID) a bare asterisk-delimited pmkid*ap*sta*essid record with fields of length 32/12/12/nonempty, all hex", true
				}
				return "", false
			},
			Prevalence: 30, Rationale: "the WPA*01*/WPA*02* hc22000 format is the current default output of hcxpcapngtool and other modern WiFi-capture conversion tools, making it the most common wireless-handshake record encountered; isLegacyPMKID covers the older bare PMKID line those same tools superseded",
		},
		// detectWPAPMKIDRecord has no fixed prefix: it only checks that the
		// record splits into 3 or 4 colon-delimited fields of length
		// 32/12/12/(hex, even, <=64), all hex, so TierStructural. Its Types
		// depend on the input (3 fields -> wpa-pmk, 4 fields -> wpa-pmkid),
		// so it is expressed with Compute rather than Types, mirroring the
		// legacy cascade's `if typ := detectWPAPMKIDRecord(t); typ != ""`.
		{
			Display: "WPA PMKID/EAPOL colon-delimited record (raw PMK candidate)",
			Tier:    hashid.TierStructural, Exclusive: true,
			Compute: func(in hashid.Input) ([]string, bool) {
				if typ := detectWPAPMKIDRecord(in.Normalized); typ != "" {
					return []string{typ}, true
				}
				return nil, false
			},
			Prevalence: 8, Rationale: "these colon-delimited PMKID/EAPOL-MIC records require a raw PMK or PSK candidate rather than a full 4-way handshake capture, a narrower verification path than the primary WPA*01*/WPA*02* hc22000 format above",
		},
		// $ethereum$ is nested in the legacy cascade: a record additionally
		// prefixed "$ethereum$w*" is the pre-sale variant; any other
		// "$ethereum$" record is the standard keystore. Neither sub-branch
		// decodes anything beyond the prefix in the cascade itself (the
		// field-level parse happens only in the verifier), so both are plain
		// hasPrefixProto entries; the more specific "$ethereum$w*" form is
		// listed first so table order reproduces the nested precedence, as
		// with $vbox$ in batchB.
		hasPrefixProto("$ethereum$w*", "Ethereum pre-sale wallet", 4,
			"the 2014 Ethereum pre-sale wallet format was retired once the mainnet went live, so it now appears only in very old pre-sale wallet backups", "ethereum-presale"),
		hasPrefixProto("$ethereum$", "Ethereum wallet (Web3 keystore v3)", 15,
			"the standard $ethereum$p* Web3 keystore v3 record is the current default export format for Ethereum wallets across MetaMask, geth and most other clients, making it the more commonly encountered of the two Ethereum record shapes here", "ethereum"),
		hasPrefixProto("$aescrypt$1*", "AES Crypt v1 password record", 12,
			"AES Crypt is a long-standing, actively maintained cross-platform file-encryption tool with a simple documented file format, giving it broader real-world exposure than most of the single-vendor wallet formats in this batch", "aescrypt"),
		hasPrefixProto("$multibit$1*", "MultiBit Classic / bitcoinj encrypted key", 5,
			"MultiBit was discontinued in 2017, so its encrypted-key format now only surfaces in legacy Bitcoin wallet backups rather than active wallets", "multibit-key"),
		// isTerraWallet has no fixed prefix — it only checks an exact total
		// length (172), hex composition of the first 64 chars, and that the
		// remainder base64-decodes to exactly 80 bytes — so TierStructural,
		// not TierSignature.
		predicateProto(isTerraWallet, "Terra Station wallet", hashid.TierStructural,
			"172-char record: the first 64 chars hex, the remaining chars base64-decoding to exactly 80 bytes",
			5, "Terra Station's user base contracted sharply after the LUNA/UST collapse in 2022, so its wallet keystore format is now a narrower cryptocurrency-wallet target than Bitcoin or Ethereum", "terra-wallet"),
		hasPrefixProto("$bitcoin$", "Bitcoin/Litecoin wallet.dat", 25,
			"Bitcoin Core's wallet.dat encryption remains the reference implementation for the largest cryptocurrency by market capitalization, making $bitcoin$ the most frequently encountered wallet record in this batch", "bitcoin"),
		hasPrefixProto("$dmg$", "Apple encrypted DMG v1/v2", 18,
			"encrypted Apple Disk Images are a routine artifact in macOS forensic examinations, recurring wherever a suspect volume or backup image is DMG-password-protected", "dmg"),
		hasPrefixProto("$monero$0*", "Monero .keys wallet", 12,
			"Monero is consistently a top-10 cryptocurrency by market capitalization, so its wallet-file KDF record recurs in cryptocurrency casework, though its privacy-coin niche gives it a smaller install base than Bitcoin", "monero"),
		hasPrefixProto("$bitwarden$", "Bitwarden vault master password", 20,
			"Bitwarden is among the most widely adopted cross-platform password managers, making its exported vault a common target in password-manager cracking casework", "bitwarden"),
		hasPrefixProto("$itunes_backup$", "iTunes backup (PBKDF2 + AES key-unwrap)", 18,
			"encrypted iTunes/Finder local device backups are a standard artifact recovered in iOS device forensic examinations", "itunes"),
		hasPrefixProto("$ansible$", "Ansible Vault", 12,
			"Ansible Vault only appears when a project has opted into encrypting its playbook secrets, a common but non-default DevOps practice, so it recurs less often than formats that are on by default", "ansible"),
		// $blockchain$ is nested in the legacy cascade: parseBlockchainLegacy
		// succeeding (full parse: prefix, a $-delimited byte-length field,
		// and a hex data field whose decoded length equals it and is >=32)
		// selects the legacy variant; otherwise any other "$blockchain$"
		// record is the current v2 format. The legacy check fully parses
		// fields, so TierSignature; the more specific entry is listed first
		// so table order reproduces the nested precedence.
		{
			Types: []string{"blockchain-legacy"}, Display: "Blockchain My Wallet legacy AES-OFB wallet",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if _, _, err := parseBlockchainLegacy(in.Normalized); err == nil {
					return "record prefix $blockchain$ followed by a $-delimited byte-length field and a hex data field whose decoded length equals it (at least 32 bytes)", true
				}
				return "", false
			},
			Prevalence: 4, Rationale: "Blockchain.info replaced this single-iteration AES-OFB wallet format with the PBKDF2-hardened v2 format below years ago, so the legacy form now only appears in very old wallet.aes.json backups",
		},
		hasPrefixProto("$blockchain$", "Blockchain.info My Wallet v2", 10,
			"the current PBKDF2-hardened Blockchain.info My Wallet v2 format is that service's present-day default, giving it more real-world exposure than the legacy single-iteration variant above", "blockchain"),
		hasPrefixProto("$rc4$", "RC4 DropN known-plaintext verifier", 4,
			"the RC4-DropN known-plaintext verifier (Hashcat modes 33500-33502) requires a captured known-plaintext/ciphertext pair for a deprecated stream cipher, a scenario encountered far less often than an on-disk credential dump", "rc4-dropn"),
		// isShiro1 fully parses the $shiro1$SHA-512$* record (6 $-delimited
		// fields, literal "shiro1" and "SHA-512" markers, iterations, and
		// salt/digest both valid base64 with the digest exactly 64 bytes), so
		// TierSignature.
		predicateProto(isShiro1, "Apache Shiro 1 SHA-512", hashid.TierSignature,
			"$shiro1$SHA-512$<iterations>$<base64 salt>$<base64 digest>: 6 $-delimited fields with literal shiro1/SHA-512 markers, and salt/digest that both decode as base64 with the digest exactly 64 bytes",
			10, "Apache Shiro is a widely used Java security framework, but iterated salted SHA-512 (Hashcat mode 12150) is only one of several credential-storage schemes a Shiro-based application may be configured to use", "shiro1-sha512"),
		// isSSPR is a literal prefix check ("$sspr$"), nothing more, so
		// TierSignature.
		predicateProto(isSSPR, "NetIQ SSPR / Adobe AEM record", hashid.TierSignature,
			"record prefix $sspr$",
			6, "the NetIQ SSPR / Adobe AEM self-service password reset answer store is confined to those two specific enterprise identity products, a narrow slice of enterprise-software casework", "sspr"),
		// isNetIQPBKDF2 is an OR of two literal prefixes, nothing more, so
		// TierSignature.
		predicateProto(isNetIQPBKDF2, "NetIQ PBKDF2-HMAC record", hashid.TierSignature,
			"record prefix $pbkdf2-hmac-sha1$ or $pbkdf2-hmac-sha512$",
			6, "NetIQ's PBKDF2-HMAC-SHA1/SHA512 record is specific to NetIQ identity-management deployments, a narrower installed base than general-purpose PBKDF2 usage", "netiq-pbkdf2"),
		// isAS400SSHA1 is a literal prefix check ("$as400$ssha1$*"), nothing
		// more, so TierSignature.
		predicateProto(isAS400SSHA1, "IBM AS/400 salted SHA-1", hashid.TierSignature,
			"record prefix $as400$ssha1$*",
			4, "IBM AS/400 (iSeries) salted SHA-1 credentials are confined to a shrinking installed base of legacy IBM midrange systems", "as400-ssha1"),
		// isAuthMeSHA256 is a literal prefix check ("$SHA$"), nothing more,
		// so TierSignature.
		predicateProto(isAuthMeSHA256, "AuthMe SHA-256", hashid.TierSignature,
			"record prefix $SHA$",
			8, "AuthMe is one of several competing Minecraft server authentication plugins (alongside LoginSecurity and others), limiting its share of Minecraft-server credential dumps", "authme-sha256"),
		// isPHPS is a literal prefix check ("$PHPS$"), nothing more, so
		// TierSignature.
		predicateProto(isPHPS, "PHPS md5(md5($pass).$salt)", hashid.TierSignature,
			"record prefix $PHPS$",
			5, "the $PHPS$ md5(md5($pass).$salt) scheme predates PHP's password_hash() API introduced in PHP 5.5 and is rarely chosen by currently maintained PHP applications", "phps"),
		// The legacy branch requires both a literal prefix ("pbkdf2(") and a
		// literal substring (",sha512)$"); both are literal text markers, so
		// TierSignature.
		{
			Types: []string{"web2py-pbkdf2"}, Display: "web2py PBKDF2-HMAC-SHA512",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "pbkdf2(") && strings.Contains(in.Normalized, ",sha512)$") {
					return "record prefix pbkdf2( together with the substring ,sha512)$", true
				}
				return "", false
			},
			Prevalence: 5, Rationale: "web2py has a substantially smaller install base than Django or Flask among Python web frameworks, giving its PBKDF2-HMAC-SHA512 password record a narrower real-world footprint",
		},
		hasPrefixProto("$wp$2", "WordPress bcrypt(HMAC-SHA384($pass))", 20,
			"WordPress moved to bcrypt(HMAC-SHA384(password)) hashing starting with WordPress 6.8, and WordPress powers a large share of the web, so this record is common on any recently updated WordPress site", "wordpress-bcrypt"),
		// The legacy branch tests two literal prefixes ("$krb5db$17$" and
		// "$krb5db$18$", etype 17/18) in one `if` for the same Kerberos KDB
		// principal-key type; kept as one prototype here so the
		// coverage-case count tracks the single cascade branch it replaces.
		{
			Types: []string{"krb5db"}, Display: "Kerberos 5 database key (etype 17/18)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$krb5db$17$") || strings.HasPrefix(in.Normalized, "$krb5db$18$") {
					return "record prefix $krb5db$17$ or $krb5db$18$", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "MIT Kerberos/Active Directory KDC database dumps (etype 17/18, AES-128/256) are the modern default principal-key encoding, recurring wherever a domain controller's Kerberos database is extracted",
		},
		// No fixed prefix: only a dot-delimited field count (3) and an exact
		// length (27) on the third field. TierStructural.
		{
			Types: []string{"flask-session"}, Display: "Flask session cookie (HMAC-SHA1)",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				fields := strings.Split(in.Normalized, ".")
				if len(fields) == 3 && len(fields[2]) == 27 {
					return "dot-delimited record with exactly 3 fields, the third exactly 27 chars", true
				}
				return "", false
			},
			Prevalence: 12, Rationale: "Flask's signed client-side session cookie is that framework's built-in default session mechanism, so it recurs wherever a Flask application's session cookie is captured, though Flask itself is one of several popular Python web frameworks",
		},
		// No fixed prefix: only a colon-delimited field count (2), an exact
		// length (40) and hex-ness on the first field, and a minimum length
		// (>=128) and hex-ness on the second. TierStructural. This branch is
		// checked before sha1-cx below (same field-0 shape, distinguished
		// only by field-1 length), reproducing the cascade's own order.
		{
			Types: []string{"peoplesoft-token"}, Display: "PeopleSoft PS_TOKEN salted SHA-1",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				fields := strings.Split(in.Normalized, ":")
				if len(fields) == 2 && len(fields[0]) == 40 && isHex(fields[0]) &&
					len(fields[1]) >= 128 && isHex(fields[1]) {
					return "colon-delimited record with exactly 2 fields: the first exactly 40 hex chars, the second at least 128 hex chars", true
				}
				return "", false
			},
			Prevalence: 5, Rationale: "PeopleSoft's PS_TOKEN salted SHA-1 format is specific to Oracle PeopleSoft HCM/Campus Solutions deployments, a narrow enterprise-software niche",
		},
		// No fixed prefix: only a colon-delimited field count (2), an exact
		// length (40) and hex-ness on the first field, and an exact length
		// (20, no hex requirement) on the second. TierStructural.
		{
			Types: []string{"sha1-cx"}, Display: "Iterated SHA-1 CX construction",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				fields := strings.Split(in.Normalized, ":")
				if len(fields) == 2 && len(fields[0]) == 40 && isHex(fields[0]) && len(fields[1]) == 20 {
					return "colon-delimited record with exactly 2 fields: the first exactly 40 hex chars, the second exactly 20 chars", true
				}
				return "", false
			},
			Prevalence: 3, Rationale: "Hashcat mode 14400's iterated SHA-1 CX construction is a narrowly-scoped legacy verifier without a well-known single source application, so it recurs far less often than mainstream crypt(3) or KDF formats",
		},
	}
}

// webFrameworkPrototypes ports the remaining wallet, wireless and web-framework
// branches of the legacy cascade: the three-field colon-split branch that
// yields rails-restful-auth (the branch immediately before isMySQL8; a scope
// correction moved it into this half so table order still matches cascade
// order) through isJWT (original lines 1470-1562). 28 top-level `if`
// statements, one of which (isPhpassHash) is nested and becomes two
// prototypes, for 29 total.
func webFrameworkPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// The legacy branch's candidate list is conditional: it always
		// includes rails-restful-auth and sha1-salt1-pass-salt2, and appends
		// sha1-salt-user-password only when fields 1 and 2 are each at most
		// 256 chars, of even length, and hex-or-empty. No fixed prefix
		// distinguishes this 3-field colon record from any other structural
		// check, so TierStructural; expressed with Compute because the
		// candidate list depends on the input, mirroring the legacy
		// cascade's conditional append exactly (returning all three
		// unconditionally would be a behaviour change the golden file
		// would catch).
		{
			Display: "Rails RESTful auth (3-field colon record)",
			Tier:    hashid.TierStructural, Exclusive: true,
			Compute: func(in hashid.Input) ([]string, bool) {
				fields := strings.Split(in.Normalized, ":")
				if len(fields) != 3 || len(fields[0]) != 40 || !isHex(fields[0]) {
					return nil, false
				}
				candidates := []string{"rails-restful-auth", "sha1-salt1-pass-salt2"}
				if len(fields[1]) <= 256 && len(fields[1])%2 == 0 && isHexOrEmpty(fields[1]) &&
					len(fields[2]) <= 256 && len(fields[2])%2 == 0 && isHexOrEmpty(fields[2]) {
					candidates = append(candidates, "sha1-salt-user-password")
				}
				return candidates, true
			},
			Prevalence: 6, Rationale: "Rails' restful_authentication plugin, the source of this three-field salted-SHA1 record, was retired with the Rails 2.x line in favor of has_secure_password/bcrypt, so it now only surfaces in very old Rails codebases",
		},
		// isMySQL8 checks the "$mysql$A$" prefix, then decodes a 3-digit
		// cost, a 20-byte hex salt and a 43-byte crypt-64 digest — a prefix
		// check plus decoded fields, so TierSignature.
		predicateProto(isMySQL8, "MySQL 8 caching_sha2_password", hashid.TierSignature,
			"record prefix $mysql$A$ followed by a 3-digit cost, a 20-byte hex salt, and a 43-byte crypt-64 digest",
			25, "caching_sha2_password has been MySQL's default authentication plugin since MySQL 8.0 (2018), so this record recurs wherever a current MySQL/MariaDB user table is dumped", "mysql8"),
		hasPrefixProto("$axcrypt_sha1$", "AxCrypt SHA-1", 8,
			"AxCrypt is a single-vendor Windows file-encryption tool with a modest user base compared to general-purpose archive/disk encryption tools", "axcrypt-sha1"),
		hasPrefixProto("$mongodb-scram$", "MongoDB SCRAM-SHA-1", 12,
			"MongoDB's SCRAM-SHA-1 stored credential record recurs wherever a MongoDB server's own credential database is extracted, though MongoDB is one of several popular document databases", "mongodb"),
		hasPrefixProto("$solarwinds$", "SolarWinds Orion credential vault", 5,
			"the SolarWinds Orion credential-vault record is specific to one enterprise network-monitoring product, a narrow slice of casework", "solarwinds"),
		hasPrefixProto("$sip$*", "SIP digest challenge-response", 10,
			"the SIP digest challenge-response record (Hashcat mode 11400) requires a captured SIP REGISTER/INVITE exchange, a narrower capture scenario than an on-disk credential dump", "sip"),
		// isDjangoHash checks that the record's first $-delimited field is a
		// literal known Django hasher name, then validates envelope-specific
		// field count and digest encoding (e.g. md5/sha1 require a 32/40-char
		// hex third field) — a prefix check plus decoded fields, so
		// TierSignature.
		predicateProto(isDjangoHash, "Django password hash", hashid.TierSignature,
			"the record's first $-delimited field is a known Django password-hasher name (pbkdf2_sha256, pbkdf2_sha1, scrypt, argon2, bcrypt_sha256, bcrypt, md5 or sha1) with envelope-appropriate field count and digest encoding",
			20, "Django is one of the most widely used Python web frameworks and its make_password() output format has changed little since Django 1.4, so its hashers recur routinely in web-application credential dumps", "django"),
		hasPrefixProto("truecrypt:", "TrueCrypt volume (colon form)", 3,
			"virtually all TrueCrypt records this project's own extractors and captured casework use are the $truecrypt$ form below, so this alternate colon-prefixed marker is rarely seen in practice", "truecrypt"),
		hasPrefixProto("veracrypt:", "VeraCrypt volume (colon form)", 3,
			"virtually all VeraCrypt records this project's own extractors and captured casework use are the $veracrypt$ form below, so this alternate colon-prefixed marker is rarely seen in practice", "veracrypt"),
		hasPrefixProto("$truecrypt$", "TrueCrypt volume", 15,
			"TrueCrypt was discontinued in 2014 but its container format lives on via VeraCrypt's compatibility mode, so $truecrypt$ headers still recur in older encrypted-volume forensic casework", "truecrypt"),
		hasPrefixProto("$veracrypt$", "VeraCrypt volume", 20,
			"VeraCrypt is the actively maintained successor to TrueCrypt and remains a common choice for full-disk/container encryption, giving it more real-world exposure than the discontinued TrueCrypt format above", "veracrypt"),
		// Fixed literal 3-char prefix ("AK1") plus an exact total length
		// (47). The prefix is what makes this a signature, unlike
		// lastpass/chap/the md5-group below, which have no literal prefix
		// at all.
		{
			Types: []string{"fortigate"}, Display: "FortiGate/FortiOS AK1 local admin hash",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "AK1") && len(in.Normalized) == 47 {
					return "record prefix AK1 with a fixed 47-char total length", true
				}
				return "", false
			},
			Prevalence: 10, Rationale: "FortiGate's AK1 local admin-password hash recurs wherever a FortiGate firewall's configuration backup is examined, a narrower target than general-purpose Linux/Windows credential stores",
		},
		hasPrefixProto("{x-isSHA512, ", "LDAP {x-isSHA512} (SAP CODVN H)", 5,
			"the {x-isSHA512, N} SAP CODVN H variant requires a newer directory server version than the {x-issha}/{x-isSHA256}/{x-isSHA384} family in batch C, so it is the least commonly encountered member of that family", "sap-issha512"),
		// No fixed prefix: only a colon-delimited field count (4), an exact
		// length (32) and hex-ness on the first field, and an exact length
		// (32) and hex-ness on the fourth. TierStructural.
		{
			Types: []string{"lastpass"}, Display: "LastPass exported vault item",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				fields := strings.Split(in.Normalized, ":")
				if len(fields) == 4 && len(fields[0]) == 32 && isHex(fields[0]) &&
					len(fields[3]) == 32 && isHex(fields[3]) {
					return "colon-delimited record with exactly 4 fields: the first exactly 32 hex chars, the fourth exactly 32 hex chars", true
				}
				return "", false
			},
			Prevalence: 12, Rationale: "LastPass is one of the most widely used cloud password managers, so its exported vault-item hash recurs in password-manager cracking casework, though the structural-only match here (no fixed prefix) means the shape is shared with other 4-field colon records",
		},
		// isChap has no fixed prefix — it only checks field count (3), an
		// exact length (32) and hex-ness on the first field, and non-empty
		// hex on the second and third — so TierStructural.
		predicateProto(isChap, "iSCSI CHAP authentication", hashid.TierStructural,
			"colon-delimited record with exactly 3 fields: the first exactly 32 hex chars, the second and third both non-empty hex",
			8, "iSCSI CHAP authentication (Hashcat mode 4800) requires a captured CHAP exchange, a narrower target than an offline credential-store dump", "chap"),
		// No fixed prefix: only a colon-delimited field count (3) and an
		// exact length (32) and hex-ness on the first field; fields 1 and 2
		// are unconstrained. This shape is shared by several distinct
		// salted-MD5 constructions (including EmpireCMS's) with no fixed
		// prefix distinguishing them, so TierStructural. Checked after
		// isChap above, reproducing the cascade's own order: isChap's
		// stricter condition (f1/f2 also hex) wins first when both would
		// otherwise match.
		{
			Types:   []string{"md5-salt1-pass-salt2", "md5-salt1-upper-md5-salt2-pass", "md5-triple-dual-salt", "md5-salt1-sha1salt2pass", "md5-triple-passsalt-dual", "empirecms"},
			Display: "Salted MD5, 3-field colon record", Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				fields := strings.Split(in.Normalized, ":")
				if len(fields) == 3 && len(fields[0]) == 32 && isHex(fields[0]) {
					return "colon-delimited record with exactly 3 fields, the first exactly 32 hex chars", true
				}
				return "", false
			},
			Prevalence: 6, Rationale: "this shape covers several distinct salted-MD5 constructions (including EmpireCMS's) that share no fixed prefix, so it is inherently ambiguous, and individually each construction is a narrow niche-CMS or legacy-app target",
		},
		hasPrefixProto("$bitlocker$", "Windows BitLocker", 20,
			"BitLocker is Windows' built-in full-disk encryption, enabled by default on many modern Windows installs, making its recovery-password/password verifier a routine target in Windows disk-forensics casework", "bitlocker"),
		hasPrefixProto("$electrum$", "Electrum Bitcoin wallet", 10,
			"Electrum is a long-standing lightweight Bitcoin wallet with a smaller user base than exchange-integrated wallets like MetaMask, so its encrypted wallet file recurs less often in cryptocurrency casework", "electrum"),
		// isPhpassHash is nested in the legacy cascade: a record additionally
		// prefixed "$H$" yields {phpass, phpass-md5}; any other
		// isPhpassHash record (necessarily "$P$", the only other prefix
		// isPhpassHash accepts) yields {phpass} alone. Both sub-branches
		// require the same fixed-length (34-char) record behind a literal
		// prefix, so both are TierSignature; the $H$-specific entry is
		// listed first so table order reproduces the nested precedence, as
		// with $vbox$ in batchB.
		{
			Types: []string{"phpass", "phpass-md5"}, Display: "phpass portable hash ($H$)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isPhpassHash(in.Normalized) && strings.HasPrefix(in.Normalized, "$H$") {
					return "record prefix $H$ with a fixed 34-char total length", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "the $H$ variant is phpass's portable-hash fallback used by WordPress and phpBB3 installs that predate or opt out of bcrypt, so it still recurs on older PHP CMS installs",
		},
		predicateProto(isPhpassHash, "phpass portable hash ($P$)", hashid.TierSignature,
			"a 34-char record beginning $P$ or $H$ (the phpass portable hash format)",
			6, "the $P$ variant only appears on PHP installs without native bcrypt support, a shrinking population now that PHP has bundled CRYPT_BLOWFISH by default for well over a decade", "phpass"),
		// isDrupal7Hash checks a fixed 55-char total length behind the
		// literal "$S$" prefix, so TierSignature.
		predicateProto(isDrupal7Hash, "Drupal 7 password hash", hashid.TierSignature,
			"record prefix $S$ with a fixed 55-char total length",
			15, "Drupal 7 remained in active use and received official security support into 2025, a much longer tail than most CMS major versions get, so its password hash still recurs in Drupal-site credential dumps", "drupal7"),
		hasPrefixProto("$luks$", "LUKS encrypted volume", 15,
			"LUKS is the standard Linux full-disk-encryption format, so its header recurs wherever an encrypted Linux volume or disk image is seized", "luks"),
		// Fixed literal prefix ("$8$") plus an exact total length (61).
		{
			Types: []string{"cisco8"}, Display: "Cisco IOS type 8 (PBKDF2-HMAC-SHA256)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$8$") && len(in.Normalized) == 61 {
					return "record prefix $8$ with a fixed 61-char total length", true
				}
				return "", false
			},
			Prevalence: 12, Rationale: "Cisco type 8 has been the recommended replacement for the reversible/weak type 4-7 IOS password encodings since IOS 15.3, so it recurs on any recently hardened Cisco device configuration",
		},
		// Fixed literal prefix ("$9$") plus an exact total length (61).
		{
			Types: []string{"cisco9"}, Display: "Cisco IOS type 9 (scrypt)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$9$") && len(in.Normalized) == 61 {
					return "record prefix $9$ with a fixed 61-char total length", true
				}
				return "", false
			},
			Prevalence: 10, Rationale: "Cisco type 9 (scrypt) is offered alongside type 8 as a stronger secret encoding on current IOS/IOS-XE, but type 8 remains the more commonly deployed of the two in practice",
		},
		// Task 15: the outer "$4$" prefix this Match used to AND against was
		// wrong — crack_cisco.go's own doc comment and the isCiscoType4
		// vector itself agree the canonical type 4 value is the BARE 43-char
		// body (a Cisco `enable secret 4 <hash>` line carries no "$4$" tag;
		// isCiscoType4 only trims that prefix because it is harmless when
		// absent, not because it is required). ANDing a prefix the real
		// format never has made this branch unable to match the one shape it
		// actually needs to, so cisco4 was undetectable by auto-detection.
		// Dropping the AND makes the evidence exactly what descrypt's
		// looksLikeDescrypt is elsewhere in this table — an exact length plus
		// membership in the crypt-64 alphabet, nothing more — so TierShape,
		// not TierSignature; keeping TierSignature here would overclaim
		// exactly the confidence descrypt's own comment argues against.
		{
			Types: []string{"cisco4"}, Display: "Cisco IOS type 4 (unsalted SHA-256)",
			Tier: hashid.TierShape, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if isCiscoType4(in.Normalized) {
					return "43-char crypt-64-alphabet body (optional $4$ tag tolerated, not required)", true
				}
				return "", false
			},
			Prevalence: 4, Rationale: "Cisco IOS type 4 was deprecated and pulled from IOS releases after a 2013 disclosure that it was no stronger than the type 5 MD5 it was meant to replace, so it now appears only on very old unpatched device configs",
		},
		hasPrefixProto("$ml$", "macOS SALTED-SHA512-PBKDF2 shadow hash", 15,
			"the $ml$ record covers macOS's SALTED-SHA512-PBKDF2 shadow hash format used since 10.8, recurring wherever a modern macOS user account's local password hash is extracted", "macos"),
		hasPrefixProto("{PKCS5S2}", "Atlassian PKCS5S2 credential", 15,
			"{PKCS5S2} is the credential-store format shared across Atlassian's Jira/Confluence/Bitbucket product line, recurring wherever one of those on-prem instances' user database is captured", "atlassian"),
		// isPBKDF1SHA1 checks two literal field values ("PBKDF1", "sha1"),
		// then decodes the iteration count and base64 salt/digest fields —
		// a prefix check plus decoded fields, so TierSignature.
		predicateProto(isPBKDF1SHA1, "PBKDF1-SHA1", hashid.TierSignature,
			"record prefix PBKDF1:sha1: followed by an iteration-count field and base64 salt/digest fields (digest at most 20 bytes)",
			5, "PBKDF1 was deprecated by PKCS#5 v2.0/RFC 2898 in favor of PBKDF2 back in 1999, so applications that still emit this exact record shape are a narrow legacy minority", "pbkdf1"),
		// isJWT requires the literal "eyJ" prefix (via reJWT), a three-part
		// dot-delimited base64url shape, and a decoded header naming
		// HS256/HS384/HS512 — a prefix check plus a decoded field. It does
		// NOT verify the HMAC itself (that happens only in the separate
		// verifyJWT), so this is a signature/structural match, not a
		// checksum one: TierSignature, not TierChecksum.
		predicateProto(isJWT, "JWT (HMAC-signed)", hashid.TierSignature,
			"record begins with the base64url-encoded JSON-object prefix eyJ, splits into exactly three dot-delimited base64url segments, and its decoded header names HS256, HS384 or HS512",
			15, "HS256-signed JWTs are common in web-API authentication, but only the HMAC-signed variant is crackable at all (RS/ES-signed tokens use asymmetric keys), so this narrower slice of JWT usage is what recurs in JWT-cracking casework", "jwt"),
	}
}
