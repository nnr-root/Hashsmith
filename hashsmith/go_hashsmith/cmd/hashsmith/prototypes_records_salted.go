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
				// Skype shares this shape exactly — md5:username — with no
				// distinguishing prefix, so it is APPENDED rather than
				// prepended: it belongs in the candidate list crack will try,
				// but it must not displace the far commoner generic salted
				// readings of the same bytes.
				if f := strings.SplitN(t, ":", 2); len(f) == 2 && len(f[0]) == 32 && isHex(f[0]) && f[1] != "" {
					generic = append(generic, "skype")
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
		// John's spelling of a Domain Cached Credentials record. hashcat
		// writes "<md4>:<username>"; John writes "M$<username>#<md4>", which
		// nothing else claims.
		predicateProtoShared(isJohnMSCash, "MS Cache (John M$user#hash spelling)", hashid.TierSignature,
			"an M$-prefixed record ending in '#' and a 32-character hex digest",
			10, "cached domain credentials are a routine Windows forensics artefact, and John's tooling writes this spelling",
			"dcc"),
		// John's self-describing NetNTLM envelopes. The pwdump-shaped form
		// lines up with hashcat's field for field; these do not, and without a
		// prototype they resolve to nothing at all.
		predicateProtoShared(isJohnNetNTLMRecord, "NetNTLM (John envelope)", hashid.TierSignature,
			"a $NETNTLM$ or $NETNTLMv2$ record with hex challenge and response fields",
			12, "captured NetNTLM responses are routine in Windows network assessments, and John's spelling is what its tooling emits",
			johnNetNTLMTypes()...),
		// John's HMAC spelling, `<message>#<digest>`. The HMAC types are
		// otherwise undetectable by design — a bare HMAC-MD5 digest is a bare
		// MD5 digest — but this spelling carries the message with it, which
		// makes the record self-describing in a way the digest alone is not.
		// Candidates are every HMAC type of that digest length, since the
		// spelling names the construction and not the hash inside it.
		predicateProtoShared(isJohnHMACRecord, "HMAC (John message#digest spelling)", hashid.TierStructural,
			"a non-record message, '#', and a hex digest of an HMAC digest length",
			6, "John's HMAC formats write the message alongside the digest, so these records arrive from John users with no separate salt flag",
			johnHMACTypes()...),
		// John-only envelopes. Each names a format whose payload this tool
		// already reads; without the prototype the record resolves to whatever
		// its bare payload looks like, which for a 32-hex MD2 digest is MD5 and
		// for a 128-hex Whirlpool digest is SHA-512. crack_john_wrappers.go
		// strips the envelope once the type is settled, and only for the type
		// the envelope names, so offering the whole set here is safe.
		// John's spellings of records Hashsmith already reads. Each is a
		// literal prefix plus a field layout that has to parse, so a record
		// that merely starts with the prefix is not claimed — see
		// crack_john_spellings.go, where the same readers rewrite the record
		// for the verifier once the type is settled.
		predicateProto(func(s string) bool { _, ok := johnSeededChecksum(s, "$crc32$"); return ok },
			"CRC-32 with a seed (John $crc32$)", hashid.TierSignature,
			"record prefix $crc32$ carrying a seed and a checksum",
			3, "a CRC is a checksum rather than a password hash, and meets a cracker only when someone has used one as a password check anyway", "crc32-hashcat"),
		predicateProto(func(s string) bool { _, ok := johnSeededChecksum(s, "$crc32c$"); return ok },
			"CRC-32C with a seed (John $crc32c$)", hashid.TierSignature,
			"record prefix $crc32c$ carrying a seed and a checksum",
			3, "the Castagnoli polynomial is rarer than the ordinary CRC-32 outside storage checksums", "crc32c-hashcat"),
		predicateProto(func(s string) bool { _, ok := johnChapRecord(s); return ok },
			"iSCSI CHAP (John $chap$)", hashid.TierSignature,
			"record prefix $chap$ carrying an id, a challenge and a response",
			5, "CHAP is still the authentication most iSCSI targets are configured with, and the exchange is visible to anyone on the storage network", "chap"),
		predicateProto(func(s string) bool { _, ok := johnScryptRecord(s); return ok },
			"scrypt (John $7$ / $ScryptKDF.pm$)", hashid.TierSignature,
			"a $7$ or $ScryptKDF.pm$ record whose parameters parse",
			6, "scrypt's own crypt(3) spelling is what Colin Percival's reference implementation writes, so it appears wherever scrypt was adopted directly rather than through a framework", "scrypt"),
		predicateProto(func(s string) bool { _, ok := johnMongoDBSCRAM(s); return ok },
			"MongoDB SCRAM-SHA-1 (John $scram$)", hashid.TierSignature,
			"record prefix $scram$ carrying a user, an iteration count, a salt and a key",
			6, "SCRAM-SHA-1 is what MongoDB 3.0 through 3.6 stored, and those releases are still widely deployed", "mongodb"),
		predicateProto(func(s string) bool { _, _, ok := johnMongoDBLegacy(s); return ok },
			"MongoDB MONGODB-CR (John $mongodb$)", hashid.TierSignature,
			"record prefix $mongodb$0$ carrying a user and an MD5",
			5, "MONGODB-CR was removed in MongoDB 4.0, so these records come from older deployments and their dumps", "mongodb"),
		hasPrefixProto("$0$", "plaintext (John $0$)", 2,
			"John writes a known password as $0$<password> so a wordlist, a rule file or a mask can be tested without a hash in the way", "plaintext"),
		predicateProtoShared(isJohnWrappedRecord, "John-enveloped digest", hashid.TierSignature,
			"a record whose leading $name$ envelope names a supported hash or format",
			8, "John writes the format name into the record where hashcat writes the payload bare, so these records arrive from John users with the algorithm already stated",
			johnWrappedTypes()...),
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
		predicateProto(func(s string) bool { _, ok := johnRAKPRecord(s); return ok },
			"IPMI 2.0 RAKP exchange (John $rakp$)", hashid.TierSignature,
			"record prefix $rakp$ carrying a session blob and an HMAC-SHA1",
			16, "a BMC answers the RAKP exchange to anyone who asks, so the hash of any account on it can be collected remotely without credentials", "ipmi"),
		predicateProto(isKeystore, "Java keystore password", hashid.TierSignature,
			"record prefix $keystore$ carrying the store and the SHA-1 that closes it",
			12, "a JKS file is the default key store for Java applications and application servers, and is routinely found on deployed hosts", "jks-keystore"),
		predicateProto(func(s string) bool { _, ok := johnAgileKeychainRecord(s); return ok },
			"1Password Agile Keychain (John $agilekeychain$)", hashid.TierSignature,
			"record prefix $agilekeychain$ carrying a key blob per entry",
			10, "the Agile Keychain is 1Password 3 and 4's format, superseded by the cloud keychain but still what older vault backups are in", "1password"),
		predicateProto(func(s string) bool { _, ok := johnCloudKeychainRecord(s); return ok },
			"1Password Cloud Keychain (John $cloudkeychain$)", hashid.TierSignature,
			"record prefix $cloudkeychain$ carrying a salt, an iteration count and a MAC",
			12, "the cloud keychain is what 1Password 4 onwards synchronises, so it is the format a vault taken from a synced device is in", "1password-cloud"),
		predicateProto(isJohnLastPass, "LastPass verifier (John $lastpass$)", hashid.TierSignature,
			"record prefix $lastpass$ carrying an account address, an iteration count and a verifier",
			12, "the verifier is what the LastPass client sends to log in, so it is collectable from a captured session as well as from a local vault", "lastpass"),
		predicateProto(isHTTPDigest, "HTTP Digest authentication (John $response$)", hashid.TierSignature,
			"record prefix $response$ carrying a response, a realm and the request it signed",
			14, "everything but the password travels in the clear, so one observed authentication is the whole record", "http-digest"),
		predicateProto(isSASLDigest, "SASL DIGEST-MD5 (John $DIGEST-MD5$)", hashid.TierSignature,
			"record prefix $DIGEST-MD5$ carrying a response and the exchange it signed",
			10, "DIGEST-MD5 is the SASL mechanism IMAP, SMTP and XMPP servers offered before they moved to TLS and plain authentication", "digest-md5"),
		predicateProto(isEnpass, "Enpass password manager", hashid.TierSignature,
			"record prefix $enpass$ carrying an iteration count and a database page",
			10, "Enpass keeps its vault as a local SQLCipher file, so the record comes from a device or a backup of one rather than from a service", "enpass"),
		predicateProto(isOpenSSLEnc, "File written by `openssl enc`", hashid.TierSignature,
			"record prefix $openssl$ carrying a salt and one encrypted block",
			10, "`openssl enc` is what a shell script reaches for when it needs to encrypt a file, and its derivation is a single digest with no iteration count", "openssl-enc"),
		predicateProto(isPutty, "PuTTY private key (.ppk)", hashid.TierSignature,
			"record prefix $putty$ carrying a MAC, a public blob and an encrypted private blob",
			16, "a .ppk file is what a Windows administrator's SSH key lives in, and its derivation has no salt and no iterations, so one of these is cheap to attack once collected", "putty"),
		predicateProto(isBlackberryES10, "BlackBerry Enterprise Server 10", hashid.TierSignature,
			"record prefix $bbes10$ carrying a digest and a salt",
			8, "BES10 is end-of-life, so these come from archived management databases rather than running servers", "bbes10"),
		predicateProto(isTezos, "Tezos fundraiser wallet", hashid.TierSignature,
			"record prefix $tezos$ carrying a mnemonic, an email address and the wallet it derives",
			12, "the 2017 fundraiser printed the mnemonic and the email on the same PDF as everything else, so whoever holds that document is missing only the password", "tezos"),
		predicateProto(isVDI, "VirtualBox encrypted disk image", hashid.TierSignature,
			"record prefix $vdi$ naming a cipher, two derivations and the key they protect",
			10, "VirtualBox's disk encryption is off by default and enabled per-VM, so it is met on developer and analyst machines rather than on servers", "vdi"),
		predicateProto(isOracleLogon, "Oracle 11g captured logon (John o5logon)", hashid.TierSignature,
			"record prefix $o5logon$ carrying an encrypted session key and its salt",
			14, "the pair travels in the clear in Oracle 11g's first authentication exchange, so watching a single login collects it without any access to the database", "oracle-o5logon"),
		predicateProto(isKrbDBKey, "Kerberos KDC long-term key (John $krb17$ / $krb18$)", hashid.TierSignature,
			"record prefix $krb17$ or $krb18$ carrying a principal salt and a key",
			14, "a KDC database dump yields one of these per principal, and unlike a ticket it is the key itself rather than something encrypted with it", "krb5-key"),
		predicateProto(isJohnMSKrb5, "Kerberos etype-23 pre-authentication (John $mskrb5$)", hashid.TierSignature,
			"record prefix $mskrb5$ carrying a checksum and an encrypted timestamp",
			16, "an AS-REQ with pre-authentication is broadcast on any Active Directory network, so capturing one needs no access at all", "krb5pa"),
		predicateProto(isNetAH, "IPsec AH authenticator (John $net-ah$)", hashid.TierSignature,
			"record prefix $net-ah$ carrying a captured packet and a truncated MAC",
			6, "AH without ESP is rare in modern deployments, so a capture of one is correspondingly rare", "net-ah"),
		predicateProto(isRSVP, "RSVP INTEGRITY object (John $rsvp$)", hashid.TierSignature,
			"record prefix $rsvp$ carrying a captured message and its MAC",
			5, "RSVP is confined to networks doing traffic engineering or MPLS-TE signalling", "rsvp"),
		predicateProto(isOSPF, "OSPFv2 cryptographic authentication (John $ospf$)", hashid.TierSignature,
			"record prefix $ospf$ carrying a captured packet and its MAC",
			12, "OSPF is the interior routing protocol of most enterprise networks, and its authentication key is usually shared across the whole area", "ospf"),
		predicateProto(isAzureAD, "Azure AD Connect synchronised credential", hashid.TierSignature,
			"the v1;PPH1_MD4, prefix, then a salt, a round count and a digest",
			18, "every tenant using password hash synchronisation has one of these per account, and cracking one recovers the on-premises domain password", "azuread"),
		predicateProto(isKnownHosts, "OpenSSH hashed known_hosts entry", hashid.TierSignature,
			"the |1|<salt>|<digest> shape HashKnownHosts writes",
			12, "HashKnownHosts is the default on several distributions, so these turn up in any home directory that has been collected", "known-hosts"),
		// Both word-size variants are offered for each scheme: the record
		// cannot say which build made it, and the two are different digests.
		{
			Types: []string{"dragonfly3-32", "dragonfly3-64"}, Display: "DragonFly BSD SHA-256 crypt",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "record prefix $3$ with a 44-character digest", isDragonfly3(in.Normalized)
			},
			Prevalence: 4,
			Rationale:  "DragonFly BSD is a small platform and this scheme is unsalted and uniterated, so a record is worth about as much as a bare SHA-256",
		},
		{
			Types: []string{"dragonfly4-32", "dragonfly4-64"}, Display: "DragonFly BSD SHA-512 crypt",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "record prefix $4$ with an 84-character digest", isDragonfly4(in.Normalized)
			},
			Prevalence: 4,
			Rationale:  "the same scheme at 512 bits, and the same absence of any work factor",
		},
		{
			Types: []string{"wowsrp"}, Display: "World of Warcraft SRP-6 verifier",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "an account name and a $WoWSRP$ verifier", isWoWSRP(in.Raw)
			},
			Prevalence: 4,
			Rationale:  "a private-server account database; the account name is part of the verifier, so the record carries it",
		},
		{
			Types: []string{"bfegg"}, Display: "Eggdrop IRC bot password",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a plus and twelve base64 characters", isBFEgg(in.Normalized)
			},
			Prevalence: 3,
			Rationale:  "Eggdrop's userfile; the leading plus is its own marker for an encrypted password, which nothing else in this table uses",
		},
		{
			Types: []string{"skey"}, Display: "S/Key one-time password",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a sequence number, a seed and a 64-bit response", isSKey(in.Raw)
			},
			Prevalence: 3,
			Rationale:  "S/Key predates every modern second factor and survives on old Unix hosts; the stored value is the last one-time password used, not a password hash",
		},
		{
			Types: []string{"sunmd5"}, Display: "SunMD5", Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "record prefix $md5$ or $md5, with a 22-character digest", isSunMD5(in.Normalized)
			},
			Prevalence: 8,
			Rationale:  "Solaris 9 and 10 shipped this as the alternative to descrypt, so it appears wherever a Solaris shadow file does",
		},
		{
			Types: []string{"sybase-prop"}, Display: "Sybase PROP", Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "0x and sixty hex characters, which no other record in this table is", isSybasePROP(in.Normalized)
			},
			Prevalence: 3,
			Rationale:  "Sybase Replication Server, not ASE; built out of FEAL-8, a cipher broken in 1994 and used by nothing written since",
		},
		hasPrefixProto("$o3logon$", "Oracle 9i logon exchange", 4,
			"captured from the wire; Oracle encrypts the password under a key derived from the password, so a candidate is checked by decrypting and asking whether what came out is the candidate", "o3logon"),
		hasPrefixProto("$o10glogon$", "Oracle 10g logon exchange", 5,
			"the same idea with AES, and both the server's and the client's session keys in the record because the password's key is the XOR of the two", "o10glogon"),
		hasPrefixProto("$krb5$", "Kerberos 5 TGT (3DES)", 4,
			"a captured ticket with no digest in it; a password is right when the decrypted ticket names the service it is for, which is krbtgt", "krb5-tgt"),
		hasPrefixProto("$kwallet$", "KDE KWallet", 8,
			"the default credential store on KDE desktops; its pre-4.13 derivation hashed the password in sixteen-byte blocks, so a long password bought less than it looked", "kwallet"),
		hasPrefixProto("$V$", "OpenVMS SYSUAF", 4,
			"DEC's password function, still running wherever VMS is; sixty-four bits of output and, unless the account is flagged otherwise, a password upper-cased before hashing", "openvms"),
		hasPrefixProto("$krb3$", "Kerberos 5 DES database key", 4,
			"etype 2 or 3 from a KDC dump; a 56-bit DES key, which finding in a modern KDC says something about the KDC", "krb5-des"),
		hasPrefixProto("$af$", "Kerberos 4 ticket", 3,
			"a captured Kerberos 4 TGT; there is no digest in the record, so a password is right when the decrypted ticket spells \"krbtgt\" where it should", "krb4"),
		hasPrefixProto("$K4$", "AFS KeyFile", 3,
			"an AFS cell's DES key; the derivation takes one path for passwords of eight bytes or fewer and another for longer ones, which is the seam between two implementations", "afs"),
		hasPrefixProto("$geli$", "FreeBSD GELI volume", 5,
			"full-disk encryption on FreeBSD; the passphrase unwraps a master key rather than encrypting the disk, and a volume can hold two independently wrapped copies", "geli"),
		hasPrefixProto("$bks$", "Bouncy Castle keystore", 5,
			"a Java keystore in Bouncy Castle's own format; the BKS variant writes its MAC key length in bits, so a keystore saying 20 has a two-byte key and many passwords produce the right MAC", "bks"),
		hasPrefixProto("$pse$", "SAP Personal Security Environment", 5,
			"an SAP system's private keys; the PIN protecting them is stored encrypted under a key derived from the PIN, so the verifier is the password itself", "sappse"),
		hasPrefixProto("$pgpsda$", "PGP Self-Decrypting Archive", 4,
			"an archive that carries its own decryptor, so it travels by email and survives in inboxes", "pgpsda"),
		hasPrefixProto("$pgpdisk$", "PGP Disk volume", 6,
			"Symantec Encryption Desktop's volume format; the algorithm number in the record dates it, since 3 means CAST5", "pgpdisk"),
		hasPrefixProto("$pgpwde$", "PGP Whole Disk Encryption", 6,
			"full-disk encryption whose record stores no verifier at all — a password is right when the session key it decrypts is correctly OAEP-padded", "pgpwde"),
		hasPrefixProto("$dashlane$", "Dashlane local vault", 5,
			"a password manager's offline vault; a correct key inflates to XML, which arbitrary bytes essentially never do", "dashlane"),
		hasPrefixProto("$padlock$", "Padlock password manager", 3,
			"a browser vault built on SJCL, whose CCM tag is computed over the wrong bytes and so cannot be checked; the plaintext is checked instead", "padlock"),
		hasPrefixProto("$andotp$", "andOTP encrypted backup", 5,
			"an Android authenticator's backup file, encrypted under one unsalted SHA-256 of the password and holding every TOTP secret its owner has", "andotp"),
		hasPrefixProto("$clipperz$", "Clipperz SRP-6a verifier", 3,
			"a web password manager's login verifier; the account name and salt are both inside it", "clipperz"),
		hasPrefixProto("$openbsd-softraid$", "OpenBSD softraid CRYPTO volume", 5,
			"full-disk encryption on OpenBSD; the passphrase masks the volume keys rather than encrypting the volume, which is why changing it is instant", "openbsd-softraid"),
		hasPrefixProto("$lpcli$", "LastPass command-line agent", 5,
			"the lpass tool's local agent key; the salt is the account's email address, so it is public and never rotated", "lastpass-cli"),
		hasPrefixProto("$lp$", "LastPass browser extension", 8,
			"the extension's vault key, salted with the account's email address; the iteration count in the record dates it, since LastPass raised its default from 500 to 5,000 to 100,100 over the years", "lastpass-lp"),
		hasPrefixProto("$keyring$", "GNOME keyring", 10,
			"the default credential store on GNOME desktops, so a Linux workstation image usually has one", "keyring"),
		hasPrefixProto("$strip$", "STRIP password manager", 4,
			"an iPhone password manager backed by SQLCipher; the record is the first page of the database", "strip"),
		hasPrefixProto("$hsrp$", "Cisco HSRP MD5 authentication", 8,
			"a captured HSRP hello; the key is configured identically on every router in the standby group", "hsrp"),
		hasPrefixProto("$vtp$", "Cisco VTP authentication", 6,
			"a captured VTP summary advertisement; unlike its neighbours in this family it stretches the password first, so a candidate costs nearly a megabyte of MD5", "vtp"),
		hasPrefixProto("$cq$", "Rational ClearQuest", 3,
			"an IBM change-management product; the stored verifier is a 32-bit sum with no avalanche, so a match names a family of passwords rather than one", "clearquest"),
		hasPrefixProto("$nk$", "Nuked-Klan portal", 3,
			"a PHP portal of the early 2000s; its site key is shared by every account, so it peppers rather than salts", "nukedklan"),
		hasPrefixProto("$siemens-s7$", "Siemens S7 PLC challenge/response", 8,
			"an industrial controller's authentication exchange, captured from the link; the password protects a PLC rather than an account", "siemens-s7"),
		hasPrefixProto("$BitShares$", "BitShares wallet", 5,
			"a cryptocurrency wallet whose type-0 records encrypt under SHA-512 of the password with no iteration at all, so a candidate costs one hash", "bitshares"),
		{
			Types: []string{"palshop"}, Display: "Palshop",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "fifty-one hex characters, which is not a whole number of bytes", isPalshop(in.Normalized)
			},
			Prevalence: 3,
			Rationale:  "the odd length is the signature: no digest is twenty-five and a half bytes, so nothing else writes a record this shape",
		},
		hasPrefixProto("$sl3$", "Nokia SL3 operator unlock code", 4,
			"SL3 locking belongs to Nokia handsets of the Symbian era; the code is always fifteen digits, so the keyspace is fixed and exhaustible", "sl3"),
		hasPrefixProto("$adxcrypt$", "ADX point-of-sale terminal password", 3,
			"a 32-bit fold printed as eight digits, whose own reference vectors include a collision noted as working on a real terminal", "adxcrypt"),
		{
			Types: []string{"epi"}, Display: "EPI salted SHA-1",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "two 0x-prefixed hex fields, a 30-byte salt and a SHA-1", isEPI(in.Normalized)
			},
			Prevalence: 3,
			Rationale:  "a single vendor's presentation software; nothing else writes a record in this shape",
		},
		{
			Types: []string{"leet"}, Display: "leet: SHA-512 XOR Whirlpool",
			Tier: hashid.TierShape,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a salt, a dollar and a 512-bit digest", isLeet(in.Normalized)
			},
			Prevalence: 3,
			Rationale:  "the shape is what a plain salted SHA-512 looks like, so this is offered alongside that reading rather than instead of it",
		},
		hasPrefixProto("$pst$", "Outlook personal-folders password", 8,
			"a .pst from any Outlook of the last twenty years can carry one, and the check behind it is a 32-bit CRC rather than a password hash", "pst"),
		hasPrefixProto("$money$", "Microsoft Money file password", 4,
			"Money was discontinued in 2009; the files that survive are personal archives", "money"),
		hasPrefixProto("$radius$", "RADIUS shared secret", 10,
			"what is recovered is the secret between a RADIUS client and its server, not the user's password — that is written in the record", "radius"),
		hasPrefixProto("$zipmonster$", "ZipMonster", 3,
			"ZipMonster is a single Windows archiving tool with a small user base", "zipmonster"),
		predicateProto(isDummy, "John's dummy format", hashid.TierSignature,
			"record prefix $dummy$ followed by the password in hex",
			1, "this is a test format rather than a scheme anything stores passwords with", "dummy"),
		predicateProto(func(s string) bool { _, _, _, ok := johnP5K2Record(s); return ok },
			"Passlib PBKDF2-HMAC-SHA1 ($p5k2$)", hashid.TierSignature,
			"record prefix $p5k2$ carrying hex rounds, a salt and a digest",
			8, "Passlib's cta_pbkdf2_sha1 appears in Python applications that took Passlib's older defaults", "p5k2"),
		predicateProto(func(s string) bool { _, ok := johnIKERecord(s); return ok },
			"IKE aggressive-mode PSK (John $ike$)", hashid.TierSignature,
			"record prefix $ike$ carrying the ten fields of an aggressive-mode exchange",
			10, "an aggressive-mode exchange hands the responder's hash to anyone who asks, so a capture is cheap wherever IKEv1 is still configured", "ike"),
		predicateProto(func(s string) bool { _, ok := johnOldOfficeRecord(s); return ok },
			"Office 97-2003 on John's line (username and RC4 key around it)", hashid.TierSignature,
			"an $oldoffice$ record with a username before it or a decryption key after it",
			14, "office2john writes this line for any pre-2007 document, which is still the format a great many archived files are in", "office-old"),
		// John's TrueCrypt spelling names the PRF in the prefix, so each of
		// these resolves to one type rather than to the generic reader that
		// tries all three derivations per candidate.
		hasPrefixProto("truecrypt_RIPEMD_160_BOOT$", "TrueCrypt boot volume, RIPEMD-160 (John)", 8,
			"a boot-mode header comes from a system-encrypted volume, which is a smaller share of TrueCrypt volumes than data volumes", "truecrypt-ripemd160-boot-xts512"),
		hasPrefixProto("truecrypt_RIPEMD_160$", "TrueCrypt, RIPEMD-160 (John)", 20,
			"RIPEMD-160 was TrueCrypt's default derivation, so most volumes in circulation use it", "truecrypt-ripemd160"),
		hasPrefixProto("truecrypt_SHA_512$", "TrueCrypt, SHA-512 (John)", 12,
			"SHA-512 was an option rather than the default, chosen by users who changed it deliberately", "truecrypt-sha512"),
		hasPrefixProto("truecrypt_WHIRLPOOL$", "TrueCrypt, Whirlpool (John)", 8,
			"Whirlpool was the least chosen of TrueCrypt's three derivations", "truecrypt-whirlpool"),
		// The two macOS hashes that predate PBKDF2 are a salt and a digest
		// run together, so their length is the whole signature — and a length
		// is not proof. Forty-eight hex characters is also a Tiger-192
		// digest, and neither tool can tell those apart either: hashcat wants
		// -m 122 and John wants --format=xsha. So these are offered rather
		// than asserted, and left NOT exclusive, so that naming this shape
		// does not silence whatever else could claim it.
		{
			Types: []string{"xsha"}, Display: "macOS 10.4-10.6 salted SHA-1",
			Tier: hashid.TierStructural,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "48 hex characters: a four-byte salt followed by a SHA-1 — the length of a Tiger-192 digest too", isXSHA(in.Normalized)
			},
			Prevalence: 10,
			Rationale:  "these come from machines running 10.6 or older, or from backups of them, rather than from anything current",
		},
		{
			Types: []string{"xsha512"}, Display: "macOS 10.7 salted SHA-512",
			Tier: hashid.TierStructural,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "136 hex characters: a four-byte salt followed by a SHA-512", isXSHA512(in.Normalized)
			},
			Prevalence: 10,
			Rationale:  "10.7 used this for one release before 10.8 replaced it with PBKDF2, so the window it comes from is narrow",
		},
		// John's envelopes for the same four exchanges. Each is a literal
		// prefix plus a field count that has to be right, so a record that
		// merely starts with the name is not claimed.
		predicateProto(func(s string) bool { _, ok := johnNetEnvelope(s, "$NETLM$", 2); return ok },
			"NetLM captured LM response (John $NETLM$)", hashid.TierSignature,
			"record prefix $NETLM$ carrying a challenge and a 24-byte response",
			8, "an LM response means a client old enough to still send one, which on a modern network is a misconfiguration rather than the default", "netlm"),
		predicateProto(func(s string) bool { _, ok := johnNetEnvelope(s, "$NETHALFLM$", 2); return ok },
			"NetHalfLM captured half response (John $NETHALFLM$)", hashid.TierSignature,
			"record prefix $NETHALFLM$ carrying a challenge and a response",
			6, "the half response is what a capture yields when only the first eight bytes survived, a narrower case than the full one", "nethalflm"),
		predicateProto(func(s string) bool { _, ok := johnNetEnvelope(s, "$NETLMv2$", 4); return ok },
			"NetLMv2 captured LMv2 response (John $NETLMv2$)", hashid.TierSignature,
			"record prefix $NETLMv2$ carrying an identity, a challenge, a response and a client challenge",
			10, "LMv2 is sent alongside NTLMv2 by clients configured for both, so a capture of one often carries the other", "netlmv2"),
		predicateProto(func(s string) bool { _, ok := johnNetEnvelope(s, "$MSCHAPv2$", 4); return ok },
			"MS-CHAPv2 (John $MSCHAPv2$)", hashid.TierSignature,
			"record prefix $MSCHAPv2$ carrying two challenges, a response and a username",
			14, "MS-CHAPv2 is the authentication behind PPTP and behind PEAP-MSCHAPv2 on enterprise wireless, so it is captured from the air as well as from the wire", "mschapv2"),
		// A captured line has no fixed prefix — six colon-separated fields
		// with an empty second one — so TierStructural. Six formats share
		// that layout and the field lengths are what tell them apart, which
		// is a calculated answer rather than a fixed one, so Compute rather
		// than Types. See netCaptureTypes for the readings and for what it
		// does with a shape that leaves a real ambiguity.
		{
			Display: "NetNTLM captured challenge/response", Tier: hashid.TierStructural,
			Exclusive: true,
			Compute: func(in hashid.Input) ([]string, bool) {
				types := netCaptureTypes(in.Normalized)
				return types, len(types) > 0
			},
			Prevalence: 25,
			Rationale:  "NetNTLM captures from Responder/relay tooling remain a routine finding in internal network penetration tests, with NetNTLMv2 the modern default most current Windows clients negotiate",
		},
		// reBcrypt, reArgon2, reScrypt, rePostgres and reMySQL41 are compiled
		// regexps rather than predicate functions, but a *regexp.Regexp's
		// MatchString method already has the func(string) bool shape
		// predicateProto wants, so each is wrapped directly.
		//
		// reBcrypt (`^\$2[aby]\$\d{2}\$`) anchors on a literal $2a$/$2b$/$2y$
		// scheme tag, so TierSignature.
		// $2x$ is bcrypt too, and is deliberately NOT in reBcrypt: the
		// schedule behind it differs, so a $2x$ record answered by the
		// ordinary bcrypt verifier would simply never match. It gets its own
		// entry and its own type.
		predicateProto(isBcryptSignExt, "bcrypt, sign-extension variant", hashid.TierSignature,
			`record prefix $2x$ followed by a 2-digit cost`,
			6, "$2x$ marks a record deliberately kept on crypt_blowfish's buggy schedule rather than migrated to $2y$, so it is rare and the password behind one is likelier than average to be non-ASCII", "bcrypt-2x"),
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
		// The 94-char 0x0100 record is SQL Server 2000's, which stores the
		// case-sensitive AND case-insensitive digests. It shares its tag with
		// the 54-char 2005 record below but is disjoint from it by length, so
		// both can be TierSignature without colliding.
		{
			Types: []string{"mssql2000"}, Display: "SQL Server 2000 password hash (both digests)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if reMSSQL2000.MatchString(in.Normalized) {
					return "record prefix 0x0100 (case-insensitive) with a fixed 94-char total length", true
				}
				return "", false
			},
			Prevalence: 12, Rationale: "SQL Server 2000 master..sysxlogins dumps still surface in legacy estates, and their case-insensitive digest is the weaker of the two",
		},
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
		// BSDi extended crypt is a STRUCTURAL match, not a shape one: the
		// leading '_' is a distinguished marker character no other crypt-64
		// record carries, which is more than "length and alphabet" and is why
		// it sits a tier above traditional DES crypt below. It also cannot be
		// confused with it — 20 characters against 13, and descrypt has no
		// prefix at all.
		predicateProto(looksLikeBSDiCrypt, "BSDi extended DES crypt", hashid.TierStructural,
			"leading '_', then 19 crypt-64 chars: 4 of iteration count, 4 of salt, 11 of result",
			8, "BSDi's extended crypt was the 4.4BSD answer to descrypt's fixed 25 rounds and 8-character limit, so it appears in BSD-lineage and embedded shadow files rather than in Linux ones", "bsdicrypt"),
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
