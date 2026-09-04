package main

import (
	"hashsmith-go/internal/hashid"
	"strings"
)

// batchBPrototypes ports the archive- and container-record branches of the
// legacy cascade: $zipcrypto$ through $office$2016$0$ (original lines
// 1499-1577). Every entry here is a literal record prefix except isPDFR6,
// which also decodes the revision field, and the two $vbox$ entries, which
// reproduce a nested `if` — the $16$-bearing prototype is listed first so
// table order keeps the more specific match's precedence.
func batchBPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		hasPrefixProto("$zipcrypto$", "ZipCrypto archive entry", 45,
			"the default legacy ZIP password scheme before AE-1/AE-2 AES support; still the most common ZIP password format encountered", "zipcrypto"),
		hasPrefixProto("$zipaes128$", "WinZip AES-128 archive entry", 15,
			"WinZip's AE-1 128-bit variant; less common than the AE-2 256-bit default most tools now write", "zipaes128"),
		hasPrefixProto("$zipaes192$", "WinZip AES-192 archive entry", 5,
			"AES-192 is valid under the ZIP AE-2 spec but no mainstream archiver UI offers it, so it is rarely seen outside crafted test vectors", "zipaes192"),
		hasPrefixProto("$zipaes256$", "WinZip AES-256 archive entry", 35,
			"WinZip's AE-2 256-bit variant is the modern default for AES-encrypted ZIP archives", "zipaes256"),
		hasPrefixProto("$7z$", "7-Zip archive", 35,
			"7-Zip is one of the most widely used general-purpose archivers outside Windows-native ZIP", "7z"),
		// The legacy branch tests two literal prefixes ("$rar3$" and "$RAR3$")
		// for the same RAR 3.x/4.x record in one `if`; kept as one prototype
		// here so the coverage-case count tracks the single cascade branch it
		// replaces, rather than splitting it into two for no behavioral reason.
		{
			Types: []string{"rar4"}, Display: "RAR 3.x/4.x archive",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$rar3$") || strings.HasPrefix(in.Normalized, "$RAR3$") {
					return "record prefix $rar3$ or $RAR3$", true
				}
				return "", false
			},
			Prevalence: 20, Rationale: "RAR 3.x/4.x's older fixed-parameter hash is still found in older archives even though RAR5 has been the default since 2017",
		},
		hasPrefixProto("$rar5$", "RAR5 archive", 30,
			"RAR5 has been WinRAR's default archive format since 2017", "rar5"),
		// isPDFR6 checks the "$pdf$" prefix, then splits the record on '*' and
		// requires at least 9 fields with the revision field (index 1, the
		// second '*'-delimited field) equal to "5" or "6" — a prefix check plus
		// decoded fields, so TierSignature rather than a full parse.
		predicateProto(isPDFR6, "PDF revision 5/6 (AES-256)", hashid.TierSignature,
			"$pdf$ record with at least 9 '*'-delimited fields and a revision field (the second field) of 5 or 6",
			25, "PDF revision 5/6 (AES-256) is the default for PDF 2.0 and Acrobat X/XI+ generated encrypted PDFs", "pdf-r6"),
		hasPrefixProto("$pdf$", "PDF encrypted document", 30,
			"the general $pdf$ record covers the older RC4/AES-128 PDF encryption revisions still produced by many PDF libraries", "pdf"),
		hasPrefixProto("$ssh$", "OpenSSH private key", 25,
			"OpenSSH encrypted private keys are a routine target wherever SSH key material is seized", "ssh"),
		hasPrefixProto("$sshng$", "SSH private key (new format)", 20,
			"the newer OpenSSH key format (bcrypt-pbkdf, post-6.5) now covers most freshly generated OpenSSH keys", "ssh"),
		hasPrefixProto("$pkcs8$", "PKCS#8 encrypted private key", 15,
			"encrypted PKCS#8 private keys are a narrow but recurring target wherever raw key files, not keystores, are seized", "pkcs8"),
		hasPrefixProto("$PEM$1$", "PKCS#8 PEM (SHA-1 KDF)", 8,
			"the legacy SHA-1 KDF variant of this project's PKCS#8 PEM format, mostly superseded by the SHA-256 variant", "pkcs8-pem-sha1"),
		hasPrefixProto("$PEM$2$", "PKCS#8 PEM (SHA-256 KDF)", 10,
			"the SHA-256 KDF variant of this project's PKCS#8 PEM format; the newer of the two and modestly more common", "pkcs8-pem-sha256"),
		hasPrefixProto("$jksprivk$*", "Java KeyStore private key", 15,
			"Java KeyStore private-key entries recur wherever a Java application's secrets are extracted", "jks-private-key"),
		hasPrefixProto("$vmx$", "VMware VMX config password", 8,
			"VMware .vmx encrypted config passwords are a narrow VM-forensics target", "vmware-vmx"),
		hasPrefixProto("$ab$", "Android backup", 15,
			"Android's adb backup encryption is a routine target in mobile forensic examinations", "android-backup"),
		hasPrefixProto("$encfs$", "EncFS volume", 8,
			"EncFS is a niche Linux user-space encrypted filesystem with a shrinking user base", "encfs"),
		hasPrefixProto("$mozilla$*", "Mozilla NSS master password", 15,
			"Firefox/Thunderbird's NSS master-password hash recurs in browser-profile forensic work", "mozilla-nss"),
		// $vbox$ is nested in the legacy cascade: a record containing "$16$"
		// selects virtualbox-aes256, otherwise virtualbox-aes128. The two
		// prototypes below reproduce that precedence via table order — the
		// $16$-bearing one is listed first, so it wins outright (the earliest
		// Exclusive match in table order suppresses every later one) whenever
		// both would otherwise match.
		{
			Types: []string{"virtualbox-aes256"}, Display: "VirtualBox VM disk (AES-256)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$vbox$") && strings.Contains(in.Normalized, "$16$") {
					return "record prefix $vbox$ with a $16$ cipher-bits field", true
				}
				return "", false
			},
			Prevalence: 12, Rationale: "AES-256 is VirtualBox's current default VM disk-encryption cipher",
		},
		hasPrefixProto("$vbox$", "VirtualBox VM disk (AES-128)", 8,
			"AES-128 was VirtualBox's older VM disk-encryption default, now superseded by AES-256", "virtualbox-aes128"),
		hasPrefixProto("$metamask-short$", "MetaMask vault (short form)", 8,
			"MetaMask's short vault export variant appears alongside, but less often than, the full vault format", "metamask-short"),
		hasPrefixProto("$metamask$", "MetaMask vault", 20,
			"MetaMask is the most widely used browser crypto wallet, making its vault export a common cracking target", "metamask"),
		hasPrefixProto("EXODUS:", "Exodus wallet export", 10,
			"Exodus is a less widely used desktop wallet than MetaMask but recurs in crypto-wallet cracking work", "exodus"),
		hasPrefixProto("$gpg$", "GPG/PGP private key", 30,
			"GPG/PGP private key encryption is a routine target in both forensic and CTF password-cracking work", "gpg"),
		hasPrefixProto("$office$2016$0$", "Office 2016 workbook protection", 12,
			"the $office$2016$0$ variant specifically covers Excel workbook-protection passwords, narrower than the general Office 2016 record", "office2016-sheet"),
	}
}

// batchCPrototypes ports the office, directory and vendor-record branches of
// the legacy cascade: $oldoffice$0* through $chacha20$* (original lines
// 1463-1533). Every entry here is a literal record-prefix test; six of them
// reproduce a legacy `if` that tested two or three alternative prefixes for
// the same type in one condition and are kept as one hand-written prototype
// each, so the coverage-case count still tracks the branch count the legacy
// cascade had, not the number of alternative prefixes within it.
func batchCPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// The legacy branch tests "$oldoffice$0*" and "$oldoffice$1*" (the
		// RC4+MD5 verifier, Hashcat mode 9700) in one `if`.
		{
			Types: []string{"office-old-md5"}, Display: "MS Office 97-2003 (RC4/MD5)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$oldoffice$0*") || strings.HasPrefix(in.Normalized, "$oldoffice$1*") {
					return "record prefix $oldoffice$0* or $oldoffice$1*", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "$oldoffice$ type 0/1 is Hashcat mode 9700, the RC4+MD5 verifier for MS Office 97-2003 documents; Office kept producing this format through the 2007 release, so it still surfaces in older document collections",
		},
		// Likewise "$oldoffice$3*"/"$oldoffice$4*" for the RC4+SHA-1 verifier.
		{
			Types: []string{"office-old-sha1"}, Display: "MS Office 97-2003 (RC4/SHA-1)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$oldoffice$3*") || strings.HasPrefix(in.Normalized, "$oldoffice$4*") {
					return "record prefix $oldoffice$3* or $oldoffice$4*", true
				}
				return "", false
			},
			Prevalence: 10, Rationale: "$oldoffice$ type 3/4 is Hashcat mode 9800, the RC4+SHA-1 verifier for the same 97-2003 encryption; seen less often than the MD5 variant above because most legacy oldoffice dumps predate the SHA-1 revision",
		},
		hasPrefixProto("$office$", "MS Office 2007/2010/2013", 30,
			"the $office$ record spans Hashcat modes 9400-9600, covering three consecutive Office releases, giving it more real-world coverage than either single-release $oldoffice$ variant above", "office"),
		hasPrefixProto("$mysqlna$", "MySQL CRAM-SHA1 auth", 10,
			"MySQL's CRAM-SHA1 authentication response (Hashcat mode 11200) requires capturing a live auth exchange rather than an offline hash dump, which limits how often it turns up", "mysql-cram"),
		hasPrefixProto("$tacacs-plus$", "TACACS+ authentication", 15,
			"TACACS+ (Hashcat mode 16100) is Cisco's standard AAA protocol for device administration, so it recurs wherever Cisco network-device auth traffic is captured", "tacacs-plus"),
		hasPrefixProto("$ASN$*", "Apple Secure Notes", 8,
			"Apple Secure Notes' wrapped-key verifier (Hashcat mode 16200) only appears when a user has enabled the rarely-used per-note password feature", "apple-secure-notes"),
		hasPrefixProto("otm_sha256:", "Oracle Transportation Management", 5,
			"Oracle Transportation Management's iterated SHA-256 hash (Hashcat mode 20600) is specific to one enterprise logistics product with a narrow customer base", "oracle-otm"),
		hasPrefixProto("$xmpp-scram$", "XMPP SCRAM stored key", 10,
			"XMPP SCRAM PBKDF2-SHA1 stored keys (Hashcat mode 23200) appear only where an XMPP server's own authentication database is captured, a narrower target than XMPP's overall deployment", "xmpp-scram"),
		hasPrefixProto("$postgres$", "PostgreSQL CRAM-MD5 auth", 20,
			"PostgreSQL's MD5 challenge-response (Hashcat mode 11100) was the default auth method before SCRAM-SHA-256 arrived in PostgreSQL 10, and many self-hosted instances still run with it", "postgres-cram"),
		hasPrefixProto("$SNMPv3$", "SNMPv3 USM auth", 10,
			"SNMPv3 USM auth (Hashcat modes 25000/25100) is less common than legacy SNMP v1/v2c community-string captures, since many network deployments never migrated off the weaker versions", "snmpv3"),
		// The legacy branch tests "@m@" and "@m," in one `if` for QNX's
		// /etc/shadow MD5 hash (Hashcat mode 19000).
		{
			Types: []string{"qnx-md5"}, Display: "QNX shadow hash (MD5)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "@m@") || strings.HasPrefix(in.Normalized, "@m,") {
					return "record prefix @m@ or @m,", true
				}
				return "", false
			},
			Prevalence: 6, Rationale: "QNX is a niche embedded/real-time OS; its /etc/shadow MD5 hash (Hashcat mode 19000) is seen almost exclusively in QNX-specific device forensics",
		},
		// Likewise "@s@"/"@s," for the SHA-256 variant.
		{
			Types: []string{"qnx-sha256"}, Display: "QNX shadow hash (SHA-256)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "@s@") || strings.HasPrefix(in.Normalized, "@s,") {
					return "record prefix @s@ or @s,", true
				}
				return "", false
			},
			Prevalence: 6, Rationale: "the SHA-256 variant of QNX's shadow hash (Hashcat mode 19100); the same narrow QNX embedded install base as the MD5 variant above",
		},
		// Likewise "@S@"/"@S," for the SHA-512 variant.
		{
			Types: []string{"qnx-sha512"}, Display: "QNX shadow hash (SHA-512)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "@S@") || strings.HasPrefix(in.Normalized, "@S,") {
					return "record prefix @S@ or @S,", true
				}
				return "", false
			},
			Prevalence: 6, Rationale: "the SHA-512 variant of QNX's shadow hash (Hashcat mode 19200); the same narrow QNX embedded install base as the other two variants",
		},
		hasPrefixProto("{x-issha, ", "LDAP {x-issha} (SAP CODVN H)", 15,
			"{x-issha} (Hashcat mode 10300) was a common LDAP password scheme in SAP/Netscape/iPlanet-derived directory servers before the SHA-256/384 successors below existed", "sap-issha1"),
		hasPrefixProto("{x-isSHA256, ", "LDAP {x-isSHA256} (SAP CODVN H)", 10,
			"the {x-isSHA256} successor requires a newer directory server version than {x-issha}, so it is seen less often than the original SHA-1 form above", "sap-issha256"),
		hasPrefixProto("{x-isSHA384, ", "LDAP {x-isSHA384} (SAP CODVN H)", 6,
			"{x-isSHA384} is the least-adopted of this family's variants; directories upgrading past SHA-1 more commonly land on {x-isSHA256} first", "sap-issha384"),
		hasPrefixProto("$stellar$", "Stellar wallet (Stargazer)", 8,
			"Stargazer Stellar wallet hashes (Hashcat mode 25500) recur far less often in wallet-cracking casework than Bitcoin/Ethereum-family wallets, reflecting Stellar's smaller share of cryptocurrency usage", "stellar-wallet"),
		hasPrefixProto("$telegram$0*", "Telegram mobile passcode", 10,
			"Telegram's mobile-app SHA-256 passcode (Hashcat mode 22301) requires the user to have enabled the optional in-app passcode lock, a setting most Telegram users leave off", "telegram-passcode"),
		// The legacy branch tests "$telegram$1*" and "$telegram$2*" in one
		// `if` for Telegram Desktop's tdata local-storage encryption.
		{
			Types: []string{"telegram-desktop"}, Display: "Telegram Desktop local storage",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$telegram$1*") || strings.HasPrefix(in.Normalized, "$telegram$2*") {
					return "record prefix $telegram$1* or $telegram$2*", true
				}
				return "", false
			},
			Prevalence: 15, Rationale: "Telegram Desktop's tdata local-storage encryption has protected the local session by default since Telegram Desktop's release, making it the more commonly recovered of the two Telegram record shapes here",
		},
		hasPrefixProto("$signal$", "Signal local master password", 15,
			"Signal is one of the most widely used end-to-end-encrypted messengers, so its stored local master password recurs in messaging-app forensic work", "signal"),
		hasPrefixProto("$keychain$*", "macOS login keychain", 25,
			"the login keychain exists on essentially every Mac by default, making it one of the most routinely recovered credential stores in macOS forensic work", "macos-keychain"),
		hasPrefixProto("$vnc$*", "VNC RFB DES challenge-response", 20,
			"VNC's RFB DES challenge-response scheme has been unchanged since the original AT&T implementation and remains common wherever VNC is used for remote administration", "vnc"),
		hasPrefixProto("$sm3$", "sm3crypt", 6,
			"SM3 is a Chinese national cryptographic standard (GB/T 32905); sm3crypt records are essentially confined to systems built for Chinese cryptography compliance and rare elsewhere", "sm3crypt"),
		hasPrefixProto("$chacha20$*", "ChaCha20 known-plaintext verifier", 8,
			"the ChaCha20 known-plaintext verifier (Hashcat mode 15400) targets a specific project-defined record shape rather than a widely deployed application format, so it is rarely seen outside crafted test cases", "chacha20"),
	}
}

// batchDPrototypes ports the remaining office, directory and vendor-record
// branches of the legacy cascade: {CRAM-MD5} through $keepass$ (original
// lines 1463-1529). This half holds every compound branch in the range —
// prefix-plus-length-plus-composition checks, a predicate matched against a
// different input form than its first occurrence, and several branches with
// no fixed prefix at all — each reproduced with a hand-written Match rather
// than simplified into a prefix check.
func batchDPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// The legacy branch requires all three: the "{CRAM-MD5}" prefix, an
		// exact total length (prefix + 64 hex chars), and the remainder being
		// hex. A prefix check plus a decoded field, so TierSignature.
		{
			Types: []string{"dovecot-cram-md5"}, Display: "Dovecot CRAM-MD5",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				const prefix = "{CRAM-MD5}"
				if strings.HasPrefix(in.Normalized, prefix) && len(in.Normalized) == len(prefix)+64 && isHex(in.Normalized[len(prefix):]) {
					return "record prefix {CRAM-MD5} followed by exactly 64 hex chars", true
				}
				return "", false
			},
			Prevalence: 10, Rationale: "Dovecot's CRAM-MD5 chaining-state record (Hashcat mode 16400) is one option among several Dovecot password-scheme choices, not the IMAP server's default",
		},
		hasPrefixProto("$sntp-ms$", "Microsoft SNTP", 6,
			"Microsoft SNTP MD5(NT-hash||packet) (Hashcat mode 31300) only appears where an SNTP exchange with an AD-joined host was captured on the wire, a narrow capture scenario compared to on-disk credential dumps", "ms-sntp"),
		// This is isNSEC3Record's second occurrence in the cascade. The first
		// (batchA) is checked against Input.Raw, before shadow-username
		// stripping, because the colon-delimited Hashcat NSEC3 form can
		// collide with a "user:13-char-des-crypt" shadow line. This second
		// occurrence checks the same predicate against the stripped
		// Normalized form. Same predicate as batchA, so the same tier:
		// parseNSEC3 fully validates field count, field lengths and
		// encodings for both its John and Hashcat forms, which is
		// TierStructural by definition, not TierSignature — the Hashcat
		// colon form carries no fixed literal prefix at all.
		//
		// This entry can never win a table evaluation, and neither could the
		// branch it mirrors in the original cascade: stripShadowUsername
		// only strips when the record's second colon-field looks like a
		// crypt(3) hash, so it never touches a John $NSEC3$ record, and on
		// the Hashcat 4-field colon form, stripping (when it fires at all)
		// leaves a single field that cannot reparse as a 4-field NSEC3
		// record either. So isNSEC3Record(Raw) and isNSEC3Record(Normalized)
		// always agree, and batchA's earlier, Raw-based entry always wins
		// first. Kept anyway: the port's job is to reproduce the cascade
		// exactly, including its dead branches, not to prune them — pruning
		// an apparently-dead branch is a deliberate decision for a dedicated
		// review pass, not something that should ride along inside a port.
		predicateProto(isNSEC3Record, "DNSSEC NSEC3 (post shadow-strip)", hashid.TierStructural,
			"parses (after shadow-username stripping) as either a John $NSEC3$ record or a Hashcat digest:domain:salt:iterations record",
			3, "mirrors a cascade branch that can never fire as a winner: stripShadowUsername cannot turn a non-NSEC3-parsing Raw string into an NSEC3-parsing Normalized one, so batchA's Raw-based entry always matches first; kept for cascade fidelity, not because this occurrence is independently reachable", "dnssec-nsec3"),
		// The legacy branch requires both: parseOracleH succeeding (the
		// record fully decodes into a 16-char hex digest and a 1-30 byte
		// username) AND the record additionally carrying the "O$" prefix.
		// parseOracleH also accepts a colon-delimited "digest:username" form
		// with no prefix at all, but this branch only fires for the
		// John-style O$ form. A prefix check plus decoded fields, so
		// TierSignature.
		{
			Types: []string{"oracle-h"}, Display: "Oracle H-type (O$ form)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if _, _, ok := parseOracleH(in.Normalized); ok && strings.HasPrefix(in.Normalized, "O$") {
					return "record prefix O$ followed by a username#digest body that decodes to a 16-char hex DES digest", true
				}
				return "", false
			},
			Prevalence: 6, Rationale: "Oracle 7-10g H-type DES hashes (Hashcat mode 3100 / John oracle) recur in legacy Oracle DB forensic work, but many captured records use the plain digest:username form without the O$ prefix this branch requires, so this branch only covers the John-style minority",
		},
		hasPrefixProto("$radmin3$", "Radmin3 SHA-1/SRP verifier", 8,
			"Radmin3 (Hashcat mode 29200) is one specific remote-administration product whose market share has shrunk as RDP became the default for Windows remote access", "radmin3"),
		// No fixed prefix: only an exact total length (137), a literal first
		// byte ('2'), and hex composition of the rest. TierStructural.
		{
			Types: []string{"citrix-sha512"}, Display: "Citrix NetScaler salted SHA-512",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if len(in.Normalized) == 137 && in.Normalized[0] == '2' && isHex(in.Normalized[1:]) {
					return "137-char record starting with '2', the remaining 136 chars hex", true
				}
				return "", false
			},
			Prevalence: 6, Rationale: "Citrix NetScaler's salted SHA-512 (Hashcat mode 22200) is specific to Citrix ADC/NetScaler deployments, a narrower footprint than the Linux crypt(3) SHA variants it structurally resembles",
		},
		// Fixed literal 3-char prefix ("SH2") plus an exact total length
		// (63). The prefix is what makes this a signature, not merely
		// structural — unlike the two hex-composition branches above and
		// below, which have no literal prefix at all.
		{
			Types: []string{"fortigate256"}, Display: "FortiGate/FortiOS salted SHA-256",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if len(in.Normalized) == 63 && strings.HasPrefix(in.Normalized, "SH2") {
					return "record prefix SH2 with a fixed 63-char total length", true
				}
				return "", false
			},
			Prevalence: 8, Rationale: "FortiGate/FortiOS salted SHA-256 (Hashcat mode 26300) recurs wherever a FortiGate firewall's local admin database is extracted, a narrower target than general-purpose Linux shadow files",
		},
		hasPrefixProto("$vbk$*", "Veeam VBK backup password", 6,
			"Veeam VBK backup password records (Hashcat mode 31200) surface specifically in Veeam backup-infrastructure engagements, a narrow slice of enterprise backup-tool casework", "veeam-vbk"),
		hasPrefixProto("$MSONLINEACCOUNT$0$", "Microsoft Online Account", 5,
			"the Microsoft Online Account PBKDF2-SHA256 + AES-256 record (Hashcat mode 33700) is specific to legacy Microsoft/Skype account exports, a shrinking target as Microsoft consolidates local caches on Entra ID auth", "ms-online-account"),
		hasPrefixProto(`S:"Config Passphrase"=02:`, "SecureCRT MasterPassphrase v2", 6,
			"the SecureCRT MasterPassphrase v2 record (Hashcat mode 31400) only appears in SecureCRT/SecureFX config-file extraction, one specific terminal-emulator product", "securecrt-v2"),
		hasPrefixProto("$knx-ip-secure-device-authentication-code$*", "KNX IP Secure device auth code", 4,
			"the KNX IP Secure device authentication code (Hashcat mode 25900) is confined to KNX building-automation gateway deployments, a small slice of industrial/IoT casework", "knx-ip-secure"),
		hasPrefixProto("$teamspeak$3$", "TeamSpeak 3 channel hash", 10,
			"the TeamSpeak 3 channel hash (Hashcat mode 28300) recurs wherever a TeamSpeak 3 server database is seized; TeamSpeak remains a common self-hosted voice server for gaming communities", "teamspeak3"),
		hasPrefixProto("$bcrypt-sha256$", "Passlib bcrypt-sha256", 10,
			"Passlib's bcrypt(HMAC-SHA256(password)) wrapper (Hashcat mode 30601) exists specifically to work around bcrypt's 72-byte input truncation, so it appears only in Python/Passlib-backed applications that opted into that wrapper", "passlib-bcrypt-sha256"),
		// Full parse: three colon-delimited fields, the first equal to the
		// literal "sha256" (effectively a "sha256:" record prefix), and the
		// remaining two fields each exactly 64 hex chars. Field count,
		// lengths and encodings all agree, so TierSignature.
		{
			Types: []string{"anope-sha256"}, Display: "Anope IRC Services enc_sha256",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				fields := strings.Split(in.Normalized, ":")
				if len(fields) == 3 && fields[0] == "sha256" &&
					len(fields[1]) == 64 && isHex(fields[1]) && len(fields[2]) == 64 && isHex(fields[2]) {
					return "record prefix sha256: followed by two 64-char hex fields", true
				}
				return "", false
			},
			Prevalence: 4, Rationale: "Anope IRC Services' enc_sha256 stored-account state (Hashcat mode 30700) is specific to one IRC services package among several competing implementations (Atheme, ircservices)",
		},
		// No fixed prefix: only an exact total length (129), a literal first
		// byte ('5'), and hex composition of the rest. TierStructural.
		{
			Types: []string{"citrix-pbkdf2"}, Display: "Citrix NetScaler PBKDF2-SHA256",
			Tier: hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if len(in.Normalized) == 129 && in.Normalized[0] == '5' && isHex(in.Normalized[1:]) {
					return "129-char record starting with '5', the remaining 128 chars hex", true
				}
				return "", false
			},
			Prevalence: 6, Rationale: "Citrix NetScaler's newer PBKDF2-HMAC-SHA256 record (Hashcat mode 33900) is displacing the older salted-SHA512 form above on current NetScaler builds, but the installed base still runs a mix of both",
		},
		// isUmbracoHMACSHA1 checks only an exact length (28) and that the
		// record base64-decodes to exactly a SHA-1-sized (20-byte) digest —
		// no fixed prefix, so TierStructural rather than TierSignature.
		predicateProto(isUmbracoHMACSHA1, "Umbraco HMAC-SHA1", hashid.TierStructural,
			"28-char record that base64-decodes to exactly a 20-byte digest",
			4, "Umbraco HMAC-SHA1 over a UTF-16LE password (Hashcat mode 24800) is confined to sites built on the Umbraco CMS, a mid-tier .NET CMS with a far smaller install base than WordPress", "umbraco-hmac-sha1"),
		hasPrefixProto("$AWS-Sig-v4$", "AWS Signature v4", 12,
			"AWS Signature Version 4 (Hashcat mode 28700) appears wherever an AWS SigV4-signed request has been captured; SigV4 is the default signing scheme across all current AWS SDKs and the CLI", "aws-sig-v4"),
		// isTOTPRecord checks field count (2-8, even), then for each pair
		// that the first field is exactly 6 chars and numeric and the second
		// parses as a uint64 timestamp — field count, field lengths and
		// encodings (numeric parse) all agree, so TierStructural. No fixed
		// prefix distinguishes a TOTP code/timestamp pair from any other
		// colon-delimited digit sequence.
		predicateProto(isTOTPRecord, "TOTP code/timestamp pairs", hashid.TierStructural,
			"2-8 colon-delimited fields in alternating (6-digit numeric code, numeric timestamp) pairs",
			5, "TOTP HMAC-SHA1 code/timestamp verification (Hashcat mode 18100) requires a captured code alongside its Unix timestamp, a narrow forensic scenario compared to a stored password hash", "totp"),
		// isHCCAPXHex checks an exact hex length (786 chars = 393 bytes) and
		// that the record begins with the "HCPX" magic plus a literal
		// version-4 field, encoded as the hex string "4843505804000000" —
		// effectively an unambiguous record signature, just expressed as hex
		// text rather than raw bytes, so TierSignature rather than
		// TierStructural.
		predicateProto(isHCCAPXHex, "Legacy hccapx WPA-EAPOL container", hashid.TierSignature,
			"786-char hex record beginning with the HCPX magic and hccapx format version 4 (4843505804000000)",
			3, "hccapx (Hashcat modes 2500/2501) is Hashcat's retired WPA handshake container, superseded by the pcapng-derived hc22000 format that current capture tooling now emits by default", "wpa-hccapx"),
		hasPrefixProto("$keepass$", "KeePass database", 20,
			"KeePass is one of the most widely used cross-platform password managers, so its KDBX database file recurs routinely in password-manager cracking casework", "keepass"),
	}
}

// batchEPrototypes ports the wallet, wireless and web-framework branches of
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
func batchEPrototypes() []hashid.Prototype {
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
