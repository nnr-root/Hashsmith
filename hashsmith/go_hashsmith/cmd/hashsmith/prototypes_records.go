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

// batchFPrototypes ports the remaining wallet, wireless and web-framework
// branches of the legacy cascade: the three-field colon-split branch that
// yields rails-restful-auth (the branch immediately before isMySQL8; a scope
// correction moved it into this half so table order still matches cascade
// order) through isJWT (original lines 1470-1562). 28 top-level `if`
// statements, one of which (isPhpassHash) is nested and becomes two
// prototypes, for 29 total.
func batchFPrototypes() []hashid.Prototype {
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
		// isCiscoType4 checks (after trimming the "$4$" prefix) an exact
		// length (43) and that every remaining char is in the crypt-64
		// alphabet — combined with the outer "$4$" prefix check, a prefix
		// plus a decoded/validated field, so TierSignature.
		{
			Types: []string{"cisco4"}, Display: "Cisco IOS type 4 (unsalted SHA-256)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if strings.HasPrefix(in.Normalized, "$4$") && isCiscoType4(in.Normalized) {
					return "record prefix $4$ with a 43-char crypt-64-alphabet body", true
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

// batchGPrototypes ports the KDF, directory and enterprise-predicate branches
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
func batchGPrototypes() []hashid.Prototype {
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

// batchHPrototypes ports the generic salted-construction, Kerberos and
// regex-single branches of the legacy cascade: detectCompatSaltedTypes
// through the 50-char arubaos branch (original lines 1978-2054). This batch
// sits near the END of the cascade, behind roughly 150 higher-precedence
// branches already in the table from batches A-G, which is why
// detectCompatSaltedTypes below is expressed as a Compute prototype AT ITS
// OWN TABLE POSITION rather than a call from detectTypesFromTable outside
// the table: the latter would run it first and silently steal matches from
// every higher-precedence entry already in the table.
func batchHPrototypes() []hashid.Prototype {
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
		// reMSSQLNew is nested, but unlike the krb5asrep/krb5tgs pairs above,
		// the nesting is dead code: reMSSQLNew itself
		// (`(?i)^0x0100[0-9a-fA-F]{48}$`) anchors on the literal digits
		// "0x0100" — digits are unaffected by the (?i) case-fold, which only
		// touches a-f — so ANY string the regexp matches is already
		// guaranteed to start with "0100", never "0200". The nested
		// `strings.HasPrefix(strings.ToLower(t), "0x0200")` check therefore
		// can never see the record it is looking for. This is inherited
		// verbatim from the legacy cascade, not introduced by porting it, and
		// is ported anyway for cascade fidelity — hence no coverage case for
		// mssql2012; see TestTableCoverageBatchH's comment for the same
		// conclusion from the test side. Kept first in table order to
		// reproduce the nested precedence, as instructed, even though it can
		// never fire.
		{
			Types: []string{"mssql2012"}, Display: "SQL Server 2012+ password hash (unreachable)",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if reMSSQLNew.MatchString(in.Normalized) && strings.HasPrefix(strings.ToLower(in.Normalized), "0x0200") {
					return "record prefix 0x0100 (case-insensitive) with a fixed 54-char total length, additionally starting 0x0200 (impossible: see the comment above)", true
				}
				return "", false
			},
			Prevalence: 10, Rationale: "no basis for a better estimate; revisit with corpus data",
		},
		// The general mssql2005 branch is just reMSSQLNew.MatchString(t) &&
		// NOT the (unreachable) 0x0200 check, i.e. equivalent to
		// reMSSQLNew.MatchString(t) alone in practice. reMSSQLNew anchors on
		// the literal "0x0100" prefix plus a fixed 54-char total length, so
		// TierSignature, matching batchG's Sybase ASE ("0xc007" prefix plus
		// fixed length) reasoning.
		{
			Types: []string{"mssql2005"}, Display: "SQL Server 2000/2005 password hash",
			Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if reMSSQLNew.MatchString(in.Normalized) && !strings.HasPrefix(strings.ToLower(in.Normalized), "0x0200") {
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
		// only reaches this check after an earlier `if !isHex(t) { return nil
		// }` guard (kept in legacyDetectHashTypes, immediately before the
		// switch len(t) shape fallback the next task owns), so an isHex(t)
		// check is added here to reproduce that precondition faithfully for
		// this now-standalone table entry. The 2-char literal at a fixed
		// offset is an embedded marker, but a much shorter and weaker one
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
