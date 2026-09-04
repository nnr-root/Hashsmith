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
