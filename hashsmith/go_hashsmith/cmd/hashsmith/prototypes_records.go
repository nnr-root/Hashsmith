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
