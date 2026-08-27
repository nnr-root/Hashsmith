package main

import (
	"fmt"
	"sort"
	"strings"
)

// extractorDefinition is the single source of truth for the *2smith surface.
// Routing, aliases, help and the machine-readable catalogue all use this one
// registry, so adding an extractor cannot silently leave another list stale.
type extractorDefinition struct {
	name    string
	aliases []string
	input   string
	formats string
	run     func([]string) error
}

var universalExtractorRegistry = []extractorDefinition{
	{name: "1password2smith", input: "1Password Agile Keychain", formats: "Agile Keychain encryptionKeys.js", run: runExtractOnePassword},
	{name: "7z2smith", input: ".7z archive", formats: "7-Zip AES-256", run: runExtract7z},
	{name: "aix2smith", input: "AIX /etc/security/passwd", formats: "AIX smd5/ssha1/ssha256/ssha512", run: runExtractAIX},
	{name: "androidbackup2smith", aliases: []string{"ab2smith"}, input: "Android .ab backup", formats: "Android Backup AES-256 (v1-v5)", run: runExtractAndroidBackup},
	{name: "ansible2smith", input: "Ansible Vault", formats: "Ansible Vault 1.x/2.x AES-256", run: runExtractAnsible},
	{name: "applenotes2smith", aliases: []string{"notes2smith"}, input: "Apple NoteStore.sqlite", formats: "Apple Secure Notes", run: runExtractAppleNotes},
	{name: "aruba2smith", input: "Aruba configuration export", formats: "ArubaOS salted SHA-1", run: runExtractAruba},
	{name: "bitcoin2smith", input: "Bitcoin wallet.dat", formats: "Bitcoin Core SQLite + legacy Berkeley DB", run: runExtractBitcoin},
	{name: "bitwarden2smith", input: "Bitwarden browser/Android storage", formats: "JSON/XML/LevelDB encrypted key", run: runExtractBitwarden},
	{name: "bitlocker2smith", input: "BitLocker volume image", formats: "password/recovery VMKs", run: runExtractBitLocker},
	{name: "blockchain2smith", input: "Blockchain.com wallet JSON", formats: "Wallet v2/v3/v4", run: runExtractBlockchain},
	{name: "dmg2smith", input: "encrypted Apple DMG", formats: "DMG v1/v2", run: runExtractDMG},
	{name: "electrum2smith", input: "Electrum wallet", formats: "legacy Electrum wallet types 1/2/3", run: runExtractElectrum},
	{name: "encfs2smith", input: "EncFS directory/XML", formats: "EncFS 6 AES", run: runExtractEncFS},
	{name: "ethereum2smith", input: "Ethereum keystore JSON", formats: "Web3 scrypt/PBKDF2 keystore", run: runExtractEthereum},
	{name: "gpg2smith", input: ".gpg/.pgp/.asc", formats: "OpenPGP symmetric encryption", run: runExtractGPG},
	{name: "hashdump2smith", input: "pwdump/secretsdump/NTDS text", formats: "LM and NTLM", run: runExtractHashdump},
	{name: "hccapx2smith", input: ".hccapx capture", formats: "WPA/WPA2 hccapx v4", run: runExtractHCCAPX},
	{name: "htpasswd2smith", input: "Apache htpasswd", formats: "bcrypt/apr1/crypt/SHA", run: runExtractHtpasswd},
	{name: "ike2smith", aliases: []string{"ikescan2smith"}, input: "ike-scan PSK parameters", formats: "IKE aggressive-mode MD5/SHA-1", run: runExtractIKE},
	{name: "itunes2smith", aliases: []string{"itunes_backup2smith"}, input: "iOS backup Manifest.plist", formats: "iOS backup v9/v10 keybag", run: runExtractITunes},
	{name: "keychain2smith", input: "legacy macOS .keychain", formats: "PBKDF2-SHA1 + 3DES", run: runExtractKeychain},
	{name: "keepass2smith", input: ".kdb/.kdbx", formats: "KeePass KDBX 3/4", run: runExtractKeePass},
	{name: "ldif2smith", input: "LDAP LDIF", formats: "RFC 2307 LDAP password schemes", run: runExtractLDIF},
	{name: "lastpass2smith", aliases: []string{"lp2smith"}, input: "lastpass-cli data dir", formats: "LastPass CLI verifier", run: runExtractLastPass},
	{name: "luks2smith", input: "LUKS volume", formats: "LUKS1", run: runExtractLUKS},
	{name: "monero2smith", input: "Monero .keys wallet", formats: "CryptoNight v0 + ChaCha8/20", run: runExtractMonero},
	{name: "multibit2smith", input: "MultiBit Classic .key", formats: "OpenSSL salted AES wallet", run: runExtractMultiBit},
	{name: "mozilla2smith", aliases: []string{"nss2smith"}, input: "Mozilla key3.db", formats: "NSS key3 master password", run: runExtractMozilla},
	{name: "office2smith", input: "Office document", formats: "Office 2007/2010/2013+", run: runExtractOffice},
	{name: "pdf2smith", input: ".pdf", formats: "PDF standard security handler", run: runExtractPDF},
	{name: "pfx2smith", aliases: []string{"p122smith"}, input: ".pfx/.p12", formats: "PKCS#12 keystore", run: runExtractPKCS12},
	{name: "prosody2smith", input: "Prosody account .dat", formats: "XMPP SCRAM-SHA-1", run: runExtractProsody},
	{name: "pwsafe2smith", input: ".psafe3", formats: "Password Safe v3", run: runExtractPwsafe},
	{name: "rar2smith", input: ".rar", formats: "RAR3/4/5", run: runExtractRAR},
	{name: "scan2smith", input: "logs/configuration/text", formats: "all auto-detectable Hashsmith records", run: runExtractScan},
	{name: "shadow2smith", input: "/etc/shadow (+ passwd)", formats: "Unix crypt password hashes", run: runExtractShadow},
	{name: "signal2smith", input: "Signal SecureSMS preferences XML", formats: "Signal master-password verifier", run: runExtractSignal},
	{name: "sip2smith", aliases: []string{"sipdump2smith"}, input: "SIPdump text", formats: "SIP digest authentication", run: runExtractSIP},
	{name: "ssh2smith", input: "SSH/private key", formats: "OpenSSH/PEM/PKCS#8", run: runExtractSSH},
	{name: "telegram2smith", input: "Telegram XML/map/key_datas or tdata", formats: "Android passcode + Desktop v1/v2", run: runExtractTelegram},
	{name: "truecrypt2smith", input: "TrueCrypt volume", formats: "512-byte TrueCrypt volume header", run: runExtractTrueCrypt},
	{name: "veracrypt2smith", input: "VeraCrypt volume", formats: "512-byte VeraCrypt volume header", run: runExtractVeraCrypt},
	{name: "virtualbox2smith", aliases: []string{"vbox2smith"}, input: "VirtualBox .vbox XML", formats: "AES-128/256-XTS keystore", run: runExtractVirtualBox},
	{name: "vncpcap2smith", input: ".pcap/.pcapng capture", formats: "RFB VNC Authentication challenge-response", run: runExtractVNCPCAP},
	{name: "vmx2smith", aliases: []string{"vmwarevmx2smith"}, input: "VMware .vmx", formats: "VMware encryption.keySafe", run: runExtractVMX},
	{name: "zip2smith", aliases: []string{"extract-hash", "zip2hash"}, input: ".zip", formats: "ZipCrypto/WinZip AES", run: runExtractHash},
}

func findExtractor(name string) (*extractorDefinition, bool) {
	for i := range universalExtractorRegistry {
		d := &universalExtractorRegistry[i]
		if name == d.name {
			return d, true
		}
		for _, alias := range d.aliases {
			if name == alias {
				return d, true
			}
		}
	}
	return nil, false
}

func printExtractorCatalogue() {
	defs := append([]extractorDefinition(nil), universalExtractorRegistry...)
	sort.Slice(defs, func(i, j int) bool { return defs[i].name < defs[j].name })
	for _, d := range defs {
		aliases := ""
		if len(d.aliases) > 0 {
			aliases = " (aliases: " + strings.Join(d.aliases, ", ") + ")"
		}
		fmt.Printf("%-20s %-29s %s%s\n", d.name, d.input, d.formats, aliases)
	}
}
