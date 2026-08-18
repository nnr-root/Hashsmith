package main

// The Hashsmith hash-type catalogue.
//
// Every entry here is a `-t <name>` value the crack/hash engine understands.
// Detection usually makes -t unnecessary, but it is available when a hash is
// ambiguous or when you want to skip auto-detection. `hashsmith types` prints
// this catalogue.

import "fmt"

type typeGroup struct {
	title string
	items [][2]string // {name, description}
}

var hashTypeCatalogue = []typeGroup{
	{"Raw digests", [][2]string{
		{"md4", "MD4"},
		{"md5", "MD5"},
		{"sha1", "SHA-1"},
		{"sha224", "SHA-224"},
		{"sha256", "SHA-256"},
		{"sha384", "SHA-384"},
		{"sha512", "SHA-512"},
		{"sha3_224", "SHA3-224"},
		{"sha3_256", "SHA3-256"},
		{"sha3_384", "SHA3-384"},
		{"sha3_512", "SHA3-512"},
		{"ripemd160", "RIPEMD-160"},
		{"blake2b", "BLAKE2b-512"},
		{"blake2s", "BLAKE2s-256"},
		{"half-md5", "Half-MD5 (first 8 bytes of MD5)"},
		{"whirlpool", "Whirlpool-512"},
		{"streebog256", "Streebog / GOST R 34.11-2012 (256-bit)"},
		{"streebog512", "Streebog / GOST R 34.11-2012 (512-bit)"},
		{"ntlm", "NTLM (UTF-16LE MD4)"},
	}},
	{"Salted digests (add -s <salt> -S prefix|suffix)", [][2]string{
		{"md5 -s <salt> -S suffix", "digest($pass . $salt)"},
		{"md5 -s <salt> -S prefix", "digest($salt . $pass)"},
		{"sha1/sha256/sha512 …", "same, for any raw digest above"},
	}},
	{"Nested digests", [][2]string{
		{"md5-md5", "md5(hex(md5($pass)))"},
		{"sha1-sha1", "sha1(hex(sha1($pass)))"},
		{"sha256-sha256", "sha256(hex(sha256($pass)))"},
	}},
	{"HMAC (message from -s <salt> or a hash:salt target)", [][2]string{
		{"hmac-md5", "HMAC-MD5, key = password"},
		{"hmac-sha1", "HMAC-SHA1, key = password"},
		{"hmac-sha256", "HMAC-SHA256, key = password"},
		{"hmac-sha512", "HMAC-SHA512, key = password"},
		{"hmac-md5-saltkey", "HMAC-MD5, key = salt"},
		{"hmac-sha1-saltkey", "HMAC-SHA1, key = salt"},
		{"hmac-sha256-saltkey", "HMAC-SHA256, key = salt"},
		{"hmac-sha512-saltkey", "HMAC-SHA512, key = salt"},
	}},
	{"Unix login / crypt(3)", [][2]string{
		{"descrypt", "traditional DES crypt (13-char)"},
		{"md5crypt", "$1$ MD5 crypt"},
		{"apr1", "Apache apr1 ($apr1$, .htpasswd MD5)"},
		{"sha256crypt", "$5$ SHA-256 crypt"},
		{"sha512crypt", "$6$ SHA-512 crypt"},
		{"bcrypt", "$2a$/$2b$/$2y$ bcrypt"},
	}},
	{"Databases", [][2]string{
		{"oracle11g", "Oracle 11g (SHA-1 + salt)"},
		{"oracle12c", "Oracle 12c 'T:' (PBKDF2-SHA512)"},
		{"mysql323", "MySQL 3.23 (OLD_PASSWORD)"},
		{"mysql41", "MySQL 4.1+ / SHA-1 based"},
		{"postgres", "PostgreSQL MD5 (username as salt)"},
		{"mssql2000", "MSSQL 2000"},
		{"mssql2005", "MSSQL 2005"},
		{"mssql2012", "MSSQL 2012/2014"},
		{"sybase", "Sybase ASE (SHA-256)"},
		{"mongodb", "MongoDB SCRAM-SHA-1"},
	}},
	{"KDF / memory-hard / frameworks / CMS", [][2]string{
		{"argon2", "Argon2id"},
		{"scrypt", "scrypt"},
		{"django", "Django PBKDF2 (pbkdf2_sha256 / pbkdf2_sha1)"},
		{"solarwinds", "SolarWinds Orion (PBKDF2-SHA1 + SHA-512)"},
		{"ansible", "Ansible Vault (PBKDF2-SHA256 + HMAC-SHA256)"},
		{"blockchain", "Blockchain.info My Wallet v2"},
		{"axcrypt-sha1", "AxCrypt 1 in-memory SHA-1"},
		{"phpass", "phpass — WordPress ($P$) / phpBB3 ($H$)"},
		{"drupal7", "Drupal 7 ($S$, SHA-512)"},
		{"mediawiki", "MediaWiki ($B$)"},
		{"vbulletin", "vBulletin (md5:salt)"},
		{"redmine", "Redmine (sha1:salt)"},
		{"cisco8", "Cisco-IOS type 8 ($8$, PBKDF2-SHA256)"},
		{"cisco9", "Cisco-IOS type 9 ($9$, scrypt)"},
		{"macos", "macOS 10.8+ ShadowHashData ($ml$, PBKDF2-SHA512)"},
		{"atlassian", "Atlassian Jira/Confluence ({PKCS5S2}, PBKDF2-SHA1)"},
		{"jwt", "JWT — HMAC-signed (HS256 / HS384 / HS512)"},
		{"pbkdf2", "Generic PBKDF2 (algo:iter:salt:dk, SHA1/256/512/MD5)"},
	}},
	{"Wireless / wallets", [][2]string{
		{"wpa", "WPA/WPA2 PMKID and EAPOL"},
		{"ethereum", "Ethereum wallet (Web3 keystore v3, scrypt/PBKDF2)"},
		{"bitcoin", "Bitcoin/Litecoin wallet.dat"},
		{"electrum", "Electrum wallet (salt-type 1-3)"},
		{"bitwarden", "Bitwarden vault (layered PBKDF2-SHA256)"},
		{"itunes", "iTunes backup (PBKDF2 + AES key-unwrap)"},
		{"1password", "1Password Agile Keychain (PBKDF2-SHA1 + AES)"},
	}},
	{"Disk encryption", [][2]string{
		{"veracrypt", "VeraCrypt AES-XTS (SHA-512 / SHA-256 / RIPEMD-160)"},
		{"truecrypt", "TrueCrypt AES-XTS (RIPEMD-160)"},
		{"bitlocker", "BitLocker (1M-round SHA-256 + AES-CTR)"},
		{"luks", "LUKS v1 — AES/Twofish, XTS/CBC, SHA-1/256/512/RIPEMD-160 (use luks2smith)"},
	}},
	{"Network capture / authentication", [][2]string{
		{"netntlmv1", "NetNTLMv1 / NTLMv1-ESS"},
		{"netntlmv2", "NetNTLMv2"},
		{"dcc", "Domain Cached Credentials (mscash)"},
		{"dcc2", "Domain Cached Credentials 2 (mscash2)"},
		{"krb5asrep", "Kerberos 5 AS-REP (etype 23)"},
		{"krb5tgs", "Kerberos 5 TGS-REP (etype 23 / 17 / 18)"},
		{"krb5pa", "Kerberos 5 pre-auth (etype 17 / 18, AES)"},
		{"wpa", "WPA/WPA2 PMKID and EAPOL (4-way handshake)"},
		{"citrix", "Citrix NetScaler (SHA-1)"},
		{"juniper", "Juniper NetScreen / ScreenOS (MD5)"},
		{"cisco-pix", "Cisco-PIX (MD5)"},
		{"cisco-asa", "Cisco-ASA (MD5 + salt)"},
		{"cram-md5", "CRAM-MD5 (HMAC-MD5 challenge-response)"},
		{"scram", "PostgreSQL SCRAM-SHA-256"},
		{"ipmi", "IPMI2 RAKP (HMAC-SHA1)"},
		{"sap-fg", "SAP CODVN F/G (PASSCODE, iSSHA-1)"},
		{"sap-b", "SAP CODVN B (BCODE)"},
		{"chap", "iSCSI CHAP (MD5 challenge-response)"},
		{"ldap", "LDAP {SSHA}/{SSHA256}/{SSHA512}/{SMD5}"},
		{"aix", "AIX {ssha256} / {ssha512} (PBKDF2)"},
		{"sip", "SIP digest authentication (HTTP Digest MD5)"},
		{"ike", "IKE aggressive-mode PSK (MD5 / SHA-1)"},
	}},
	{"Encrypted containers (extract with the matching *2smith command)", [][2]string{
		{"zipcrypto / zipaes128/192/256", "ZIP"},
		{"7z", "7-Zip AES-256"},
		{"rar4 / rar5", "RAR"},
		{"pdf", "PDF Standard security handler"},
		{"pdf-r6", "PDF R5/R6 (AES-256, Acrobat 9/X/XI)"},
		{"ssh / pkcs8", "SSH / PKCS#8 private keys"},
		{"gpg", "gpg -c symmetric"},
		{"office", "MS Office 2007/2010/2013"},
		{"keepass", "KeePass KDBX"},
	}},
}

func runListTypes(_ []string) error {
	fmt.Println("Hashsmith hash types")
	fmt.Println("Pass any of these as `-t <name>` — or just let auto-detection choose.")
	fmt.Println()
	for _, g := range hashTypeCatalogue {
		accentPrintln(g.title)
		for _, it := range g.items {
			fmt.Printf("  %-32s %s\n", it[0], it[1])
		}
		fmt.Println()
	}
	fmt.Println("Salted digests place the salt with -S prefix|suffix; HMAC types read the")
	fmt.Println("message from -s or from a `hash:salt` target. Most hashes are detected")
	fmt.Println("automatically, so -t is optional.")
	return nil
}

// accentPrintln prints a heading in the accent colour on stdout.
func accentPrintln(s string) {
	fmt.Println(accentSprint(s))
}
