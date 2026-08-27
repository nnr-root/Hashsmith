package main

import (
	"crypto/des"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"strings"
)

func newSHA3_224() hash.Hash { return sha3.New224() }
func newSHA3_256() hash.Hash { return sha3.New256() }
func newSHA3_384() hash.Hash { return sha3.New384() }
func newSHA3_512() hash.Hash { return sha3.New512() }

var (
	crc32cTable      = crc32.MakeTable(crc32.Castagnoli)
	crc64Table       = crc64.MakeTable(crc64.ECMA)
	hashOutputCodecs = map[string]bool{
		"base32": true, "base32-nopad": true, "base32hex": true,
		"base32crockford": true, "zbase32": true, "base36": true, "base45": true,
		"base58": true, "base58flickr": true, "base58ripple": true,
		"base58check": true, "base62": true,
		"base64": true, "base64raw": true, "base64url": true,
		"base64url-padded": true, "base64-mime": true,
		"base85": true, "adobe85": true,
		"z85": true, "base91": true, "binary": true, "decimal": true,
		"octal": true, "pem": true, "gzip": true, "zlib": true,
		"hex-escape": true, "bubblebabble": true,
	}
)

// canonicalHashType accepts the punctuation variants people commonly use for
// standardized algorithm names while preserving Hashsmith's stable CLI tokens.
func canonicalHashType(typ string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	// Accept the identifiers users already know from Hashcat (-m <number>) and
	// John the Ripper (--format=<name>).  Namespaced spellings are useful in
	// scripts, while bare Hashcat mode numbers keep interactive use concise.
	for _, prefix := range []string{"hashcat:", "hashcat-", "hc:", "hc-", "john:", "john-", "jtr:", "jtr-"} {
		if strings.HasPrefix(t, prefix) {
			t = strings.TrimPrefix(t, prefix)
			break
		}
	}
	if alias, ok := universalHashRegistry.aliases[t]; ok {
		return alias
	}
	return t
}

// compatibilityHashAliasSeed maps formats whose candidate semantics are usable
// by Hashsmith. Ciphertexts are normally accepted verbatim; documented
// extractor-normalized exceptions (currently the split LUKS v1 matrix) still
// require Hashsmith's compact *2smith record. Modes with neither representation
// nor candidate compatibility are intentionally omitted.
func compatibilityHashAliasSeed() map[string]string {
	return map[string]string{
		// ── Hashcat: raw digests ──────────────────────────────────────────────────
		"0": "md5", "70": "md5-utf16le", "900": "md4", "1000": "ntlm", "3000": "lm",
		"100": "sha1", "170": "sha1-utf16le",
		"1300": "sha224", "1400": "sha256", "1470": "sha256-utf16le",
		"1700": "sha512", "1770": "sha512-utf16le",
		"10800": "sha384", "10870": "sha384-utf16le",
		"600": "blake2b", "31000": "blake2s", "34800": "blake2b256",
		"6000": "ripemd160", "6100": "whirlpool",
		// RIPEMD-128/256 have no Hashcat mode; John names them directly.
		"ripemd-128": "ripemd128", "ripemd-256": "ripemd256", "ripemd-320": "ripemd320",
		"11700": "streebog256", "11800": "streebog512", "31100": "sm3", "33600": "ripemd320",
		"17300": "sha3_224", "17400": "sha3_256", "17500": "sha3_384", "17600": "sha3_512",
		"17700": "keccak224", "17800": "keccak256", "17900": "keccak384", "18000": "keccak512",
		"5100": "half-md5",

		// ── Hashcat: generic salted constructions ─────────────────────────────────
		"10": "md5-pass-salt", "20": "md5-salt-pass",
		"30": "md5-utf16le-pass-salt", "40": "md5-salt-utf16le-pass",
		"110": "sha1-pass-salt", "120": "sha1-salt-pass",
		"130": "sha1-utf16le-pass-salt", "140": "sha1-salt-utf16le-pass",
		"1310": "sha224-pass-salt", "1320": "sha224-salt-pass",
		"1410": "sha256-pass-salt", "1420": "sha256-salt-pass",
		"1430": "sha256-utf16le-pass-salt", "1440": "sha256-salt-utf16le-pass",
		"1710": "sha512-pass-salt", "1720": "sha512-salt-pass",
		"1730": "sha512-utf16le-pass-salt", "1740": "sha512-salt-utf16le-pass",
		"10810": "sha384-pass-salt", "10820": "sha384-salt-pass",
		"10830": "sha384-utf16le-pass-salt", "10840": "sha384-salt-utf16le-pass",
		// Application modes that are exactly one of the generic constructions.
		"11": "md5-pass-salt", // Joomla < 2.5.18
		"24": "md5-salt-pass", // SolarWinds Serv-U
		// Composite constructions: a nesting of MD5/SHA-1/SHA-256 over pass and salt.
		"3710":  "md5-salt-md5pass",
		"2630":  "md5-md5passsalt",
		"3610":  "md5-md5-md5pass-salt",
		"3800":  "md5-salt-pass-salt",
		"3910":  "md5-md5pass-md5salt",
		"4010":  "md5-salt-md5saltpass",
		"4110":  "md5-salt-md5passsalt",
		"4410":  "md5-sha1pass-salt",
		"4420":  "md5-sha1passsalt",
		"4430":  "md5-sha1saltpass",
		"4510":  "sha1-sha1pass-salt",
		"4710":  "sha1-md5pass-salt",
		"2811":  "md5-md5salt-md5pass",
		"21200": "md5-sha1salt-md5pass",
		"21300": "md5-salt-sha1saltpass",
		"4900":  "sha1-salt-pass-salt",
		"5000":  "sha1-sha1saltpasssalt",
		"24300": "sha1-salt-sha1passsalt",
		"29000": "sha1-salt-user-password",
		"22800": "md5-salt-pass-md5pass",
		"22300": "sha256-salt-pass-salt",
		"20710": "sha256-sha256pass-salt",
		"20800": "sha256-md5pass",
		"21400": "sha256-sha256binpass",
		"21000": "sha512-sha512binpass",
		"20900": "md5-sha1pass-md5pass-sha1pass",
		"30500": "md5-md5salt-md5-md5pass",
		"3730":  "md5-salt1-upper-md5-salt2-pass",
		"31700": "md5-triple-dual-salt",
		"19300": "sha1-salt1-pass-salt2",
		"20720": "sha256-salt-sha256pass", "20730": "sha256-sha256passsalt",
		"21100": "sha1-md5passsalt", "21310": "md5-salt1-sha1salt2pass",
		"21420": "sha256-salt-sha256binpass", "21900": "md5-triple-passsalt-dual",
		"12600": "sha256-salt-uppersha1pass",
		"13800": "sha256-salt-utf16lepass",
		"32410": "sha512-sha512pass-salt", "32420": "sha512-sha512binpass-salt",
		"32600": "whirlpool-salt-pass-salt",
		"32800": "md5-sha1-md5pass", "33100": "md5-salt-md5pass-salt",
		"34400": "sha224-sha224pass", "34500": "sha224-sha1pass",
		"1421":  "hmailserver",
		"15000": "sha512-pass-salt", // FileZilla Server >= 0.9.55
		"610":   "blake2b-pass-salt", "620": "blake2b-salt-pass",
		"34810": "blake2b256-pass-salt", "34820": "blake2b256-salt-pass",
		// Application modes that are exactly one of the constructions above.
		"121":   "sha1-salt-pass",             // Simple Machines Forum
		"11000": "md5-salt-pass",              // PrestaShop
		"8400":  "sha1-salt-sha1saltsha1pass", // Woltlab Burning Board 3
		"13900": "sha1-salt-sha1saltsha1pass", // OpenCart
		"21":    "md5-salt-pass",              // osCommerce / xt:Commerce
		"23":    "md5-salt-pass",              // Skype

		// ── Hashcat: nested digests ───────────────────────────────────────────────
		"2600": "md5-md5", "3500": "md5-md5-md5", "4300": "md5-upper-md5",
		"4400": "md5-sha1", "4500": "sha1-sha1", "4700": "sha1-md5",
		"18500": "sha1-md5-md5pass",
		"33000": "md5-salt1-pass-salt2",

		// ── Hashcat: HMAC ─────────────────────────────────────────────────────────
		"50": "hmac-md5", "60": "hmac-md5-saltkey",
		"150": "hmac-sha1", "160": "hmac-sha1-saltkey",
		"1450": "hmac-sha256", "1460": "hmac-sha256-saltkey",
		"1750": "hmac-sha512", "1760": "hmac-sha512-saltkey",
		"6050": "hmac-ripemd160", "6060": "hmac-ripemd160-saltkey",
		"33300": "hmac-blake2s", "33650": "hmac-ripemd320", "33660": "hmac-ripemd320-saltkey",
		"11750": "hmac-streebog256", "11760": "hmac-streebog256-saltkey",
		"11850": "hmac-streebog512", "11860": "hmac-streebog512-saltkey",

		// ── Hashcat: keyed and seeded checksums ───────────────────────────────────
		"10100": "siphash", "11500": "crc32-hashcat", "25700": "murmurhash",
		"34200": "murmur64a", "34201": "murmur64a-zero", "34211": "murmur64a-truncated",
		"27800": "murmur3-seeded", "27900": "crc32c-hashcat", "28000": "crc64-jones",
		"14900": "skip32",
		"18700": "java-hashcode",
		"125":   "arubaos", "14400": "sha1-cx", "16400": "dovecot-cram-md5",
		"14000": "des-plaintext", "14100": "3des-plaintext", "15400": "chacha20",
		"33500": "rc4-dropn", "33501": "rc4-dropn", "33502": "rc4-dropn",
		"26401": "aes128-ecb-nokdf", "26402": "aes192-ecb-nokdf", "26403": "aes256-ecb-nokdf",

		// ── Hashcat: Unix login / crypt(3) ────────────────────────────────────────
		"500": "md5crypt", "1500": "descrypt", "1600": "apr1",
		"1800": "sha512crypt", "3200": "bcrypt", "7400": "sha256crypt",
		"25600": "bcrypt-md5", "25800": "bcrypt-sha1", "30600": "bcrypt-sha256",
		"28400": "bcrypt-sha512", "30601": "passlib-bcrypt-sha256",
		"15100": "sha1crypt", "35100": "sm3crypt",

		// ── Hashcat: databases ────────────────────────────────────────────────────
		"12": "postgres", "112": "oracle11g", "12300": "oracle12c",
		"3100": "oracle-h",
		"133":  "peoplesoft", "13500": "peoplesoft-token", "141": "episerver", "1441": "episerver",
		"12800": "azuresync",
		"131":   "mssql2000", "132": "mssql2005", "1731": "mssql2012",
		"200": "mysql323", "300": "mysql41", "8000": "sybase", "11200": "mysql-cram",
		"11100": "postgres-cram", "20600": "oracle-otm", "26200": "openedge",
		"24100": "mongodb", "24200": "mongodb", "28600": "scram",

		// ── Hashcat: CMS / frameworks / app platforms ─────────────────────────────
		"400": "phpass", "7900": "drupal7", "3711": "mediawiki", "2612": "phps",
		"2611": "vbulletin", "2711": "vbulletin",
		"4520": "redmine", "4521": "redmine", "4522": "sha1-salt-sha1pass", "4711": "sha1-md5pass-salt",
		"124": "django", "10000": "django", "12001": "atlassian", "12150": "shiro1-sha512", "16500": "jwt",
		"16000": "tripcode", "16501": "mojolicious", "18800": "blockchain-second",
		"35700": "phpass-md5", "35800": "symfony-legacy",
		"32300": "empirecms", "6800": "lastpass", "9900": "radmin2",
		"19500": "rails-restful-auth", "21600": "web2py-pbkdf2", "29100": "flask-session",
		"27200": "rails-restful-auth-one-round",
		"35500": "wordpress-bcrypt",
		"22301": "telegram-passcode", "30700": "anope-sha256", "33900": "citrix-pbkdf2",
		"28300": "teamspeak3", "31200": "veeam-vbk", "31400": "securecrt-v2",
		"33700": "ms-online-account",
		"16900": "ansible", "21500": "solarwinds", "21501": "solarwinds",
		"30000": "werkzeug", "30120": "werkzeug", "32060": "passlib-pbkdf2",
		"20200": "passlib-pbkdf2", "20300": "passlib-pbkdf2", "20400": "passlib-pbkdf2",
		"32000": "sspr", "32010": "sspr", "32020": "sspr", "32030": "sspr",
		"32031": "sspr", "32040": "sspr", "32041": "sspr",
		"32050": "netiq-pbkdf2", "32070": "netiq-pbkdf2",
		"9200": "cisco8", "9300": "cisco9",
		"5700": "cisco4", "5800": "samsung-android",
		"5720": "cisco-ise", "7000": "fortigate",
		"22200": "citrix-sha512", "24800": "umbraco-hmac-sha1", "26300": "fortigate256",
		"20712": "netwitness-sha256", "24900": "dahua-auth-md5", "24901": "besder-auth-md5",
		"29200": "radmin3",
		"6300":  "aix", "6400": "aix", "6500": "aix", "6700": "aix",
		"7100": "macos", "7200": "grub2", "7401": "mysql8",
		"122": "macos", "1722": "macos", "20711": "authme-sha256",
		"30420": "dane-sha256", "35200": "as400-ssha1",

		// ── Hashcat: KDFs ─────────────────────────────────────────────────────────
		"8900": "scrypt", "10900": "pbkdf2", "10901": "ldap-pbkdf2", "32900": "pbkdf1",
		"11900": "pbkdf2", "12000": "pbkdf2", "12100": "pbkdf2",
		"34000": "argon2", "70000": "argon2", "70100": "scrypt", "70200": "scrypt",

		// ── Hashcat: LDAP / directory ─────────────────────────────────────────────
		"101": "ldap", "111": "ldap", "1411": "ldap", "1711": "ldap",

		// ── Hashcat: network capture / authentication ─────────────────────────────
		"1100": "dcc", "2100": "dcc2", "31500": "dcc-nt", "31600": "dcc2-nt",
		"2500": "wpa-hccapx", "2501": "wpa-hccapx-pmk",
		"2400": "cisco-pix", "2410": "cisco-asa", "22": "juniper",
		"4800": "chap", "5500": "netntlmv1", "5600": "netntlmv2",
		"7300": "ipmi", "8100": "citrix", "10200": "cram-md5",
		"7350": "ipmi-md5", "7500": "krb5pa", "8300": "dnssec-nsec3",
		"11400": "sip", "22000": "wpa",
		"16100": "tacacs-plus", "23200": "xmpp-scram",
		"18100": "totp", "25000": "snmpv3", "25100": "snmpv3", "28700": "aws-sig-v4",
		"5300": "ike", "5400": "ike",
		"16800": "wpa-pmkid", "16801": "wpa-pmk", "22001": "wpa-pmk",
		"25200": "snmpv3", "26700": "snmpv3", "26800": "snmpv3", "26900": "snmpv3", "27300": "snmpv3",
		"25900": "knx-ip-secure", "27000": "netntlmv1-nt", "27100": "netntlmv2-nt", "31300": "ms-sntp",
		"7700": "sap-b", "7701": "sap-b-rfc-read-table",
		"7800": "sap-fg", "7801": "sap-fg-rfc-read-table", "35000": "sap-issha512",
		"10300": "sap-issha1",
		// Kerberos: etype 23 (RC4) and the AES etypes 17/18.
		"13100": "krb5tgs", "19600": "krb5tgs", "19700": "krb5tgs",
		"18200": "krb5asrep", "32100": "krb5asrep", "32200": "krb5asrep",
		"19800": "krb5pa", "19900": "krb5pa", "28800": "krb5db", "28900": "krb5db",
		"35300": "krb5tgs-nt", "35400": "krb5asrep-nt",

		// ── Hashcat: wallets ──────────────────────────────────────────────────────
		"28501": "bitcoin-wif-p2pkh-compressed", "28502": "bitcoin-wif-p2pkh-uncompressed",
		"28503": "bitcoin-wif-p2wpkh-compressed", "28504": "bitcoin-wif-p2wpkh-uncompressed",
		"28505": "bitcoin-wif-p2sh-p2wpkh-compressed", "28506": "bitcoin-wif-p2sh-p2wpkh-uncompressed",
		"30901": "bitcoin-raw-p2pkh-compressed", "30902": "bitcoin-raw-p2pkh-uncompressed",
		"30903": "bitcoin-raw-p2wpkh-compressed", "30904": "bitcoin-raw-p2wpkh-uncompressed",
		"30905": "bitcoin-raw-p2sh-p2wpkh-compressed", "30906": "bitcoin-raw-p2sh-p2wpkh-uncompressed",
		"26600": "metamask", "26610": "metamask-short", "28200": "exodus",
		"11300": "bitcoin", "12700": "blockchain", "15200": "blockchain", "34700": "blockchain-legacy", "16600": "electrum",
		"15600": "ethereum", "15700": "ethereum", "16300": "ethereum-presale",
		"22400": "aescrypt", "22500": "multibit-key", "29600": "terra-wallet",
		"6600": "1password", "23400": "bitwarden",
		"14700": "itunes", "14800": "itunes",
		"16200": "apple-secure-notes",
		"25500": "stellar-wallet",
		"19000": "qnx-md5", "19100": "qnx-sha256", "19200": "qnx-sha512", "19210": "qnx-sha512",

		// ── Hashcat: disk encryption ──────────────────────────────────────────────
		"14600": "luks", "22100": "bitlocker",
		"6211": "truecrypt", "6212": "truecrypt", "6213": "truecrypt",
		"6221": "truecrypt", "6222": "truecrypt", "6223": "truecrypt",
		"6231": "truecrypt-whirlpool", "6232": "truecrypt-whirlpool-xts1024", "6233": "truecrypt-whirlpool-xts1536",
		"6241": "truecrypt-ripemd160-boot-xts512", "6242": "truecrypt-ripemd160-boot-xts1024",
		"6243":  "truecrypt-ripemd160-boot-xts1536",
		"13711": "veracrypt", "13712": "veracrypt", "13713": "veracrypt",
		"13721": "veracrypt", "13722": "veracrypt", "13723": "veracrypt",
		"13731": "veracrypt-whirlpool", "13732": "veracrypt-whirlpool-xts1024", "13733": "veracrypt-whirlpool-xts1536",
		"13741": "veracrypt-ripemd160-boot-xts512", "13742": "veracrypt-ripemd160-boot-xts1024",
		"13743": "veracrypt-ripemd160-boot-xts1536",
		"13751": "veracrypt", "13752": "veracrypt", "13753": "veracrypt",
		"13761": "veracrypt-sha256-boot-xts512", "13762": "veracrypt-sha256-boot-xts1024",
		"13763": "veracrypt-sha256-boot-xts1536",
		"13771": "veracrypt-streebog512", "13772": "veracrypt-streebog512-xts1024",
		"13773": "veracrypt-streebog512-xts1536",
		"13781": "veracrypt-streebog512-boot-xts512", "13782": "veracrypt-streebog512-boot-xts1024",
		"13783": "veracrypt-streebog512-boot-xts1536",
		"29311": "truecrypt-ripemd160", "29321": "truecrypt-sha512", "29331": "truecrypt-whirlpool",
		"29312": "truecrypt-ripemd160-xts1024", "29313": "truecrypt-ripemd160-xts1536",
		"29322": "truecrypt-sha512-xts1024", "29323": "truecrypt-sha512-xts1536",
		"29332": "truecrypt-whirlpool-xts1024", "29333": "truecrypt-whirlpool-xts1536",
		"29341": "truecrypt-ripemd160-boot-xts512", "29342": "truecrypt-ripemd160-boot-xts1024",
		"29343": "truecrypt-ripemd160-boot-xts1536",
		"29411": "veracrypt-ripemd160", "29421": "veracrypt-sha512", "29431": "veracrypt-whirlpool",
		"29451": "veracrypt-sha256",
		"29412": "veracrypt-ripemd160-xts1024", "29413": "veracrypt-ripemd160-xts1536",
		"29422": "veracrypt-sha512-xts1024", "29423": "veracrypt-sha512-xts1536",
		"29432": "veracrypt-whirlpool-xts1024", "29433": "veracrypt-whirlpool-xts1536",
		"29441": "veracrypt-ripemd160-boot-xts512", "29442": "veracrypt-ripemd160-boot-xts1024",
		"29443": "veracrypt-ripemd160-boot-xts1536",
		"29452": "veracrypt-sha256-xts1024", "29453": "veracrypt-sha256-xts1536",
		"29461": "veracrypt-sha256-boot-xts512", "29462": "veracrypt-sha256-boot-xts1024",
		"29463": "veracrypt-sha256-boot-xts1536",
		"29471": "veracrypt-streebog512", "29472": "veracrypt-streebog512-xts1024",
		"29473": "veracrypt-streebog512-xts1536",
		"29481": "veracrypt-streebog512-boot-xts512", "29482": "veracrypt-streebog512-boot-xts1024",
		"29483": "veracrypt-streebog512-boot-xts1536",
		"29511": "luks-sha1-aes", "29512": "luks-sha1-serpent", "29513": "luks-sha1-twofish",
		"29521": "luks-sha256-aes", "29522": "luks-sha256-serpent", "29523": "luks-sha256-twofish",
		"29531": "luks-sha512-aes", "29532": "luks-sha512-serpent", "29533": "luks-sha512-twofish",
		"29541": "luks-ripemd160-aes", "29542": "luks-ripemd160-serpent", "29543": "luks-ripemd160-twofish",

		// ── Hashcat: documents / archives / key material ──────────────────────────
		"9400": "office", "9500": "office", "9600": "office", "25300": "office2016-sheet",
		"9700": "office-old-md5", "9800": "office-old-sha1",
		"17010": "gpg", "17020": "gpg", "17030": "gpg", "17040": "gpg",
		"22911": "ssh", "22921": "ssh", "22931": "ssh", "22941": "ssh", "22951": "ssh",
		"10400": "pdf", "10500": "pdf", "10510": "pdf", "10600": "pdf-r6", "10700": "pdf-r6",
		"11600": "7z", "12500": "rar4", "13000": "rar5",
		"13400": "keepass", "29700": "keepass",
		"24400": "pkcs8", "24410": "pkcs8-pem-sha1", "24420": "pkcs8-pem-sha256",
		"15500": "jks-private-key", "27400": "vmware-vmx",
		"27500": "virtualbox-aes128", "27600": "virtualbox-aes256",
		"13300": "axcrypt-sha1",
		"pfx":   "pfx", "p12": "pfx", "pkcs12": "pfx",
		"5200": "pwsafe", "pwsafe": "pwsafe",

		// ── John the Ripper: raw digests ──────────────────────────────────────────
		"raw-md2": "md2", "raw-md4": "md4", "raw-md5": "md5", "raw-md5u": "md5-utf16le",
		"raw-sha1": "sha1", "raw-sha1-ng": "sha1", "raw-sha1-axcrypt": "axcrypt-sha1",
		"raw-sha224": "sha224", "raw-sha256": "sha256",
		"raw-sha384": "sha384", "raw-sha512": "sha512",
		"raw-sha3-224": "sha3_224", "raw-sha3-256": "sha3_256",
		"raw-sha3-384": "sha3_384", "raw-sha3-512": "sha3_512",
		// John's Raw-SHA3 is the 512-bit variant; Raw-Keccak likewise.
		"raw-sha3": "sha3_512", "raw-keccak": "keccak512", "raw-keccak-224": "keccak224",
		"raw-keccak-256": "keccak256", "raw-keccak-384": "keccak384",
		"raw-blake2": "blake2b", "raw-blake2s": "blake2s", "raw-sm3": "sm3",
		"raw-ripemd320": "ripemd320", "nt": "ntlm", "whirlpool": "whirlpool",
		"gost-2012-256": "streebog256", "gost-2012-512": "streebog512",

		// ── John the Ripper: crypt(3) and system ──────────────────────────────────
		"md5apr1": "apr1", "netbsd-sha1": "sha1crypt",
		"aix-ssha256": "aix", "aix-ssha512": "aix",
		"pbkdf2-hmac-md5": "pbkdf2", "pbkdf2-hmac-sha1": "pbkdf2",
		"pbkdf2-hmac-sha256": "pbkdf2", "pbkdf2-hmac-sha512": "pbkdf2",

		// ── John the Ripper: databases ────────────────────────────────────────────
		"mysql": "mysql323", "mysql-sha1": "mysql41", "mysqlna": "mysql-cram",
		"mssql": "mssql2000", "mssql05": "mssql2005", "mssql12": "mssql2012",
		"oracle": "oracle-h", "oracle11": "oracle11g", "sybasease": "sybase",
		"pstoken": "peoplesoft-token",

		// ── John the Ripper: network / directory ──────────────────────────────────
		"netntlm": "netntlmv1", "mscash": "dcc", "mscash2": "dcc2",
		"wpapsk": "wpa", "salted-sha1": "ldap", "nsldap": "ldap", "nsldaps": "ldap",
		"rakp": "ipmi", "citrix_ns10": "citrix", "krb5pa-md5": "krb5pa", "krb5pa-sha1": "krb5pa",
		"nsec3": "dnssec-nsec3",
		"sapb":  "sap-b", "sapg": "sap-fg", "saph": "sap-issha512",
		"restful-auth": "rails-restful-auth", "web2py": "web2py-pbkdf2",
		"flask": "flask-session", "wpbcrypt": "wordpress-bcrypt",
		"tacacs": "tacacs-plus", "oracle-otm": "oracle-otm", "xmpp-scram": "xmpp-scram",
		"notes": "apple-secure-notes", "office2016": "office2016-sheet", "oldoffice": "office-old",
		"snmp": "snmpv3",
		"qnx":  "qnx-sha512", "telegram": "telegram-passcode",

		// ── John the Ripper: containers and wallets ───────────────────────────────
		"rar": "rar4", "agilekeychain": "1password", "itunes-backup": "itunes",
		"episerver": "episerver", "peoplesoft": "peoplesoft",
		"hmailserver": "hmailserver", "coldfusion": "sha256-salt-uppersha1pass",
		"filezilla-server": "sha512-pass-salt",
		"vc":               "veracrypt",

		// ── John the Ripper: dynamic formats ──────────────────────────────────────
		"dynamic_0": "md5", "dynamic_1": "md5-pass-salt", "dynamic_2": "md5-md5",
		"dynamic_3": "md5-md5-md5", "dynamic_4": "md5-salt-pass",
		"dynamic_5": "md5-salt-pass-salt", "dynamic_6": "md5-md5pass-salt",
		"dynamic_8": "md5-salt-md5pass", "dynamic_9": "md5-salt-md5saltpass",
		"dynamic_10": "md5-salt-pass-salt", "dynamic_11": "md5-md5salt-pass",
		"dynamic_12": "md5-md5salt-md5pass", "dynamic_13": "md5-md5pass-md5salt",
		"dynamic_14": "md5-salt-md5pass-salt",
		"dynamic_22": "md5-sha1", "dynamic_23": "sha1-md5",
		"dynamic_24": "sha1-pass-salt", "dynamic_25": "sha1-salt-pass",
		"dynamic_26": "sha1", "dynamic_27": "md5crypt", "dynamic_28": "apr1",
		"dynamic_29": "md5-utf16le", "dynamic_30": "md4", "dynamic_33": "ntlm",
		"dynamic_60": "sha256", "dynamic_61": "sha256-pass-salt",
		"dynamic_62": "sha256-salt-pass",
	}
}

func legacyLMHash(password string) (string, error) {
	for _, ch := range password {
		if ch > 0x7f {
			return "", errors.New("LM hashing accepts ASCII passwords only")
		}
	}
	upper := strings.ToUpper(password)
	plain := []byte(upper)
	if len(plain) > 14 {
		plain = plain[:14]
	}
	padded := make([]byte, 14)
	copy(padded, plain)
	magic := []byte("KGS!@#$%")
	out := make([]byte, 16)
	for half := 0; half < 2; half++ {
		key := expandLMKey(padded[half*7 : half*7+7])
		cipher, err := des.NewCipher(key[:])
		if err != nil {
			return "", err
		}
		cipher.Encrypt(out[half*8:half*8+8], magic)
	}
	return strings.ToUpper(hex.EncodeToString(out)), nil
}

// expandLMKey spreads 56 key bits across a DES key and sets odd parity.
func expandLMKey(in []byte) [8]byte {
	key := [8]byte{
		in[0] & 0xfe,
		((in[0] << 7) | (in[1] >> 1)) & 0xfe,
		((in[1] << 6) | (in[2] >> 2)) & 0xfe,
		((in[2] << 5) | (in[3] >> 3)) & 0xfe,
		((in[3] << 4) | (in[4] >> 4)) & 0xfe,
		((in[4] << 3) | (in[5] >> 5)) & 0xfe,
		((in[5] << 2) | (in[6] >> 6)) & 0xfe,
		(in[6] << 1) & 0xfe,
	}
	for i, b := range key {
		parity := byte(1)
		for bit := uint(1); bit < 8; bit++ {
			parity ^= (b >> bit) & 1
		}
		key[i] |= parity
	}
	return key
}

func checksumText(text, algorithm string) string {
	data := []byte(text)
	switch algorithm {
	case "crc32":
		return fmt.Sprintf("%08x", crc32.ChecksumIEEE(data))
	case "crc32c":
		return fmt.Sprintf("%08x", crc32.Checksum(data, crc32cTable))
	case "crc64":
		return fmt.Sprintf("%016x", crc64.Checksum(data, crc64Table))
	case "adler32":
		return fmt.Sprintf("%08x", adler32.Checksum(data))
	case "fnv1a32":
		h := uint32(2166136261)
		for _, b := range data {
			h = (h ^ uint32(b)) * 16777619
		}
		return fmt.Sprintf("%08x", h)
	case "fnv1a64":
		h := uint64(14695981039346656037)
		for _, b := range data {
			h = (h ^ uint64(b)) * 1099511628211
		}
		return fmt.Sprintf("%016x", h)
	case "xxhash32":
		return fmt.Sprintf("%08x", xxhash32(data))
	case "xxhash64":
		return fmt.Sprintf("%016x", xxhash64(data))
	case "murmur3-32":
		return fmt.Sprintf("%08x", murmur3_32(data))
	default:
		return ""
	}
}

func encodeHashOutput(hexDigest, encoding string) (string, error) {
	codec := canonicalCodecType(encoding)
	if codec == "" || codec == "hex" {
		return hexDigest, nil
	}
	if !hashOutputCodecs[codec] {
		return "", fmt.Errorf("unsupported hash output encoding: %s", encoding)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(hexDigest, "0x"), "0X"))
	if err != nil {
		return "", fmt.Errorf("%s output is only supported for raw hexadecimal digests", encoding)
	}
	return encodeText(string(raw), codec, 0, "", 2)
}
