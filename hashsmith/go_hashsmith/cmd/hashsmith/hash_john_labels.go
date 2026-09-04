package main

// johnLabelSeed maps a canonical Hashsmith format to the label John the Ripper
// accepts after --format=.
//
// This is deliberately a separate, hand-curated table rather than a filter over
// the alias map. Aliases are an INPUT vocabulary — every spelling anyone might
// type — and they carry no provenance, so "raw-md5" and "md-5" are the same
// kind of thing there. Reporting a John label is an OUTPUT claim about another
// tool's interface, and it has to be right or not made at all.
//
// Coverage is intentionally incremental: a format absent from this table prints
// "-" in identify's john column, and `identify --coverage` counts the gap.
func johnLabelSeed() map[string]string {
	return map[string]string{
		// Raw digests
		"md4": "raw-md4", "md5": "raw-md5", "sha1": "raw-sha1",
		"sha224": "raw-sha224", "sha256": "raw-sha256",
		"sha384": "raw-sha384", "sha512": "raw-sha512",
		"ripemd128": "ripemd-128", "ripemd160": "ripemd-160",
		"whirlpool": "whirlpool", "sm3": "sm3",

		// Windows
		"ntlm": "NT", "lm": "LM",
		"netntlmv1": "netntlmv1", "netntlmv2": "netntlmv2",
		"dcc": "mscash", "dcc2": "mscash2",

		// Unix crypt(3)
		"descrypt": "descrypt",
		"md5crypt": "md5crypt", "bcrypt": "bcrypt",
		"sha256crypt": "sha256crypt", "sha512crypt": "sha512crypt",
		"sha1crypt": "sha1crypt", "apr1": "md5crypt",

		// Databases
		"mysql323": "mysql", "mysql41": "mysql-sha1",
		"mssql2005": "mssql05", "mssql2012": "mssql12",
		"oracle11g": "oracle11", "oracle12c": "oracle12c",
		"postgres": "postgres", "sybase": "sybasease",

		// Kerberos
		"krb5tgs": "krb5tgs", "krb5asrep": "krb5asrep", "krb5pa": "krb5pa-sha1",

		// Containers and archives
		"7z": "7z", "rar4": "rar", "rar5": "rar5",
		"zipcrypto": "PKZIP", "zipaes256": "ZIP",
		"pdf": "PDF", "office": "office", "keepass": "KeePass",
		"ssh": "SSH", "pfx": "pfx", "gpg": "gpg",
		"luks": "LUKS", "truecrypt": "truecrypt", "veracrypt": "VeraCrypt",
		"pwsafe": "pwsafe", "dmg": "dmg",

		// Applications
		"phpass": "phpass", "drupal7": "Drupal7", "django": "django",
		"mediawiki": "mediawiki",
		"vbulletin": "vbulletin", "ldap": "ssha",
		"sap-b": "sapb", "sap-fg": "sapg",
		"cisco-pix": "pix-md5", "cisco-asa": "asa-md5",
		"juniper": "md5crypt", "grub2": "grub",
		"bitcoin": "bitcoin", "ethereum": "ethereum-opencl",
		"wpa": "wpapsk", "vnc": "VNC", "sip": "SIP",
	}
}
