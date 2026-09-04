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
//
// A format whose ciphertexts map to MORE THAN ONE John format gets no entry
// here, rather than an arbitrary or "best guess" one. Two worked examples that
// were tried and reverted:
//
//   - "ldap" is an umbrella over ten RFC 2307 schemes ({SSHA}/{SMD5}/{SHA}/
//     {MD5}/... plus a {CRYPT} wrapper that dispatches to any crypt(3)
//     format, crack_ldap.go:33-68) — John has no single format for it, and
//     the format's own self-test vector is a {CRYPT}$1$... md5crypt payload,
//     not an SSHA one.
//   - "krb5pa" covers etype 23 (RC4) and etypes 17/18 (AES) under one
//     canonical name (types.go), but John splits these into krb5pa-md5 and
//     krb5pa-sha1 — the alias seed already treats them as separate spellings
//     collapsing to this one canonical (hash_extra.go), which is exactly why
//     a single label here would be a guess.
//
// Do not re-add either: reporting one of several true labels is worse than
// reporting none, because it tells a user to run `john --format=X` against
// ciphertexts John's own format detection would reject.
//
// TestJohnLabelSeedNamesRealFormats only proves every KEY here names a format
// that exists in universalHashRegistry. It cannot and does not prove a VALUE
// is the correct label for that format — that is a claim about John's
// interface, not this registry, and has to be checked by hand against John's
// own format list and Hashsmith's crack/self-test code for that format. The
// test's guarantee is narrower than it looks; do not read a passing run as
// confirmation that a value is right.
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
		"krb5tgs": "krb5tgs", "krb5asrep": "krb5asrep",

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
		"vbulletin": "vbulletin",
		"sap-b": "sapb", "sap-fg": "sapg",
		"cisco-pix": "pix-md5", "cisco-asa": "asa-md5",
		"grub2": "grub",
		"bitcoin": "bitcoin", "ethereum": "ethereum-opencl",
		"wpa": "wpapsk", "vnc": "VNC", "sip": "SIP",
	}
}
