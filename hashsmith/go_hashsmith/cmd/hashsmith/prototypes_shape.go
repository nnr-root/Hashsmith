package main

import (
	"strconv"
	"strings"

	"hashsmith-go/internal/hashid"
)

// hexShapeProto builds a non-exclusive prototype matching hex of one exact
// length. These are the weakest rules in the table and the only ones that
// coexist: a bare 32-char hex string really could be any of five digests.
func hexShapeProto(length int, display string, prevalence uint8, rationale string,
	against func(hashid.Input) (string, bool), types ...string) hashid.Prototype {
	return hashid.Prototype{
		Types: types, Display: display, Tier: hashid.TierShape, Exclusive: false,
		Match: func(in hashid.Input) (hashid.Evidence, bool) {
			v := in.Normalized
			if len(v) != length || !isHex(v) {
				return "", false
			}
			casing := "lowercase"
			if v == strings.ToUpper(v) && v != strings.ToLower(v) {
				casing = "uppercase"
			}
			return hashid.Evidence(strconv.Itoa(length) + "-char " + casing + " hex"), true
		},
		Against: against, Prevalence: prevalence, Rationale: rationale,
	}
}

func lowercaseRulesOutLM(in hashid.Input) (string, bool) {
	v := in.Normalized
	if v != strings.ToUpper(v) {
		return "LM digests are upper-case", true
	}
	return "", false
}

// isTripcodeShape reports the only thing a tripcode has to show for itself:
// ten characters from crypt(3)'s alphabet.
func isTripcodeShape(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(itoa64, s[i]) < 0 {
			return false
		}
	}
	return true
}

func shapePrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		hexShapeProto(10, "StuffIt5", 5,
			"a 40-bit archive checksum; nothing else in the table is ten hex characters, so claiming it costs nothing",
			nil, "stuffit5"),
		hexShapeProto(16, "MySQL 3.23 / Cisco-PIX / half-MD5", 25,
			"truncated and legacy digests; uncommon as a primary target", nil,
			"mysql323", "cisco-pix", "half-md5"),

		hexShapeProto(32, "MD5", 85,
			"the most common raw digest in leaked credential dumps by a wide margin", nil, "md5"),
		hexShapeProto(32, "MD4", 20,
			"rare standalone; almost always seen inside NTLM instead", nil, "md4"),
		hexShapeProto(32, "MD2", 5,
			"effectively extinct; no modern system emits it", nil, "md2"),
		hexShapeProto(32, "NTLM", 70,
			"ubiquitous in Windows domain compromise work", nil, "ntlm"),
		hexShapeProto(32, "LM (LAN Manager)", 30,
			"obsolete since Vista but still found in old NTDS dumps",
			lowercaseRulesOutLM, "lm"),

		// The scarce digests of each width.
		//
		// None of these is a plausible first guess, and that is exactly why
		// they belong here: a bare digest carries no evidence at all beyond
		// its length, so the only question is whether the tool is willing to
		// try an algorithm nothing rules out. John will, if you name the
		// format; hashcat has no mode for most of them. Every one below is
		// under the extinct-prevalence bar, which means it is reported as
		// "unlikely" with its reason and attacked only after every likelier
		// candidate of the same width has failed.
		hexShapeProto(32, "RIPEMD-128", 5,
			"RIPEMD-128 is the narrow member of a family whose 160-bit version is the one anything actually uses", nil, "ripemd128"),
		hexShapeProto(32, "MDC-2", 3,
			"a hash built out of DES because its designers had no hash function; it survives in older banking and smartcard stacks", nil, "mdc2"),
		hexShapeProto(32, "MD5 of UTF-16LE", 6,
			"the same MD5 over the password as Windows stores it, which several web applications ported from a .NET original emit", nil, "md5-utf16le"),
		hexShapeProto(32, "Lotus Notes/Domino 5", 4,
			"a proprietary digest from a product line that peaked in the 1990s, still present in preserved Domino directories", nil, "domino5"),
		hexShapeProto(32, "Snefru-128", 3,
			"broken at two passes in 1990 and repaired by raising it to eight; the repaired version is what survives, in very little", nil, "snefru128"),
		hexShapeProto(32, "HAVAL-128", 3,
			"HAVAL is parameterised by pass count and output width, and nothing in a bare digest says which; all three pass counts are offered because a run that tried one would miss two thirds of the format", nil,
			"haval128-3", "haval128-4", "haval128-5"),

		hexShapeProto(40, "SHA-1", 80,
			"the second most common raw digest after MD5", nil, "sha1"),
		hexShapeProto(40, "SHA-0", 5,
			"withdrawn in 1995; effectively never encountered", nil, "sha0"),
		hexShapeProto(40, "RIPEMD-160", 20,
			"mainly seen via Bitcoin address derivation", nil, "ripemd160"),
		hexShapeProto(40, "HAS-160", 4,
			"the Korean national standard's hash, which appears where KCDSA does and essentially nowhere else", nil, "has160"),
		hexShapeProto(40, "HAVAL-160", 3,
			"the 160-bit HAVAL width, in all three pass counts for the reason the 128-bit one lists", nil,
			"haval160-3", "haval160-4", "haval160-5"),
		// Three shapes that say a little more than a length, and still not
		// much: a run of zeros where a dump or a truncation put them, and
		// ten characters of crypt(3) output. All three stay TierShape and
		// non-exclusive like everything else here, because a real SHA-1 can
		// begin or end with those zeros and ten crypt characters are ten
		// crypt characters. They add a reading; they do not take one away.
		{
			Types: []string{"sha1-linkedin"}, Display: "SHA-1, LinkedIn dump (first five digits zeroed)",
			Tier: hashid.TierShape,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "forty hex characters beginning with five zeros", isSHA1LinkedIn(in.Normalized)
			},
			Prevalence: 15,
			Rationale:  "the 2012 LinkedIn dump is six and a half million hashes and is still circulated in that form, which is the only reason this shape has a name",
		},
		{
			Types: []string{"axcrypt-sha1"}, Display: "AxCrypt 1 in-memory SHA-1 (truncated, zero-padded)",
			Tier: hashid.TierShape,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "forty hex characters ending in eight zeros", isBareAxCryptSHA1(in.Normalized)
			},
			Prevalence: 8,
			Rationale:  "AxCrypt keeps only the first sixteen bytes, and a genuine SHA-1 ends in eight zero digits once in four billion",
		},
		{
			Types: []string{"tripcode"}, Display: "Japanese imageboard tripcode",
			Tier: hashid.TierShape,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "ten characters from crypt(3)'s alphabet", isTripcodeShape(in.Normalized)
			},
			Prevalence: 6,
			Rationale:  "a tripcode is ten characters of crypt(3) output with nothing else to go on, so it is offered as a possibility rather than asserted",
		},

		hexShapeProto(56, "SHA-224", 30, "uncommon; SHA-256 is chosen instead", nil, "sha224"),
		hexShapeProto(56, "SHA-512/224", 10, "rare truncated variant", nil, "sha512_224"),
		hexShapeProto(56, "SHA3-224", 10, "rare; SHA-3 adoption is thin", nil, "sha3_224"),
		hexShapeProto(56, "Keccak-224", 10, "rare outside Ethereum tooling", nil, "keccak224"),
		hexShapeProto(56, "HAVAL-224", 3,
			"the 224-bit HAVAL width, in all three pass counts", nil,
			"haval224-3", "haval224-4", "haval224-5"),
		hexShapeProto(56, "Skein-512-224", 4,
			"a SHA-3 finalist that lost; it is implemented widely enough to appear and chosen rarely enough to surprise", nil, "skein224"),

		// Forty-eight hex characters is a 192-bit digest, and until now the
		// only reading this table offered for it was macOS 10.4's salt and
		// SHA-1 run together — whose own note in prototypes_records_salted.go
		// says, correctly, that the same length is a Tiger digest and that
		// neither John nor hashcat can tell the two apart. The hash half of
		// that pair is now here.
		hexShapeProto(48, "Tiger", 8,
			"Tiger is the commonest thing that produces a 192-bit digest, which is not saying much; it survives in file-sharing checksums and in a handful of older applications", nil, "tiger"),
		hexShapeProto(48, "HAVAL-192", 3,
			"the 192-bit HAVAL width, in all three pass counts", nil,
			"haval192-3", "haval192-4", "haval192-5"),

		hexShapeProto(60, "Oracle 11g", 25, "legacy Oracle; still present in old databases", nil, "oracle11g"),
		hexShapeProto(160, "Oracle 12c", 25, "current Oracle password verifier", nil, "oracle12c"),

		hexShapeProto(64, "SHA-256", 85, "the default modern digest choice", nil, "sha256"),
		hexShapeProto(64, "SHA3-256", 15, "thin SHA-3 adoption", nil, "sha3_256"),
		hexShapeProto(64, "SM3", 10, "Chinese national standard; regionally concentrated", nil, "sm3"),
		hexShapeProto(64, "BLAKE2s", 10,
			"BLAKE2s targets 8- to 32-bit platforms per the BLAKE2 specification; general-purpose password-hashing software defaults to BLAKE2b (its 64-bit sibling) or SHA-2 instead", nil, "blake2s"),
		hexShapeProto(64, "Streebog-256", 10, "Russian national standard; regionally concentrated", nil, "streebog256"),
		// GOST R 34.11-94 is Streebog's predecessor with the identical
		// footprint, so it belongs in this family for the same reason
		// Streebog does. Both parameter sets are offered because nothing in a
		// bare digest can choose between them — they are different functions
		// that produce the same shape, and a run that tried only one would
		// miss half the format.
		hexShapeProto(64, "GOST R 34.11-94", 6, "superseded by Streebog in 2012, so it appears in older Russian-standard deployments rather than current ones", nil, "gost", "gost-cryptopro"),
		hexShapeProto(64, "SHA-512/256", 10, "rare truncated variant", nil, "sha512_256"),
		hexShapeProto(64, "Keccak-256", 20, "common in Ethereum tooling", nil, "keccak256"),
		hexShapeProto(64, "SHAKE128-256", 5, "rare XOF output", nil, "shake128-256"),
		hexShapeProto(64, "BLAKE2b-256", 10, "uncommon truncated BLAKE2b", nil, "blake2b256"),
		{
			Types: []string{"postoffice"}, Display: "Post.Office mail server",
			Tier: hashid.TierShape,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "32 hex characters followed by a 32-character printable salt", isPostOffice(in.Normalized)
			},
			Prevalence: 3,
			Rationale:  "a mail server discontinued around 2000; the records that survive are in preserved installations, and the shape is the same 64 characters a SHA-256 is",
		},
		hexShapeProto(64, "PANAMA", 3,
			"broken as a hash in 2001 and again in 2007, so nothing has emitted one deliberately since", nil, "panama"),
		hexShapeProto(64, "Snefru-256", 3,
			"the wide Snefru, as scarce as the narrow one", nil, "snefru256"),
		hexShapeProto(64, "HAVAL-256", 3,
			"the 256-bit HAVAL width, in all three pass counts", nil,
			"haval256-3", "haval256-4", "haval256-5"),
		hexShapeProto(64, "Skein-512-256", 4,
			"Skein truncated to 256 bits; John calls this one \"Skein 256\"", nil, "skein256"),

		// Task 15: this 80-char (40-byte) bucket was simply missing —
		// ripemd320's own self-test vector is a bare 80-hex digest with no
		// distinguishing marker, so it fell through every prototype and was
		// undetectable by auto-detection even though hashing/verification for
		// it were correct. Length and alphabet only, so TierShape, matching
		// every other bucket in this function.
		hexShapeProto(80, "RIPEMD-320", 5,
			"RIPEMD-320 is a rarely-implemented double-width variant of RIPEMD-160; almost no software emits it as a password digest", nil, "ripemd320"),

		hexShapeProto(96, "SHA-384", 40, "used where SHA-512 is considered oversized", nil, "sha384"),
		hexShapeProto(96, "SHA3-384", 10, "thin SHA-3 adoption", nil, "sha3_384"),
		hexShapeProto(96, "BLAKE2b-384", 5, "rare truncated BLAKE2b", nil, "blake2b384"),
		hexShapeProto(96, "Keccak-384", 5, "rare outside Ethereum tooling", nil, "keccak384"),
		hexShapeProto(96, "Skein-512-384", 4, "Skein truncated to 384 bits", nil, "skein384"),

		hexShapeProto(128, "SHA-512", 80, "the common choice for a long digest", nil, "sha512"),
		hexShapeProto(128, "SHA3-512", 10, "thin SHA-3 adoption", nil, "sha3_512"),
		hexShapeProto(128, "BLAKE2b", 20, "the usual BLAKE2b output length", nil, "blake2b"),
		hexShapeProto(128, "Whirlpool", 15, "legacy; appears in older applications", nil, "whirlpool"),
		hexShapeProto(128, "Streebog-512", 10, "regionally concentrated", nil, "streebog512"),
		hexShapeProto(128, "Keccak-512", 10, "rare outside Ethereum tooling", nil, "keccak512"),
		hexShapeProto(128, "SHAKE256-512", 5, "rare XOF output", nil, "shake256-512"),
		hexShapeProto(128, "Skein-512", 4, "Skein at its full width", nil, "skein512"),
		hexShapeProto(128, "Whirlpool, withdrawn revisions", 3,
			"anything hashed before the 2003 revision was hashed with one of these two, and nothing in a bare digest says which", nil,
			"whirlpool0", "whirlpool1"),
		hexShapeProto(128, "Cisco ISE", 10, "single-product format", nil, "cisco-ise"),

		// A Notes user.id blob is a ciphertext, not a digest, so its length is
		// whatever the file held — John accepts anything from 40 to 100 bytes.
		// It is offered by shape only at the width every blob seen so far has,
		// because the wider rule would add it to every SHA-512 and Whirlpool
		// digest in the world for no gain. The reader accepts the full range
		// when the type is named with -t.
		hexShapeProto(112, "Lotus Notes 8.5 user.id blob", 3,
			"not a digest at all but an RC2 ciphertext, recognised only by its width; nothing else of this length is in common use", nil, "lotus85"),
	}
}

// tailPrototypes ports the three branches that ran immediately ahead of the
// trailing `switch len(t)` in the legacy cascade: a bitcoin/litecoin
// address-recovery target, a Mojolicious signed cookie, and a Blockchain.info
// second-password record (bitcoinAddressHashTypes, then the inline "--"
// separator check, then parseBlockchainSecond, in that order in the original
// code). None of the eight porting batches (now split across prototypes_records_*.go) claimed
// these three, and the task-10 brief's own listing of what those batches
// cover does not mention them either — they are a genuine gap, not something
// this task's brief says to delete. Deleting the legacy fallback cascade
// without porting them would silently drop detection for every golden-file
// line that exercises them (see testdata/detect_golden.txt: the
// bitcoin-wif/-raw groups, "blockchain-second", and "mojolicious").
//
// All three were unconditional early `return`s in the legacy cascade, so like
// every other ported branch except the shape group itself, they are
// Exclusive. Table order relative to shapePrototypes() does not matter for
// correctness (none of these three shapes is valid hex of a length the shape
// group recognizes, so they can never compete with it for the same input),
// but they are appended here, ahead of shapePrototypes(), to mirror their
// position in the original cascade: before the shape switch.
func tailPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		// bitcoinAddressHashTypes has two independent paths with different
		// evidentiary strength, so each gets its own prototype and its own
		// honest tier rather than one prototype claiming the stronger of the
		// two for both:
		//
		//   - the bech32 path is a bare "bc1q" prefix check, nothing else. It
		//     does NOT call bech32Polymod (codecs_checksums.go), the verifier
		//     isBech32 (identify.go) already uses elsewhere in this codebase.
		//     Tagging this TierChecksum would let confidenceFor report
		//     "certain" for any string that merely starts with four fixed
		//     characters — a claim of proof where nothing was verified.
		//   - the base58check path calls decodeBase58Check, which genuinely
		//     verifies a SHA-256d checksum before this prototype matches, so
		//     TierChecksum is earned there.
		//
		// Both remain Exclusive: true, matching their unconditional early
		// `return` in the legacy cascade. Order preserved from the original
		// `if bc1q ... else if decodeBase58Check ...`: bech32 first.
		{
			Types: []string{
				"bitcoin-wif-p2wpkh-compressed", "bitcoin-wif-p2wpkh-uncompressed",
				"bitcoin-raw-p2wpkh-compressed", "bitcoin-raw-p2wpkh-uncompressed",
			},
			Display: "Bitcoin/Litecoin address recovery target (bech32 prefix)",
			Tier:    hashid.TierStructural, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if !strings.HasPrefix(strings.ToLower(in.Normalized), "bc1q") {
					return "", false
				}
				return "bc1q prefix present; the bech32 polymod checksum is not verified here", true
			},
			Prevalence: 20,
			Rationale:  "the bc1q human-readable-part prefix is how a mainnet P2WPKH bech32 address is conventionally spelled, but this prototype checks only that four-character prefix — bech32's own polymod checksum (already implemented in codecs_checksums.go and used by isBech32 elsewhere in this codebase) is not evaluated here, so a match is shape evidence only, not a verified address",
		},
		{
			Display: "Bitcoin/Litecoin address recovery target (base58check)",
			Tier:    hashid.TierChecksum, Exclusive: true,
			Compute: func(in hashid.Input) ([]string, bool) {
				// bitcoinAddressHashTypes also has a bc1q branch, but the
				// sibling prototype above already claims that input; guard it
				// out here so this prototype's own checksum-verified evidence
				// is never used to justify a bech32 match.
				if strings.HasPrefix(strings.ToLower(in.Normalized), "bc1q") {
					return nil, false
				}
				types := bitcoinAddressHashTypes(in.Normalized)
				return types, len(types) > 0
			},
			Prevalence: 20,
			Rationale:  "Bitcoin has held the largest market capitalization of any cryptocurrency since its creation, so P2PKH/P2SH-P2WPKH address-recovery casework (WIF or raw secp256k1 key against a supplied address) concentrates on it far more than on the many altcoins sharing the same address scheme; unlike the sibling bech32-prefix prototype above, base58check's SHA-256d checksum is verified before this one matches",
		},
		predicateProto(isMojoliciousRecord, "Perl Mojolicious signed cookie", hashid.TierStructural,
			`record shape <data>--<64-char hex HMAC>, with "=" in the data field`,
			10, "Mojolicious is a single Perl web framework's session-cookie format (Hashcat mode 16501), so this record shape recurs only in casework that specifically targets a Mojolicious-based application", "mojolicious"),
		predicateProto(isBlockchainSecondRecord, "Blockchain.info wallet second password", hashid.TierChecksum,
			"parses as a Blockchain.info second-password record (base64, 59 decoded bytes, \"bs:\" tag, valid CRC32 trailer)",
			15, "Blockchain.info (now Blockchain.com) was one of the earliest and largest hosted web wallets, so its optional second-password feature (Hashcat mode 18800) recurs in exchange/web-wallet forensics more than the many single-vendor KDF records this table also covers", "blockchain-second"),
	}
}
