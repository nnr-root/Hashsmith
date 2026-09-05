package main

import (
	"fmt"
	"strconv"
	"strings"

	"hashsmith-go/internal/hashid"
)

// nonHashPrototypes ports the non-hash recognitions that lived in the deleted
// scoreEncodingGroup, scoreStructuralGroup and scoreCipherTextGroup (plus four
// signatureMatch branches: Bubble Babble, Bech32, Bech32m and PEM — see
// identify.go's history). hashid, Name-That-Hash and haiti only ever look for
// hash shapes; recognizing that a candidate is Base64, Morse code or a Bech32
// address instead — rather than reporting nothing — is a real Hashsmith
// advantage that must not disappear along with the scorer that held it.
//
// Every entry here is Exclusive: false and Tier is TierStructural or
// TierShape, never TierSignature or TierChecksum, even where the underlying
// predicate happens to verify a checksum (Bech32's polymod, Bubble Babble's
// running checksum): these are encodings, not passwords, and the point of
// this table is to make evidence-strength claims that hold up, not to
// maximize a Tier.
//
// Fix round 1: this file's own stated invariant ("every entry here is
// Exclusive: false") was false for the dozen entries built with
// predicateProto — that helper hardcodes Exclusive: true, which is correct
// for the cascade batches it was built for (prototypes_records.go) but wrong
// here: it made these non-hash prototypes suppress EACH OTHER (Evaluate's
// "first exclusive match wins, everything else — before or after it — is
// suppressed" rule applies regardless of which prototype is exclusive), so
// e.g. "0 1 2 3 4 5 6 7" reported "likely" Crockford Base32 while ruling out
// Decimal and Octal as "ruled out by a stronger match" even though nothing
// about Crockford's evidence is stronger. predicateProtoShared below wraps
// predicateProto and clears Exclusive; every non-hash entry in this file
// uses it now. predicateProto itself, and every batch outside this file that
// calls it, is untouched — those are cascade ports whose Exclusive: true is
// correct.
func predicateProtoShared(fn func(string) bool, display string, tier hashid.Tier, evidence string, prevalence uint8, rationale string, types ...string) hashid.Prototype {
	p := predicateProto(fn, display, tier, evidence, prevalence, rationale, types...)
	p.Exclusive = false
	return p
}

// Two categories of formats the deleted groups also recognized are
// deliberately NOT ported: Plain Text and the Caesar/Vigenere/ROT13
// "Substitution Cipher" guess. Both were entropy/chi-squared HEURISTICS —
// probabilistic judgment calls with no deterministic Match predicate — and
// Plain Text in particular would fire on ordinary English ("not a hash at
// all" has a 100% printable-ASCII ratio), which contradicts
// TestUnrecognizedInputSaysSo's requirement that unrecognized text produce
// zero candidates. Base85, Base62 and Leet Speak are also not ported: their
// charsets are broad enough to collide with existing hash-shaped golden
// corpus entries (a 43-char Cisco type 4 hash and a 2ch tripcode both parse
// as valid Base85/Base62/Leet), which would silently change
// testdata/detect_golden.txt. Each omission was verified empirically by
// running the golden corpus through the prototype table with each candidate
// prototype appended, not guessed from reading the old code.
func nonHashPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		{
			Types: []string{"base64"}, Display: "Base64", Tier: hashid.TierStructural, Exclusive: false,
			// A bare charset match would also match every lowercase hash-length
			// hex string in the table (hex is a subset of the Base64 alphabet),
			// so hex is excluded outright. Requiring successful decode PLUS
			// either "=" padding or a printable-text result is what separates a
			// real Base64 transport encoding (padding is basically never present
			// on a hash/salt/address token) from an incidentally alphanumeric
			// hash-shaped string (a Cisco tripcode, an "0x..."-prefixed hex
			// record) that merely happens to satisfy the charset.
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isHex(v) || !reBase64Std.MatchString(v) || len(v)%4 == 1 {
					return "", false
				}
				dec, err := decodeBase64Flexible(v, false)
				if err != nil {
					return "", false
				}
				switch {
				case strings.HasSuffix(v, "="):
					return "valid Base64 charset with standard padding", true
				case allPrintable(dec):
					return "decodes to printable text", true
				}
				return "", false
			},
			Prevalence: 40, Rationale: "Base64 is the default binary-to-text transport for JSON APIs, config files and email attachments, so it is the encoding most likely to be pasted into identify by accident",
		},
		{
			Types: []string{"base32"}, Display: "Base32", Tier: hashid.TierStructural, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isHex(v) {
					return "", false
				}
				upper := strings.ToUpper(v)
				if !reBase32Std.MatchString(upper) {
					return "", false
				}
				if _, err := decodeBase32Flexible(upper, false); err != nil {
					return "", false
				}
				return "decodes as RFC 4648 Base32", true
			},
			Prevalence: 25, Rationale: "seen mainly in TOTP secret keys and DNSSEC/DNS-label contexts; less common than Base64 as a general transport",
		},
		{
			Types: []string{"base32hex"}, Display: "Base32hex", Tier: hashid.TierStructural, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isHex(v) {
					return "", false
				}
				upper := strings.ToUpper(v)
				// Require a digit outside the standard Base32 alphabet so a
				// string valid in both alphabets is reported as plain Base32,
				// not double-counted here too.
				if !reBase32Hex.MatchString(upper) || !strings.ContainsAny(upper, "0189") {
					return "", false
				}
				if _, err := decodeBase32Flexible(upper, true); err != nil {
					return "", false
				}
				return "decodes as RFC 4648 extended-hex Base32", true
			},
			Prevalence: 10, Rationale: "no basis for a better estimate; revisit with corpus data",
		},
		predicateProtoShared(func(v string) bool { return !isHex(v) && isCrockfordCandidate(v) },
			"Crockford Base32", hashid.TierStructural, "decodes under the Crockford Base32 alphabet (O/I/L typo-tolerant)",
			10, "no basis for a better estimate; revisit with corpus data", "base32crockford"),
		predicateProtoShared(func(v string) bool { return !isHex(v) && isZBase32Candidate(v) },
			"z-base-32", hashid.TierStructural, "canonical z-base-32 alphabet; round-trips through its own encoder",
			10, "no basis for a better estimate; revisit with corpus data", "zbase32"),
		{
			// A real double-SHA256 checksum is verified here — the same proof
			// tailPrototypes()' Bitcoin/Litecoin base58check entry relies on
			// for its own TierChecksum — so this earns TierChecksum too, the
			// one deliberate exception to this file's TierStructural/TierShape
			// rule. It is non-exclusive and placed after every hash prototype,
			// so for an actual Bitcoin address the earlier, more specific
			// exclusive prototype still wins and this is merely suppressed
			// alongside everything else (verified empirically against the
			// golden corpus); this entry only ever surfaces for a Base58Check
			// payload that isn't a recognized coin address.
			Types: []string{"base58check"}, Display: "Base58Check", Tier: hashid.TierChecksum, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if strings.HasPrefix(strings.ToLower(v), "bc1q") || len(bitcoinAddressHashTypes(v)) > 0 {
					return "", false
				}
				if _, err := decodeBase58Check(v); err != nil {
					return "", false
				}
				return "valid double-SHA256 Base58Check checksum", true
			},
			Prevalence: 15, Rationale: "Base58Check payloads outside a coin-address shape appear mainly in wallet/vendor-specific export formats; narrower than a bare hash",
		},
		{
			Types: []string{"base58"}, Display: "Base58", Tier: hashid.TierShape, Exclusive: false,
			// Deliberately no checksum verification here: Base58Check (above)
			// is a stronger, separate claim; this entry is the plain,
			// unchecksummed alphabet, so it earns only TierShape.
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isHex(v) || !reBase58Pat.MatchString(v) || len(v) < 8 {
					return "", false
				}
				if _, err := decodeBase58(v); err != nil {
					return "", false
				}
				return "valid Base58 charset (no checksum verified)", true
			},
			Prevalence: 20, Rationale: "the Bitcoin alphabet is common for cryptocurrency-adjacent identifiers, but a bare unchecksummed Base58 string is otherwise unremarkable",
		},
		{
			// Stronger evidence than plain Base64: the decoded payload's own
			// magic bytes confirm what it is, not just that Base64 decoded.
			Types: []string{"gzip"}, Display: "Gzip + Base64", Tier: hashid.TierStructural, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isHex(v) || !reBase64Std.MatchString(v) || len(v)%4 == 1 {
					return "", false
				}
				dec, err := decodeBase64Flexible(v, false)
				if err != nil || len(dec) < 2 || dec[0] != 0x1f || dec[1] != 0x8b {
					return "", false
				}
				return "Base64 payload begins with gzip magic bytes", true
			},
			Prevalence: 15, Rationale: "gzip-then-Base64 is a routine transport for compressed API payloads and log attachments",
		},
		{
			Types: []string{"zlib"}, Display: "Zlib + Base64", Tier: hashid.TierStructural, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isHex(v) || !reBase64Std.MatchString(v) || len(v)%4 == 1 {
					return "", false
				}
				dec, err := decodeBase64Flexible(v, false)
				if err != nil || !looksLikeZlib(dec) {
					return "", false
				}
				return "Base64 payload has a valid zlib header", true
			},
			Prevalence: 10, Rationale: "no basis for a better estimate; revisit with corpus data",
		},
		predicateProtoShared(isUUStr, "UU Encoded", hashid.TierStructural,
			"length-prefixed UU line format", 10, "no basis for a better estimate; revisit with corpus data", "uu"),
		predicateProtoShared(isPEMData, "PEM", hashid.TierStructural,
			"BEGIN/END block with a valid Base64 payload", 15,
			"PEM wraps certificates and private keys, both routine in TLS and SSH tooling, but is rare as an identify target compared to a bare hash", "pem"),
		predicateProtoShared(func(v string) bool { return isBech32(v, "bech32") }, "Bech32", hashid.TierStructural,
			"valid Bech32 polymod checksum", 20,
			"Bech32 is the current native SegWit address format for Bitcoin and several other UTXO chains", "bech32"),
		predicateProtoShared(func(v string) bool { return isBech32(v, "bech32m") }, "Bech32m", hashid.TierStructural,
			"valid Bech32m polymod checksum", 10,
			"Bech32m covers only Taproot addresses, a narrower slice of wallet traffic than Bech32", "bech32m"),
		predicateProtoShared(isBubbleBabble, "Bubble Babble", hashid.TierStructural,
			"valid pronounceable Bubble Babble record", 10,
			"Bubble Babble fingerprints appear mainly in older SSH tooling (ssh-keygen -B); rare in general corpora", "bubblebabble"),
		predicateProtoShared(reUUID.MatchString, "UUID", hashid.TierStructural,
			"8-4-4-4-12 hex groups", 30,
			"UUIDs are a ubiquitous identifier format across databases and APIs, so a random-looking token is fairly likely to be one rather than a hash", "uuid"),
		{
			Types: []string{"nato"}, Display: "NATO Phonetic Alphabet", Tier: hashid.TierStructural, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				ok, count := isNATOStr(in.Normalized)
				if !ok {
					return "", false
				}
				return hashid.Evidence(fmt.Sprintf("%d phonetic words detected", count)), true
			},
			Prevalence: 10, Rationale: "no basis for a better estimate; revisit with corpus data",
		},
		predicateProtoShared(isBinaryStr, "Binary", hashid.TierStructural,
			"space-separated 8-bit groups", 10, "no basis for a better estimate; revisit with corpus data", "binary"),
		predicateProtoShared(isDecimalStr, "Decimal", hashid.TierStructural,
			"space-separated byte values 0-255", 10, "no basis for a better estimate; revisit with corpus data", "decimal"),
		predicateProtoShared(isOctalStr, "Octal", hashid.TierStructural,
			"space-separated octal byte values", 10, "no basis for a better estimate; revisit with corpus data", "octal"),
		// Fix round 1 (Critical): Morse was never ported in the first pass —
		// isMorseStr survived as dead code and "morse" was a resolvable
		// format with no prototype behind it, so a genuine Morse string like
		// ".... . .-.. .-.. ---" (HELLO) fell through to Brainf*ck below,
		// which shares Morse's dot/dash characters. Ported here, mirroring
		// Binary/Decimal/Octal above.
		predicateProtoShared(isMorseStr, "Morse Code", hashid.TierStructural,
			"dot/dash/slash pattern", 10, "no basis for a better estimate; revisit with corpus data", "morse"),
		predicateProtoShared(isBaconianStr, "Baconian Cipher", hashid.TierStructural,
			"5-char A/B groups", 10, "no basis for a better estimate; revisit with corpus data", "baconian"),
		predicateProtoShared(isPolybiusStr, "Polybius Square", hashid.TierStructural,
			"digit-pair groups (1-5)", 10, "no basis for a better estimate; revisit with corpus data", "polybius"),
		{
			Types: []string{"brainf*ck"}, Display: "Brainf*ck", Tier: hashid.TierShape, Exclusive: false,
			// Mirrors the deleted scoreStructuralGroup's own guard exactly
			// (`if !morseMatch && isBrainfuckStr(v)`): Brainfuck's operator
			// set (+-<>[].,) overlaps Morse's alphabet (.-/space) in its two
			// most frequent characters, '.' and '-', so an unambiguous Morse
			// string like ".... . .-.. .-.. ---" also satisfies
			// isBrainfuckStr's "≥60% operators" threshold. Excluding
			// Morse-shaped input here (rather than tightening isBrainfuckStr
			// itself) keeps the shared helper's behavior unchanged for any
			// other caller and restores exactly the mutual exclusion the
			// original cascade had, instead of inventing a new rule.
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isMorseStr(v) || !isBrainfuckStr(v) {
					return "", false
				}
				return "BF operator set (+-<>[].,) is at least 60% of non-whitespace characters", true
			},
			Prevalence: 10, Rationale: "no basis for a better estimate; revisit with corpus data",
		},
		{
			Types: []string{"url"}, Display: "URL Encoded", Tier: hashid.TierShape, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				matches := reURLEnc.FindAllString(in.Normalized, -1)
				if len(matches) == 0 {
					return "", false
				}
				return hashid.Evidence(fmt.Sprintf("%d %%XX sequences", len(matches))), true
			},
			Prevalence: 25, Rationale: "percent-encoding is routine in URLs and query strings, which is exactly the kind of text likely to be pasted into identify by mistake",
		},
		{
			Types: []string{"json"}, Display: "JSON String Escapes", Tier: hashid.TierShape, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				matches := reJSONEsc.FindAllString(in.Normalized, -1)
				if len(matches) == 0 {
					return "", false
				}
				return hashid.Evidence(fmt.Sprintf("%d JSON escape sequences", len(matches))), true
			},
			Prevalence: 20, Rationale: "JSON string escapes turn up whenever a hash is copied out of a log line or API response verbatim, quotes included",
		},
		{
			Types: []string{"hex-escape"}, Display: "C-style Hex Escapes", Tier: hashid.TierStructural, Exclusive: false,
			// The whole string must be \xNN groups back-to-back (len(matches)*4
			// == len(v)); a few escapes inside a longer string is not this
			// format, it is text that happens to contain some.
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				matches := reHexEsc.FindAllString(v, -1)
				if len(matches) == 0 || len(matches)*4 != len(v) {
					return "", false
				}
				return hashid.Evidence(strconv.Itoa(len(matches)) + " \\xNN byte escapes"), true
			},
			Prevalence: 10, Rationale: "no basis for a better estimate; revisit with corpus data",
		},
		{
			// Base45 round-trips through its own encoder before being
			// reported, which is why — unlike Base32/Base58/Crockford above —
			// a bare charset match is not enough: its alphabet is wide enough
			// to overlap ordinary punctuation-heavy text, and only a
			// successful re-encode confirms the string is actually a
			// canonical member of the alphabet rather than incidentally
			// composed of its characters. isHex is excluded because, unlike
			// every guard verified only against the golden corpus, this one
			// was caught by a real test: "ABCDEF123456" (a hex string of a
			// length no hash prototype claims) round-trips through Base45
			// cleanly, and a hex-shaped identify target should never be
			// reported as Base45.
			Types: []string{"base45"}, Display: "Base45", Tier: hashid.TierStructural, Exclusive: false,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				v := in.Normalized
				if isHex(v) || len(v) < 4 || len(v)%3 == 1 || !strings.ContainsAny(v, "0123456789$%*+-./:") {
					return "", false
				}
				dec, err := decodeBase45(v)
				if err != nil || encodeBase45(dec) != v {
					return "", false
				}
				return "valid RFC 9285 Base45 groups", true
			},
			Prevalence: 10, Rationale: "no basis for a better estimate; revisit with corpus data",
		},
		// basE91 and Z85 are deliberately NOT ported here even though both
		// round-trip through their own encoder the same way Base45 does
		// above. Both were caught producing false positives on ordinary text
		// that plain golden-corpus diffing missed entirely, because they were
		// not hash-shaped inputs at all:
		//   - basE91's alphabet is broad enough that "password_hash=[<a real
		//     md5 hex digest>]" — an ordinary scanned log line, exercised by
		//     TestExtractorTextFormats/scan — round-trips cleanly through it.
		//     A false "this whole line is basE91" match there does not just
		//     misname a display row: extractScannedRecords treats any line
		//     detectHashTypes recognizes as a whole hash record, so this
		//     would have started vacuuming ordinary log lines into extracted
		//     hash lists.
		//   - Z85's 5-character-block round-trip produces false positives
		//     against the frozen golden corpus itself (a 2ch tripcode target
		//     and a colon-joined hash:salt record both round-trip through
		//     it), which would change testdata/detect_golden.txt.
		// Base45's own isHex escape above was found the same way (a real
		// test, not the golden corpus), which is why it stayed in only after
		// gaining that guard — basE91 and Z85 have no equally narrow guard
		// available (basE91's false positive is not hex; Z85's was a
		// tripcode and a colon-joined record) and were dropped instead.
	}
}
