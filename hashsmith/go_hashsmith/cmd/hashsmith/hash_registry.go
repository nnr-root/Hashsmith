package main

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// hashFormat is the complete runtime view of one Hashsmith format. External
// tool identifiers are aliases of a format; they are not counted as additional
// hash implementations.
type hashFormat struct {
	name        string
	description string
	group       string
	aliases     []string
	vectors     []selfTestVector
	slow        bool
	// identifyOnly marks a format identify.go's prototype table can
	// recognize (Base64, Morse, Bech32, ...) that `crack` has no routine
	// for. It is true only for formats registered via
	// nonHashRecognitionFormatSeed. See (*hashRegistry).crackable.
	identifyOnly bool
}

// hashRegistry is Hashsmith's single source of truth for hash/code metadata.
// The large literals remain split into seed functions so they are reviewable,
// but they are normalized exactly once into this immutable runtime index.
type hashRegistry struct {
	formats map[string]*hashFormat
	order   []string
	aliases map[string]string
	groups  []typeGroup
	vectors []selfTestVector
}

// universalHashRegistry is deliberately the only package-level registry
// variable. Catalogue output, alias routing, self-tests, coverage, and reported
// totals all consume it.
var universalHashRegistry = buildHashRegistry()

func buildHashRegistry() *hashRegistry {
	registry := &hashRegistry{
		formats: make(map[string]*hashFormat),
		aliases: make(map[string]string),
		groups:  hashTypeCatalogueSeed(),
	}

	ensureFormat := func(name, description, group string) *hashFormat {
		name = strings.ToLower(strings.TrimSpace(name))
		format := registry.formats[name]
		if format == nil {
			format = &hashFormat{name: name, description: description, group: group}
			registry.formats[name] = format
			registry.order = append(registry.order, name)
		} else {
			if format.description == "" && description != "" {
				format.description = description
			}
			if format.group == "" && group != "" {
				format.group = group
			}
		}
		return format
	}

	// Literal -t tokens establish the presentation order and descriptions.
	for _, group := range registry.groups {
		for _, item := range group.items {
			if name, ok := literalCatalogueType(item[0]); ok {
				ensureFormat(name, item[1], group.title)
			}
		}
	}

	aliases := compatibilityHashAliasSeed()
	for alias, canonical := range spellingHashAliasSeed() {
		if existing, ok := aliases[alias]; ok && existing != canonical {
			panic("conflicting hash alias " + alias)
		}
		aliases[alias] = canonical
	}
	aliasNames := make([]string, 0, len(aliases))
	for alias := range aliases {
		aliasNames = append(aliasNames, alias)
	}
	sort.Strings(aliasNames)
	for _, alias := range aliasNames {
		canonical := aliases[alias]
		format := ensureFormat(canonical, "", "")
		registry.aliases[alias] = canonical
		format.aliases = append(format.aliases, alias)
	}

	registry.vectors = append(registry.vectors, baseSelfTestVectorSeed()...)
	registry.vectors = append(registry.vectors, hashcatBatchSelfTestVectorSeed()...)
	registry.vectors = append(registry.vectors, cryptCascadeSelfTestVectorSeed()...)
	for _, item := range hashcatLegacyCryptAndStreebogVectorSeed() {
		registry.vectors = append(registry.vectors, item.vector)
	}
	registry.vectors = append(registry.vectors, luksOldOfficeSelfTestVectorSeed()...)
	for _, vector := range registry.vectors {
		format := ensureFormat(vector.typ, "", "")
		format.vectors = append(format.vectors, vector)
	}

	for name, slow := range slowSelfTestTypeSeed() {
		ensureFormat(name, "", "").slow = slow
	}

	// Non-hash recognitions (Base64, Morse, Bech32, UUID, ...) get a format
	// entry so hashcatMode/johnLabel/canonicalHashType and the prototype
	// table's integrity check (Prototype.Types must resolve here) all work.
	// The group label is metadata on the format only (satisfying
	// TestUniversalHashRegistryIntegrity's "every format has catalogue
	// metadata" check) — it is deliberately never appended to
	// registry.groups itself, which is the crackable `-t` catalogue
	// `hashsmith types` prints and that TestTypeCatalogueWired asserts is
	// entirely wired into verifyCandidate. These formats have no cracking
	// routine — identify recognizes them, crack does not attack them — so
	// they stay out of that catalogue and out of that promise. See
	// prototypes_nonhash.go.
	const nonHashGroupLabel = "Encodings and structural formats identify recognizes (not crackable via -t)"
	for name, description := range nonHashRecognitionFormatSeed() {
		ensureFormat(name, description, nonHashGroupLabel).identifyOnly = true
	}
	return registry
}

// crackable reports whether `crack -t <name>` has an actual attack routine
// for a format, as opposed to being an identify-only recognition (Base64,
// Morse, Bech32, ...) with no cracking routine at all. identify's rendered
// output uses this to decide whether the trailing command line it prints is
// `crack` (runnable) or `decode` (the honest analogue for a recognized
// encoding) — see renderIdentifyHuman in identify_output.go.
func (r *hashRegistry) crackable(name string) bool {
	format := r.formats[canonicalHashType(name)]
	return format != nil && !format.identifyOnly
}

// nonHashRecognitionFormatSeed names the encodings and structural formats
// identify.go's prototypes_nonhash.go recognizes. hashid, Name-That-Hash and
// haiti only ever look for hash shapes; recognizing that a candidate is
// Base64, Morse code or a Bech32 address instead of a hash is a real
// Hashsmith advantage, but these are not password hashes and `crack` has no
// routine for them, so they are registered here (for hashcatMode/johnLabel/
// canonicalHashType lookups and Prototype.Types resolution) without being
// added to the `-t` catalogue in types.go.
func nonHashRecognitionFormatSeed() map[string]string {
	return map[string]string{
		"base64":          "RFC 4648 Base64",
		"base32":          "RFC 4648 Base32",
		"base32hex":       "RFC 4648 extended-hex Base32",
		"base32crockford": "Crockford Base32 (O/I/L typo-tolerant decoding)",
		"zbase32":         "z-base-32 human-oriented Base32",
		"base58":          "Bitcoin-alphabet Base58",
		"base58check":     "Base58Check (Base58 with a verified double-SHA256 checksum)",
		"base45":          "RFC 9285 Base45",
		"uu":              "UUencoding",
		"pem":             "PEM DATA block",
		"gzip":            "gzip-compressed data (transported as Base64)",
		"zlib":            "zlib-compressed data (transported as Base64)",
		"bech32":          "Checksummed Bech32 encoding",
		"bech32m":         "Checksummed Bech32m encoding",
		"bubblebabble":    "Pronounceable Bubble Babble binary encoding",
		"uuid":            "RFC 4122 UUID (8-4-4-4-12 hex groups)",
		"url":             "RFC 3986 percent encoding",
		"json":            "JSON string escape sequences",
		"hex-escape":      `C-style \xNN byte escapes`,
		"morse":           "International Morse code",
		"nato":            "NATO phonetic alphabet",
		"binary":          "space-separated 8-bit binary byte groups",
		"decimal":         "space-separated decimal byte values 0-255",
		"octal":           "space-separated octal byte values",
		"baconian":        "Bacon's cipher",
		"polybius":        "Polybius square",
		"brainf*ck":       "Brainfuck source",
	}
}

func literalCatalogueType(display string) (string, bool) {
	if strings.ContainsAny(display, " /<(") {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(display)), display != ""
}

func (registry *hashRegistry) isSlow(name string) bool {
	name = canonicalHashType(name)
	format := registry.formats[name]
	return format != nil && format.slow
}

func (registry *hashRegistry) numericAliases() int {
	total := 0
	for alias := range registry.aliases {
		if isDecimalIdentifier(alias) {
			total++
		}
	}
	return total
}

// hashcatMode reports the Hashcat -m number for a format.
//
// A format may carry several numeric aliases — GPG spans 17010/17020/17030/
// 17040 — so the LOWEST is reported. That choice is arbitrary but it must be
// deterministic: a lookup that varies between runs would make identify's
// output unstable and its JSON undiffable.
func (r *hashRegistry) hashcatMode(name string) (int, bool) {
	format := r.formats[canonicalHashType(name)]
	if format == nil {
		return 0, false
	}
	best, found := 0, false
	for _, alias := range format.aliases {
		if !isDecimalIdentifier(alias) {
			continue
		}
		n, err := strconv.Atoi(alias)
		if err != nil {
			continue
		}
		if !found || n < best {
			best, found = n, true
		}
	}
	return best, found
}

// johnLabel reports the John the Ripper --format= label for a format.
//
// It cannot be derived from the alias map: John's labels live there
// undifferentiated from spelling variants, so "raw-md5" and "md-5" are
// indistinguishable to the registry. The mapping is therefore curated
// explicitly in johnLabelSeed, and a format with no entry reports none rather
// than guessing.
func (r *hashRegistry) johnLabel(name string) (string, bool) {
	canonical := canonicalHashType(name)
	if _, ok := r.formats[canonical]; !ok {
		return "", false
	}
	label, ok := johnLabels[canonical]
	return label, ok
}

var johnLabels = johnLabelSeed()

func isDecimalIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// spellingHashAliasSeed keeps punctuation and common-name normalization in the
// same alias namespace as Hashcat modes and John labels.
func spellingHashAliasSeed() map[string]string {
	return map[string]string{
		"sha-1": "sha1", "sha-0": "sha0", "md-2": "md2",
		"sha-224": "sha224", "sha2-224": "sha224",
		"sha-256": "sha256", "sha2-256": "sha256",
		"sha-384": "sha384", "sha2-384": "sha384",
		"sha-512": "sha512", "sha2-512": "sha512",
		"sha512-224": "sha512_224", "sha512/224": "sha512_224", "sha-512/224": "sha512_224",
		"sha512-256": "sha512_256", "sha512/256": "sha512_256", "sha-512/256": "sha512_256",
		"sha3-224": "sha3_224", "sha3-256": "sha3_256", "sha3-384": "sha3_384", "sha3-512": "sha3_512",
		"sha3-256-sha3-256": "sha3_256-sha3_256",
		"hmac-sha3-224":     "hmac-sha3_224", "hmac-sha3/224": "hmac-sha3_224",
		"hmac-sha3-256": "hmac-sha3_256", "hmac-sha3/256": "hmac-sha3_256",
		"hmac-sha3-384": "hmac-sha3_384", "hmac-sha3/384": "hmac-sha3_384",
		"hmac-sha3-512": "hmac-sha3_512", "hmac-sha3/512": "hmac-sha3_512",
		"hmac-sha3-224-saltkey": "hmac-sha3_224-saltkey", "hmac-sha3/224-saltkey": "hmac-sha3_224-saltkey",
		"hmac-sha3-256-saltkey": "hmac-sha3_256-saltkey", "hmac-sha3/256-saltkey": "hmac-sha3_256-saltkey",
		"hmac-sha3-384-saltkey": "hmac-sha3_384-saltkey", "hmac-sha3/384-saltkey": "hmac-sha3_384-saltkey",
		"hmac-sha3-512-saltkey": "hmac-sha3_512-saltkey", "hmac-sha3/512-saltkey": "hmac-sha3_512-saltkey",
		"hmac-ripemd-160": "hmac-ripemd160", "hmac-ripemd-160-saltkey": "hmac-ripemd160-saltkey",
		"keccak-256": "keccak256", "keccak-512": "keccak512",
		"shake128": "shake128-256", "shake-128": "shake128-256", "shake128/256": "shake128-256",
		"shake256": "shake256-512", "shake-256": "shake256-512", "shake256/512": "shake256-512",
		"blake2b-256": "blake2b256", "blake2b-384": "blake2b384", "blake2b-512": "blake2b",
		"blake2s-256": "blake2s",
		"ripemd-160":  "ripemd160", "ripemd-128": "ripemd128", "ripemd-256": "ripemd256", "ripemd-320": "ripemd320",
		"siphash-2-4": "siphash", "siphash24": "siphash", "sm-3": "sm3",
		"lmhash": "lm", "lanman": "lm",
		"crc-32": "crc32", "crc32-ieee": "crc32", "crc-32c": "crc32c", "castagnoli": "crc32c",
		"crc-64": "crc64", "crc64-ecma": "crc64", "adler-32": "adler32",
		"fnv-1a-32": "fnv1a32", "fnv-1a-64": "fnv1a64",
		"xxh32": "xxhash32", "xxhash-32": "xxhash32", "xxh64": "xxhash64", "xxhash-64": "xxhash64",
		"murmur3": "murmur3-32", "murmurhash3": "murmur3-32", "murmurhash3-32": "murmur3-32",
		"mysql-a": "mysql8", "mysql-$a$": "mysql8", "caching-sha2-password": "mysql8", "mysql8-caching-sha2": "mysql8",
		"389-ds": "ldap-pbkdf2", "389ds": "ldap-pbkdf2", "redhat-389-ds": "ldap-pbkdf2", "pbkdf2-sha256-389ds": "ldap-pbkdf2",
	}
}
