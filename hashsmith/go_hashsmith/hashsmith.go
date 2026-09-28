// Package hashsmith is the Hashsmith toolkit as a library.
//
// Hashsmith is normally a command-line tool. Everything it does to a hash, a
// record or an encoded string is available here as well, so that a scanner, a
// test harness, an incident-response script or another Go program can use it
// without shelling out and parsing terminal output.
//
// # What is here
//
// Four things, matching the four the CLI does:
//
//   - [Identify] names the types that recognise a record.
//   - [Hash] produces a hash; [Verify] checks a password against a record.
//   - [Encode] and [Decode] run any of the eighty codecs, and [Magic] searches
//     for the chain of them that turns a payload into something meaningful.
//   - [Extract] reads a password record out of a container — a keystore, a
//     wallet, an archive, a capture.
//
// # What is deliberately not here
//
// The cracking engine's machinery: sessions, the potfile, rule application,
// mask enumeration, progress reporting, GPU dispatch. Those own the process —
// they write to the terminal, they read and write files under the user's home
// directory, they install signal handlers — and a library has no business
// doing any of that to its caller. [Crack] is the verifier run in parallel
// over candidates the caller supplies, which is the part that belongs in a
// library. For the rest, run the command.
//
// # Stability
//
// The implementation lives in an internal package and is free to change. This
// file is the promise. Anything not named here is not part of it.
//
// # Example
//
//	types := hashsmith.Identify("$2b$05$...")
//	ok, err := hashsmith.Verify("hunter2", record, hashsmith.WithType("bcrypt"))
package hashsmith

import (
	"strconv"

	"hashsmith-go/internal/smith"
)

// ── Options ───────────────────────────────────────────────────────────────────

// Options carry the parameters a particular type or codec needs. The zero
// value is valid everywhere: it means "no type given, work it out", no salt,
// and each codec's own default.
type Options struct {
	// Type is the -t name. Leaving it empty asks the identification engine,
	// which is convenient and slower, and ambiguous for records whose shape
	// several types share — a bare 32-hex digest is MD5, NTLM, and a dozen
	// others. A caller who knows the type should say so.
	Type string

	// Salt and SaltMode apply to the plain digest types. SaltMode is "prefix"
	// or "suffix"; formats that carry their salt inside the record place it
	// themselves and ignore both.
	Salt     string
	SaltMode string

	// Cost is the work factor for the types that have one instead of a salt.
	//
	// Today that is bcrypt alone: it draws its own random salt and embeds it
	// in the record, so there is nothing to supply, and the parameter that
	// slot carries is the log2 cost written into the record as $2a$NN$. Legal
	// values are 4 to 31; bcrypt's own default is 10, and this package does
	// not pick one for you because the cost is a security decision.
	//
	// Argon2 and scrypt take a real salt in Salt, not a cost here. If you
	// hash bcrypt without setting Cost, the error you get back is worded for
	// the command line and will name a flag you do not have — that message is
	// the CLI's and is left alone rather than duplicated.
	Cost int

	// Shift is the Caesar shift, Key the string a keyed codec needs — a
	// Vigenere key, an XOR key, a Bech32 prefix, a base-N alphabet — and
	// Rails the rail-fence rail count or the scytale's rod. Each codec reads
	// only what it uses.
	Shift int
	Key   string
	Rails int

	// Limit refuses a decode result larger than this many bytes. Zero uses
	// the default ceiling of 64 MiB. It exists for the compression codecs,
	// where a few hundred bytes of input is an instruction to allocate
	// megabytes: a caller decoding untrusted data should set it to what it is
	// actually willing to hold.
	Limit int

	// Workers is how many goroutines Crack runs. Zero means one per CPU.
	Workers int
}

// Option modifies Options. The With functions cover the common cases; a caller
// wanting several can build an Options value and pass it to the Opts form.
type Option func(*Options)

// WithType names the hash or codec type instead of letting it be detected.
func WithType(typ string) Option { return func(o *Options) { o.Type = typ } }

// WithSalt sets the salt and how it is applied: "prefix" or "suffix".
func WithSalt(salt, mode string) Option {
	return func(o *Options) { o.Salt, o.SaltMode = salt, mode }
}

// WithKey sets the key a keyed codec needs.
func WithKey(key string) Option { return func(o *Options) { o.Key = key } }

// WithShift sets the Caesar shift.
func WithShift(n int) Option { return func(o *Options) { o.Shift = n } }

// WithRails sets the rail-fence rail count, or the scytale's rod.
func WithRails(n int) Option { return func(o *Options) { o.Rails = n } }

// WithLimit refuses a decode result larger than n bytes.
func WithLimit(n int) Option { return func(o *Options) { o.Limit = n } }

// WithWorkers sets how many goroutines Crack runs.
func WithWorkers(n int) Option { return func(o *Options) { o.Workers = n } }

// WithCost sets the work factor for a type that takes one instead of a salt,
// which today means bcrypt. See [Options.Cost].
func WithCost(n int) Option { return func(o *Options) { o.Cost = n } }

func collect(opts []Option) Options {
	var o Options
	for _, apply := range opts {
		apply(&o)
	}
	return o
}

// ── Identification ────────────────────────────────────────────────────────────

// Identify returns the type names that recognise a record, in the order
// cracking should try them. An empty result means nothing recognised it.
//
// More than one name is the normal case, not a failure: a 32-character hex
// string is a valid MD5, NTLM, MD4, and several more, and no amount of looking
// at it will decide which. The order is the engine's judgement about
// likelihood, not a claim of certainty.
func Identify(record string) []string { return smith.IdentifyRecord(record) }

// HashTypes returns every type name the registry knows, sorted.
func HashTypes() []string { return smith.HashTypeNames() }

// CanonicalType resolves a type alias — a hashcat mode name, a John format
// label, a spelling variant — to the name this package uses.
func CanonicalType(typ string) string { return smith.CanonicalHashType(typ) }

// ── Hashing ───────────────────────────────────────────────────────────────────

// Hash produces a hash of password. The type is required.
func Hash(password string, opts ...Option) (string, error) {
	return HashOpts(password, collect(opts))
}

// HashOpts is Hash taking an Options value.
func HashOpts(password string, o Options) (string, error) {
	salt := o.Salt
	if salt == "" && o.Cost > 0 {
		// The work-factor types and the salted types share one channel
		// underneath. Cost exists so that a caller does not have to know
		// that, and does not have to write strconv.Itoa to hash a bcrypt.
		salt = strconv.Itoa(o.Cost)
	}
	return smith.HashPassword(password, o.Type, salt, o.SaltMode)
}

// ── Verification ──────────────────────────────────────────────────────────────

// Verify reports whether password produces record.
//
// Without a type it asks the identification engine and accepts the password if
// any candidate type verifies it. That is the CLI's behaviour and it is the
// right default for a record pulled out of a file, but it means a true result
// does not say WHICH type matched. Name the type when you know it.
func Verify(password, record string, opts ...Option) (bool, error) {
	o := collect(opts)
	return smith.VerifyPassword(password, record, o.Type, o.Salt, o.SaltMode)
}

// VerifyOpts is Verify taking an Options value.
func VerifyOpts(password, record string, o Options) (bool, error) {
	return smith.VerifyPassword(password, record, o.Type, o.Salt, o.SaltMode)
}

// ── Cracking ──────────────────────────────────────────────────────────────────

// Crack tries each candidate against the record and returns the first that
// verifies, along with whether one did.
//
// "First" means first in the order given, not first to finish: candidates are
// checked in parallel, but a caller who ordered their list by likelihood gets
// the answer that ordering asked for.
//
// This is the verifier and a worker pool. It has no session file, no potfile,
// no rules, no mask enumeration and no GPU — see the package comment for why.
// The per-candidate cost is the same as the command's, so for a wordlist
// already in memory this is the whole of what the command would do.
func Crack(record string, candidates []string, opts ...Option) (string, bool, error) {
	o := collect(opts)
	return smith.CrackWith(record, o.Type, o.Salt, o.SaltMode, candidates, o.Workers)
}

// CrackOpts is Crack taking an Options value.
func CrackOpts(record string, candidates []string, o Options) (string, bool, error) {
	return smith.CrackWith(record, o.Type, o.Salt, o.SaltMode, candidates, o.Workers)
}

// ── Codecs ────────────────────────────────────────────────────────────────────

// Encode applies a codec. The type is required.
func Encode(text string, opts ...Option) (string, error) {
	o := collect(opts)
	return smith.Encode(text, o.Type, o.Shift, o.Key, o.Rails)
}

// EncodeOpts is Encode taking an Options value.
func EncodeOpts(text string, o Options) (string, error) {
	return smith.Encode(text, o.Type, o.Shift, o.Key, o.Rails)
}

// Decode reverses a codec. The type is required.
//
// Set Limit when decoding anything untrusted. The compression codecs will
// otherwise inflate up to 64 MiB from a few hundred bytes of input, because
// that is what a compressed stream is: an instruction to allocate.
func Decode(text string, opts ...Option) (string, error) {
	o := collect(opts)
	return smith.Decode(text, o.Type, o.Shift, o.Key, o.Rails, o.Limit)
}

// DecodeOpts is Decode taking an Options value.
func DecodeOpts(text string, o Options) (string, error) {
	return smith.Decode(text, o.Type, o.Shift, o.Key, o.Rails, o.Limit)
}

// Codec is one entry in the catalogue.
type Codec struct {
	Name        string
	Description string
}

// Codecs returns every codec, with its one-line description.
func Codecs() []Codec {
	pairs := smith.CodecNames()
	out := make([]Codec, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, Codec{Name: p[0], Description: p[1]})
	}
	return out
}

// CanonicalCodec resolves a codec alias to the name this package uses.
func CanonicalCodec(typ string) string { return smith.CanonicalCodec(typ) }

// Chain is one decode chain that Magic found.
type Chain struct {
	// Value is what the chain produced.
	Value string
	// Codecs are the codecs applied, in order.
	Codecs []string
	// Score is how meaningful the result looks, from 0 to 1.
	Score float64
	// Identified names what the hash-identification engine makes of the
	// result, when it makes anything of it.
	Identified string
}

// Magic searches for chains of decoders that turn input into something
// meaningful, best first. A depth of zero uses the default of three.
//
// Codecs needing a key or a parameter are not tried, and neither are the
// compression formats with no signature to check. Guessing a key and reporting
// the noise as a finding would be worse than declining, so Magic declines.
func Magic(input string, depth int) []Chain {
	found := smith.MagicDecode(input, depth)
	out := make([]Chain, 0, len(found))
	for _, c := range found {
		out = append(out, Chain{
			Value:      c.Value,
			Codecs:     c.Chain,
			Score:      c.Score,
			Identified: c.Identified,
		})
	}
	return out
}

// ── Extraction ────────────────────────────────────────────────────────────────

// Extractor is one entry in the extractor catalogue.
type Extractor struct {
	Name string
	// Input describes the container it reads.
	Input string
}

// Extractors returns every extractor, with the container it reads.
func Extractors() []Extractor {
	pairs := smith.ExtractorNames()
	out := make([]Extractor, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, Extractor{Name: p[0], Input: p[1]})
	}
	return out
}

// Extract identifies a container from its first bytes and returns the
// crackable records inside it, along with the name of the extractor that read
// it.
//
// It fails rather than guesses when nothing recognises the file. Use
// [ExtractWith] to name the extractor yourself.
//
// One caveat, inherited from the extractors being subcommands: while this
// runs, the process's standard output is redirected so the records can be
// captured. Anything else in the program writing to stdout at that moment is
// captured too. Concurrent calls to Extract are serialised; the rest of the
// program is not.
func Extract(path string) (records []string, extractor string, err error) {
	return smith.ExtractFromFile(path)
}

// ExtractWith runs a named extractor over a file. The same stdout caveat as
// [Extract] applies.
func ExtractWith(name, path string) ([]string, error) {
	return smith.RunExtractor(name, path)
}
