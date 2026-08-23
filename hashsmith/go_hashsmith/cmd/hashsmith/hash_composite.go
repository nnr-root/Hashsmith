package main

// Composite hash constructions — the "md5($salt.md5($pass))" family.
//
// Hashcat and John both carry a long tail of modes that are nothing more than
// a particular nesting of MD5/SHA-1/SHA-256 over the password and salt.  Rather
// than transcribe each one as its own function, this file defines a tiny
// expression tree (salt, password, or a nested digest of a sequence of those)
// and declares every construction in terms of it.  Adding a mode is then one
// table entry, and the shape of the entry is the formula it implements.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"sort"
	"strings"
)

// compositePart is one element of a concatenation: the salt, the password, or
// a nested digest.
type compositePart struct {
	kind   int // partSalt, partPass, partDigest
	algo   string
	inner  []compositePart
	binary bool // nested digest contributes raw bytes rather than lowercase hex
	upper  bool // nested digest contributes uppercase hex
}

const (
	partSalt = iota
	partPass
	partPassUTF16
	partDigest
)

func cSalt() compositePart { return compositePart{kind: partSalt} }
func cPass() compositePart { return compositePart{kind: partPass} }

// cUTF16Pass splices the password as UTF-16LE, the encoding Windows-derived
// formats hash rather than the raw bytes.
func cUTF16Pass() compositePart { return compositePart{kind: partPassUTF16} }

// cHash nests a digest whose result is spliced in as lowercase hex, which is
// what these constructions almost always mean.
func cHash(algo string, inner ...compositePart) compositePart {
	return compositePart{kind: partDigest, algo: algo, inner: inner}
}

// cRaw nests a digest spliced in as raw bytes.
func cRaw(algo string, inner ...compositePart) compositePart {
	return compositePart{kind: partDigest, algo: algo, inner: inner, binary: true}
}

// cUpper nests a digest spliced in as uppercase hex, which a few platforms
// (ColdFusion most notably) do and which changes the result entirely.
func cUpper(algo string, inner ...compositePart) compositePart {
	return compositePart{kind: partDigest, algo: algo, inner: inner, upper: true}
}

var compositeHashers = map[string]func() hash.Hash{
	"md5":       md5.New,
	"sha1":      sha1.New,
	"sha224":    sha256.New224,
	"sha256":    sha256.New,
	"sha512":    sha512.New,
	"whirlpool": newWhirlpool,
}

// evalComposite renders a part sequence to bytes for the given password/salt.
func evalComposite(parts []compositePart, pass, salt string) ([]byte, error) {
	var out []byte
	for _, p := range parts {
		switch p.kind {
		case partSalt:
			out = append(out, salt...)
		case partPass:
			out = append(out, pass...)
		case partPassUTF16:
			out = append(out, utf16le(pass)...)
		case partDigest:
			newHash, ok := compositeHashers[p.algo]
			if !ok {
				return nil, errors.New("unknown nested digest: " + p.algo)
			}
			inner, err := evalComposite(p.inner, pass, salt)
			if err != nil {
				return nil, err
			}
			h := newHash()
			_, _ = h.Write(inner)
			sum := h.Sum(nil)
			switch {
			case p.binary:
				out = append(out, sum...)
			case p.upper:
				out = append(out, strings.ToUpper(hex.EncodeToString(sum))...)
			default:
				out = append(out, hex.EncodeToString(sum)...)
			}
		}
	}
	return out, nil
}

type compositeSpec struct {
	algo  string // outer digest
	parts []compositePart
	desc  string
}

// compositeConstructions is the catalogue.  Names read left to right as the
// formula: md5-salt-md5pass is md5($salt.md5($pass)).
var compositeConstructions = map[string]compositeSpec{
	"md5-salt-md5pass": {"md5", []compositePart{cSalt(), cHash("md5", cPass())},
		"md5($salt.md5($pass)), Hashcat 3710"},
	"md5-md5pass-salt": {"md5", []compositePart{cHash("md5", cPass()), cSalt()},
		"md5(md5($pass).$salt), Hashcat 2611 / vBulletin"},
	"md5-md5passsalt": {"md5", []compositePart{cHash("md5", cPass(), cSalt())},
		"md5(md5($pass.$salt)), Hashcat 2630"},
	"md5-md5-md5pass-salt": {"md5", []compositePart{cHash("md5", cHash("md5", cPass())), cSalt()},
		"md5(md5(md5($pass)).$salt), Hashcat 3610"},
	"md5-salt-pass-salt": {"md5", []compositePart{cSalt(), cPass(), cSalt()},
		"md5($salt.$pass.$salt), Hashcat 3800"},
	"md5-salt-md5saltpass": {"md5", []compositePart{cSalt(), cHash("md5", cSalt(), cPass())},
		"md5($salt.md5($salt.$pass)), Hashcat 4010"},
	"md5-salt-md5passsalt": {"md5", []compositePart{cSalt(), cHash("md5", cPass(), cSalt())},
		"md5($salt.md5($pass.$salt)), Hashcat 4110"},
	"md5-md5salt-md5pass": {"md5", []compositePart{cHash("md5", cSalt()), cHash("md5", cPass())},
		"md5(md5($salt).md5($pass)), Hashcat 2811 / IPB / MyBB"},
	"md5-md5salt-pass": {"md5", []compositePart{cHash("md5", cSalt()), cPass()},
		"md5(md5($salt).$pass), PHPS"},
	"md5-md5pass-md5salt": {"md5", []compositePart{cHash("md5", cPass()), cHash("md5", cSalt())},
		"md5(md5($pass).md5($salt)), Hashcat 3910"},
	"md5-sha1pass-salt": {"md5", []compositePart{cHash("sha1", cPass()), cSalt()},
		"md5(sha1($pass).$salt), Hashcat 4410"},
	"md5-sha1passsalt": {"md5", []compositePart{cHash("sha1", cPass(), cSalt())},
		"md5(sha1($pass.$salt)), Hashcat 4420"},
	"md5-sha1saltpass": {"md5", []compositePart{cHash("sha1", cSalt(), cPass())},
		"md5(sha1($salt.$pass)), Hashcat 4430"},
	"md5-sha1salt-md5pass": {"md5", []compositePart{cHash("sha1", cSalt()), cHash("md5", cPass())},
		"md5(sha1($salt).md5($pass)), Hashcat 21200"},
	"md5-salt-sha1saltpass": {"md5", []compositePart{cSalt(), cHash("sha1", cSalt(), cPass())},
		"md5($salt.sha1($salt.$pass)), Hashcat 21300"},
	"md5-md5salt-md5-md5pass": {"md5", []compositePart{cHash("md5", cSalt()), cHash("md5", cHash("md5", cPass()))},
		"md5(md5($salt).md5(md5($pass))), Hashcat 30500"},
	"md5-salt-pass-md5pass": {"md5", []compositePart{cSalt(), cPass(), cHash("md5", cPass())},
		"md5($salt.$pass.md5($pass)), Hashcat 22800 / Simpla CMS"},

	"sha1-salt-pass-salt": {"sha1", []compositePart{cSalt(), cPass(), cSalt()},
		"sha1($salt.$pass.$salt), Hashcat 4900"},
	"sha1-sha1pass-salt": {"sha1", []compositePart{cHash("sha1", cPass()), cSalt()},
		"sha1(sha1($pass).$salt), Hashcat 4510"},
	"sha1-salt-sha1pass": {"sha1", []compositePart{cSalt(), cHash("sha1", cPass())},
		"sha1($salt.sha1($pass)), Hashcat 4520 / Redmine"},
	"sha1-salt-sha1passsalt": {"sha1", []compositePart{cSalt(), cHash("sha1", cPass(), cSalt())},
		"sha1($salt.sha1($pass.$salt)), Hashcat 24300"},
	"sha1-md5pass-salt": {"sha1", []compositePart{cHash("md5", cPass()), cSalt()},
		"sha1(md5($pass).$salt), Hashcat 4710 / Huawei"},
	"sha1-sha1saltpasssalt": {"sha1", []compositePart{cHash("sha1", cSalt(), cPass(), cSalt())},
		"sha1(sha1($salt.$pass.$salt)), Hashcat 5000"},
	"sha1-salt-sha1saltsha1pass": {"sha1", []compositePart{cSalt(), cHash("sha1", cSalt(), cHash("sha1", cPass()))},
		"sha1($salt.sha1($salt.sha1($pass))), Hashcat 8400 / 13900"},

	"sha256-salt-pass-salt": {"sha256", []compositePart{cSalt(), cPass(), cSalt()},
		"sha256($salt.$pass.$salt), Hashcat 22300"},
	"sha256-sha256pass-salt": {"sha256", []compositePart{cHash("sha256", cPass()), cSalt()},
		"sha256(sha256($pass).$salt), Hashcat 20710"},
	"sha256-salt-sha256pass": {"sha256", []compositePart{cSalt(), cHash("sha256", cPass())},
		"sha256($salt.sha256($pass)), Hashcat 20720"},
	"sha256-sha256passsalt": {"sha256", []compositePart{cHash("sha256", cPass(), cSalt())},
		"sha256(sha256($pass.$salt)), Hashcat 20730"},
	"sha256-md5pass": {"sha256", []compositePart{cHash("md5", cPass())},
		"sha256(md5($pass)), Hashcat 20800"},
	"sha256-sha256binpass": {"sha256", []compositePart{cRaw("sha256", cPass())},
		"sha256(sha256_bin($pass)), Hashcat 21400"},
	"sha256-salt-sha256binpass": {"sha256", []compositePart{cSalt(), cRaw("sha256", cPass())},
		"sha256($salt.sha256_bin($pass)), Hashcat 21420"},

	"sha1-md5passsalt": {"sha1", []compositePart{cHash("md5", cPass(), cSalt())},
		"sha1(md5($pass.$salt)), Hashcat 21100"},

	"sha512-salt-pass-salt": {"sha512", []compositePart{cSalt(), cPass(), cSalt()},
		"sha512($salt.$pass.$salt)"},
	"sha512-sha512binpass": {"sha512", []compositePart{cRaw("sha512", cPass())},
		"sha512(sha512_bin($pass)), Hashcat 21000 / BitShares v0.x"},
	"sha512-sha512pass-salt": {"sha512", []compositePart{cHash("sha512", cPass()), cSalt()},
		"sha512(sha512($pass).$salt), Hashcat 32410"},
	"sha512-sha512binpass-salt": {"sha512", []compositePart{cRaw("sha512", cPass()), cSalt()},
		"sha512(sha512_bin($pass).$salt), Hashcat 32420"},
	"whirlpool-salt-pass-salt": {"whirlpool", []compositePart{cSalt(), cPass(), cSalt()},
		"whirlpool($salt.$pass.$salt), Hashcat 32600 / CubeCart"},

	// Password-only constructions.
	"md5-pass-pass": {"md5", []compositePart{cPass(), cPass()},
		"md5($pass.$pass)"},
	"md5-md5pass-pass": {"md5", []compositePart{cHash("md5", cPass()), cPass()},
		"md5(md5($pass).$pass)"},
	"md5-pass-md5pass": {"md5", []compositePart{cPass(), cHash("md5", cPass())},
		"md5($pass.md5($pass))"},
	"md5-md5binpass": {"md5", []compositePart{cRaw("md5", cPass())},
		"md5(md5_bin($pass))"},
	"sha1-sha1binpass": {"sha1", []compositePart{cRaw("sha1", cPass())},
		"sha1(sha1_bin($pass))"},
	"sha1-sha1-sha1pass": {"sha1", []compositePart{cHash("sha1", cHash("sha1", cPass()))},
		"sha1(sha1(sha1($pass)))"},
	"sha512-pass-pass": {"sha512", []compositePart{cPass(), cPass()},
		"sha512($pass.$pass)"},
	"md5-sha1pass-md5pass-sha1pass": {"md5", []compositePart{
		cHash("sha1", cPass()), cHash("md5", cPass()), cHash("sha1", cPass())},
		"md5(sha1($pass).md5($pass).sha1($pass)), Hashcat 20900"},
	"md5-sha1-md5pass": {"md5", []compositePart{cHash("sha1", cHash("md5", cPass()))},
		"md5(sha1(md5($pass))), Hashcat 32800"},
	"sha224-sha224pass": {"sha224", []compositePart{cHash("sha224", cPass())},
		"sha224(sha224($pass)), Hashcat 34400"},
	"sha224-sha1pass": {"sha224", []compositePart{cHash("sha1", cPass())},
		"sha224(sha1($pass)), Hashcat 34500"},

	// Salted constructions.
	"md5-salt-md5pass-salt": {"md5", []compositePart{cSalt(), cHash("md5", cPass()), cSalt()},
		"md5($salt.md5($pass).$salt), John dynamic_14"},
	"sha1-salt-md5pass": {"sha1", []compositePart{cSalt(), cHash("md5", cPass())},
		"sha1($salt.md5($pass))"},
	"sha256-salt-uppersha1pass": {"sha256", []compositePart{cSalt(), cUpper("sha1", cPass())},
		"sha256($salt.uppercase(sha1($pass))), Hashcat 12600 / ColdFusion 10+"},
	"sha256-salt-utf16lepass": {"sha256", []compositePart{cSalt(), cUTF16Pass()},
		"sha256($salt.utf16le($pass)), Hashcat 13800 / Windows Phone 8+"},
}

// hashComposite renders one construction for a password/salt pair.
func hashComposite(pass, name, salt string) (string, error) {
	spec, ok := compositeConstructions[name]
	if !ok {
		return "", errors.New("unsupported composite construction: " + name)
	}
	if salt == "" && compositeNeedsSalt(spec) {
		return "", errors.New(name + " requires a salt")
	}
	body, err := evalComposite(spec.parts, pass, salt)
	if err != nil {
		return "", err
	}
	h := compositeHashers[spec.algo]()
	_, _ = h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func compositeNeedsSalt(spec compositeSpec) bool {
	var walk func([]compositePart) bool
	walk = func(parts []compositePart) bool {
		for _, p := range parts {
			if p.kind == partSalt {
				return true
			}
			if p.kind == partDigest && walk(p.inner) {
				return true
			}
		}
		return false
	}
	return walk(spec.parts)
}

// verifyComposite accepts the hash:salt form these modes are distributed in,
// falling back to an explicit -s salt.
func verifyComposite(candidate, target, name, salt string) (bool, error) {
	spec, ok := compositeConstructions[name]
	if !ok {
		return false, errors.New("unsupported composite construction: " + name)
	}
	effTarget, effSalt := target, salt
	if effSalt == "" && compositeNeedsSalt(spec) {
		i := strings.LastIndexByte(target, ':')
		if i < 1 || i == len(target)-1 {
			return false, errors.New(name + " requires a hash:salt target or -s")
		}
		effTarget, effSalt = target[:i], target[i+1:]
	}
	got, err := hashComposite(candidate, name, effSalt)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(got, effTarget), nil
}

// compositeTypesForDigestLength lists the constructions whose output matches a
// digest of the given hex length.  Auto-detection appends these after the
// simpler generic forms, so the common cases are still tried first.
func compositeTypesForDigestLength(n int) []string {
	var out []string
	for name, spec := range compositeConstructions {
		var size int
		switch spec.algo {
		case "md5":
			size = 32
		case "sha1":
			size = 40
		case "sha224":
			size = 56
		case "sha256":
			size = 64
		case "sha512":
			size = 128
		case "whirlpool":
			size = 128
		}
		if size == n {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
