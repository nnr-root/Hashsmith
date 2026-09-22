package main

// John's named records for schemes its own dynamic engine already computes.
//
// John gives a scheme a name and a record of its own when the scheme has a
// name worth having — $IPB2$ for Invision Power Board, $netmd5$ for the MD5
// authentication on a routing update — even where the hash behind it is one of
// the expressions crack_john_dynamic.go evaluates. John says so itself: its
// listing calls dynamic_12 "IPB" and dynamic_4 "OSC".
//
// So these records need a reader, not a hash. Each names the dynamic
// expression it spells, where its salt and digest sit, and whether the salt is
// written as hex. Everything else is the engine's.
//
// The routing-protocol formats are worth stating plainly, because their salt
// is not a salt in the usual sense: it is the packet itself, captured off the
// wire, with the shared secret appended and padded. Cracking one recovers the
// key configured on both routers.

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"hashsmith-go/internal/hashid"
)

// johnDynamicEnvelope describes one of those records.
type johnDynamicEnvelope struct {
	prefix    string
	sep       string
	fields    int
	saltAt    int
	digestAt  int
	saltHex   bool
	requires  map[int]string // fields that must hold exactly this value
	number    int            // the dynamic expression this record spells
	display   string
	rationale string
}

var johnDynamicEnvelopes = map[string]johnDynamicEnvelope{
	"ipb2": {
		prefix: "$IPB2$", sep: "$", fields: 2, saltAt: 0, digestAt: 1, saltHex: true,
		number: 12, display: "Invision Power Board 2 md5(md5($salt).md5($pass))",
		rationale: "Invision Power Board 2 reached end of life in 2011, so these records come from old forum dumps rather than live installations",
	},
	"osc": {
		prefix: "$OSC$", sep: "$", fields: 2, saltAt: 0, digestAt: 1, saltHex: true,
		number: 4, display: "osCommerce md5($salt.$pass)",
		rationale: "osCommerce still runs a long tail of small storefronts, and its two-character salt makes a dump of them worth little more than unsalted MD5",
	},
	"wbb3": {
		prefix: "$wbb3$", sep: "*", fields: 4, saltAt: 2, digestAt: 3,
		requires: map[int]string{1: "1"},
		number:   1592, display: "WoltLab Burning Board 3 sha1($salt.sha1($salt.sha1($pass)))",
		rationale: "WoltLab Burning Board 3 was superseded by WoltLab Suite, whose records are bcrypt, so this shape appears mainly in archived forum dumps",
	},
	"net-md5": {
		prefix: "$netmd5$", sep: "$", fields: 2, saltAt: 0, digestAt: 1, saltHex: true,
		number: 39, display: "RIPv2 / OSPF MD5 routing authentication",
		rationale: "a captured routing update is the whole record, so anyone who can see the link can collect one; the key it protects is usually shared across a whole routing domain",
	},
	"net-sha1": {
		prefix: "$netsha1$", sep: "$", fields: 2, saltAt: 0, digestAt: 1, saltHex: true,
		number: 40, display: "OSPF SHA-1 routing authentication",
		rationale: "the SHA-1 authentication in RFC 5709 is newer than the MD5 one and correspondingly rarer on deployed links",
	},
	"tcp-md5": {
		prefix: "$tcpmd5$", sep: "$", fields: 2, saltAt: 0, digestAt: 1, saltHex: true,
		number: 4, display: "TCP MD5 signature (RFC 2385, BGP)",
		rationale: "TCP-MD5 is what protects most BGP sessions between peers, and the signed segment is visible to anyone on the path",
	},
	"eigrp": {
		prefix: "$eigrp$", sep: "$", fields: 5, saltAt: 1, digestAt: 4, saltHex: true,
		requires: map[int]string{0: "2", 2: "0"},
		number:   39, display: "EIGRP MD5 routing authentication",
		rationale: "EIGRP is Cisco-only, which bounds how often one of these is met, but within a Cisco network its authentication key is often the same on every router",
	},
}

// johnDynamicEnvelopeOrder keeps the generated prototypes and any listing in a
// fixed order, since ranging a map is not.
func johnDynamicEnvelopeOrder() []string {
	return []string{"eigrp", "ipb2", "net-md5", "net-sha1", "osc", "tcp-md5", "wbb3"}
}

// readJohnDynamicEnvelope splits one of these records into the salt and digest
// the expression needs.
func readJohnDynamicEnvelope(typ, target string) (salt []byte, digest string, err error) {
	e, ok := johnDynamicEnvelopes[typ]
	if !ok {
		return nil, "", errors.New("no John record is registered for " + typ)
	}
	t := strings.TrimSpace(target)
	if len(t) < len(e.prefix) || !strings.EqualFold(t[:len(e.prefix)], e.prefix) {
		return nil, "", errors.New("not a " + e.display + " record")
	}
	f := strings.Split(t[len(e.prefix):], e.sep)
	if len(f) != e.fields {
		return nil, "", errors.New(e.display + " records have " + strconv.Itoa(e.fields) + " fields")
	}
	for at, want := range e.requires {
		if f[at] != want {
			return nil, "", errors.New("this " + e.display + " record names a variant Hashsmith does not read")
		}
	}
	digest = f[e.digestAt]
	if len(digest) < 16 || len(digest)%2 != 0 || !isHex(digest) {
		return nil, "", errors.New("invalid " + e.display + " digest")
	}
	saltField := f[e.saltAt]
	if len(saltField) > maxKDFFieldSize*2 {
		return nil, "", errors.New(e.display + " salt is too long")
	}
	if !e.saltHex {
		return []byte(saltField), digest, nil
	}
	salt, err = hex.DecodeString(saltField)
	if err != nil {
		return nil, "", errors.New("invalid " + e.display + " salt")
	}
	return salt, digest, nil
}

// verifyJohnDynamicEnvelope answers one of these records by running the
// expression its number names.
func verifyJohnDynamicEnvelope(typ, target, candidate string) (bool, error) {
	salt, digest, err := readJohnDynamicEnvelope(typ, target)
	if err != nil {
		return false, err
	}
	c := compileDynamic(johnDynamicEnvelopes[typ].number)
	if c.err != nil {
		return false, c.err
	}
	env := dynEnv{pw: []byte(candidate), salt: salt}
	got, err := evalDynExpr(c.terms, &env)
	if err != nil {
		return false, err
	}
	return dynHexMatches(digest, string(got)), nil
}

// johnDynamicEnvelopePrototypes registers each record for detection. The
// prefix alone settles the format, and the record still has to parse, so these
// are TierSignature and exclusive.
func johnDynamicEnvelopePrototypes() []hashid.Prototype {
	var out []hashid.Prototype
	for _, typ := range johnDynamicEnvelopeOrder() {
		e := johnDynamicEnvelopes[typ]
		typ, prefix := typ, e.prefix
		out = append(out, hashid.Prototype{
			Types: []string{typ}, Display: e.display, Tier: hashid.TierSignature, Exclusive: true,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				if _, _, err := readJohnDynamicEnvelope(typ, in.Normalized); err != nil {
					return "", false
				}
				return hashid.Evidence("record prefix " + prefix), true
			},
			Prevalence: 4, Rationale: e.rationale,
		})
	}
	return out
}
