package main

// Records John writes without the prefix this tool reads them by.
//
// Each of these is a format Hashsmith already computes correctly. What was
// missing is that John's own spelling of the record carries no marker, or a
// different one, so detection never offered the type that would have answered
// it. None of these needs an algorithm; they need a reader.
//
// A record with no marker is read by shape, and a shape is weak evidence, so
// every one of these is offered rather than asserted and none of them
// suppresses anything else.

import (
	"strings"

	"hashsmith-go/internal/hashid"
)

// ── net-md5 written bare ──────────────────────────────────────────────────────
//
// John writes a captured routing update as "<packet hex>$<digest hex>" with no
// "$netmd5$" in front of it. The packet is what makes the shape readable: it
// is tens of bytes of hex, far longer than any salt, and the digest after it
// is exactly thirty-two characters.
//
// This is the case hash_compat.go's dollar-separated salt rule deliberately
// declines — "both halves hex means another format's two fields" — and this is
// that other format.

const netMD5MinPacketHex = 40

func bareNetMD5(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "$") {
		return "", false
	}
	packet, digest, ok := strings.Cut(t, "$")
	if !ok || strings.Contains(digest, "$") {
		return "", false
	}
	if len(packet) < netMD5MinPacketHex || len(packet)%2 != 0 || !isHex(packet) {
		return "", false
	}
	if len(digest) != 32 || !isHex(digest) {
		return "", false
	}
	return "$netmd5$" + packet + "$" + digest, true
}

func isBareNetMD5(target string) bool { _, ok := bareNetMD5(target); return ok }

// ── mscash2 written as user:hash ──────────────────────────────────────────────
//
// John's mscash2 record is the username and the digest joined by a colon, with
// the iteration count left implicit. Hashsmith reads the "$DCC2$10240#user#hash"
// spelling, which states it.
//
// Ten thousand two hundred and forty is the count Windows has used since
// Vista. A domain can be configured to use another, and a record in this
// spelling cannot say so — which is the reason to prefer the spelling that
// carries it, and no reason to refuse this one.

const dcc2DefaultRounds = "10240"

func bareMSCash2(target string) (string, bool) {
	t := strings.TrimSpace(target)
	user, digest, ok := strings.Cut(t, ":")
	if !ok || user == "" || len(user) > 128 {
		return "", false
	}
	if len(digest) != 32 || !isHex(digest) {
		return "", false
	}
	// A username with a colon or a dollar in it is some other format's record
	// split in the wrong place.
	if strings.ContainsAny(user, ":$#*") {
		return "", false
	}
	return "$DCC2$" + dcc2DefaultRounds + "#" + user + "#" + digest, true
}

func isBareMSCash2(target string) bool { _, ok := bareMSCash2(target); return ok }

// ── Kerberos database keys written bare ───────────────────────────────────────
//
// John's krb5-17 and krb5-18 records are "<salt><key hex>" with the salt and
// the key separated by a dollar and nothing in front. The salt is the realm
// and the principal run together, so it is not hex and usually not even
// lower-case, which is what tells this shape apart from a salted digest.

func bareKerberosDBKey(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "$") {
		return "", false
	}
	salt, key, ok := strings.Cut(t, "$")
	if !ok || salt == "" || len(salt) > maxKDFFieldSize || strings.Contains(key, "$") {
		return "", false
	}
	// A hex salt means this is some other format's two fields.
	if isHex(salt) {
		return "", false
	}
	var name string
	switch {
	case len(key) == 32 && isHex(key):
		name = "$krb17$"
	case len(key) == 64 && isHex(key):
		name = "$krb18$"
	default:
		return "", false
	}
	return name + salt + "$" + key, true
}

func isBareKerberosDBKey(target string) bool { _, ok := bareKerberosDBKey(target); return ok }

// johnBareSpellingPrototypes offers each of these shapes.
func johnBareSpellingPrototypes() []hashid.Prototype {
	return []hashid.Prototype{
		{
			Types: []string{"net-md5"}, Display: "RIPv2 / OSPF MD5 routing authentication (bare)",
			Tier: hashid.TierStructural,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a long hex packet, a dollar, and one MD5", isBareNetMD5(in.Normalized)
			},
			Prevalence: 12,
			Rationale:  "a captured routing update, which anyone on the link can collect; the key it protects is usually the same on every router in the domain",
		},
		{
			Types: []string{"dcc2"}, Display: "Domain Cached Credentials 2, as username:hash",
			Tier: hashid.TierShape,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a username, a colon and one MD4-width digest", isBareMSCash2(in.Normalized)
			},
			Prevalence: 14,
			Rationale:  "this spelling leaves the iteration count implicit, so it is read as Windows' default of 10,240; a domain configured otherwise needs the $DCC2$ spelling that states it",
		},
		{
			Types: []string{"krb5asrep", "krb5asrep-nt"}, Display: "Kerberos 5 AS-REP, RC4 (bare)",
			Tier: hashid.TierStructural,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a 16-byte checksum, a dollar, and a long encrypted part", isBareKrb5ASREP(in.Normalized)
			},
			Prevalence: 20,
			Rationale:  "AS-REP roasting produces these in quantity against accounts with Kerberos pre-authentication disabled",
		},
		{
			Types: []string{"sl3"}, Display: "Nokia SL3 unlock code, as IMEI:digest",
			Tier: hashid.TierStructural,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a 14- or 15-digit IMEI, a colon and a SHA-1", isBareSL3(in.Normalized)
			},
			Prevalence: 4,
			Rationale:  "the same shape as a numeric username beside a SHA-1, so it is offered as one more reading of that rather than asserted",
		},
		{
			Types: []string{"krb5-key"}, Display: "Kerberos AES database key (bare)",
			Tier: hashid.TierShape,
			Match: func(in hashid.Input) (hashid.Evidence, bool) {
				return "a non-hex principal salt, a dollar, and a 16- or 32-byte key", isBareKerberosDBKey(in.Normalized)
			},
			Prevalence: 10,
			Rationale:  "a key taken from a KDC or domain controller database rather than a ticket encrypted with one",
		},
	}
}

// ── AS-REP written bare ───────────────────────────────────────────────────────
//
// John writes an RC4 AS-REP as "<checksum>$<encrypted part>" with no etype and
// no marker. Hashsmith reads "$krb5asrep$23$<the same thing>", where the 23
// says RC4 — which is what this shape always is, because the bare spelling
// predates the etypes that needed distinguishing.

func bareKrb5ASREP(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "$") {
		return "", false
	}
	checksum, edata, ok := strings.Cut(t, "$")
	if !ok || strings.Contains(edata, "$") {
		return "", false
	}
	if len(checksum) != 32 || !isHex(checksum) {
		return "", false
	}
	// The encrypted timestamp and PAC are far longer than any digest, which
	// is what keeps this apart from a salted hash written the same way.
	if len(edata) < 64 || len(edata)%2 != 0 || !isHex(edata) {
		return "", false
	}
	return "$krb5asrep$23$" + checksum + "$" + edata, true
}

func isBareKrb5ASREP(target string) bool { _, ok := bareKrb5ASREP(target); return ok }

// ── Cisco ASA under its dynamic number ────────────────────────────────────────
//
// Once "$dynamic_20$" is off the front, what is left is the PIX digest and the
// username joined by a dollar where every other spelling of the same record
// uses a colon.

func dynamicCiscoASA(target string) (string, bool) {
	t := strings.TrimSpace(target)
	digest, user, ok := strings.Cut(t, "$")
	if !ok || user == "" || strings.Contains(user, "$") || len(digest) != 16 {
		return "", false
	}
	return digest + ":" + user, true
}

// ── Nokia SL3 written as IMEI:digest ──────────────────────────────────────────
//
// John also accepts an SL3 record in the shape a dump produces: the IMEI in
// the username field and the digest after a colon. The IMEI may be fifteen
// digits there rather than fourteen, because a full IMEI carries a Luhn check
// digit — and the hash uses only the first fourteen, so the fifteenth is along
// for the ride.
//
// John refuses a fifteen-digit IMEI whose check digit does not validate. That
// is not copied here, for a reason worth recording: the fifteen-digit value in
// John's own published format listing is 112233445566778, whose Luhn digit is
// wrong — the source says 112233445566773 — and the digest verifies against
// the first fourteen digits either way. Refusing the record would mean
// refusing one John itself prints, to enforce a check on a digit that does not
// reach the hash. So the check digit is ignored, and the shape stays narrow on
// the two things that do matter: the IMEI is digits and the digest is a SHA-1.

func bareSL3(target string) (string, bool) {
	t := strings.TrimSpace(target)
	imei, digest, ok := strings.Cut(t, ":")
	if !ok || len(digest) != 40 || !isHex(digest) {
		return "", false
	}
	if len(imei) != 14 && len(imei) != 15 {
		return "", false
	}
	for i := 0; i < len(imei); i++ {
		if imei[i] < '0' || imei[i] > '9' {
			return "", false
		}
	}
	return sl3Prefix + imei[:14] + "$" + digest, true
}

func isBareSL3(target string) bool { _, ok := bareSL3(target); return ok }

// canonicalBareSpelling rewrites a record John wrote without a marker into
// the spelling the verifier for that type reads. A record that is already in
// that spelling, or that does not match the bare shape, is returned unchanged.
func canonicalBareSpelling(target, algo string) string {
	var rewrite func(string) (string, bool)
	switch algo {
	case "net-md5":
		rewrite = bareNetMD5
	case "dcc2":
		rewrite = bareMSCash2
	case "krb5-key":
		rewrite = bareKerberosDBKey
	case "krb5asrep", "krb5asrep-nt":
		rewrite = bareKrb5ASREP
	case "cisco-asa":
		rewrite = dynamicCiscoASA
	case "sl3":
		rewrite = bareSL3
	default:
		return target
	}
	if out, ok := rewrite(target); ok {
		return out
	}
	return target
}
