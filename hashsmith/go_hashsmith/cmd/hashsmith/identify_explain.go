package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"hashsmith-go/internal/hashid"
)

// explainField is one decoded field of a record. Note carries an observation
// worth acting on, e.g. that an etype is the weak one or a JWT is unsigned.
type explainField struct {
	Label string
	Value string
	Note  string
}

// krbEtypes names the encryption types that appear in Kerberos records. 23 is
// called out because RC4-HMAC is the etype most exposed to offline cracking.
var krbEtypes = map[string]struct{ name, note string }{
	"17": {"AES128-CTS-HMAC-SHA1-96", ""},
	"18": {"AES256-CTS-HMAC-SHA1-96", ""},
	"23": {"RC4-HMAC", "the etype most exposed to offline cracking"},
}

// explainRecord decodes a record's internal structure. It returns nothing for
// formats that have no structure to show — a raw digest is just bytes.
func explainRecord(input string, c hashid.Candidate) []explainField {
	switch {
	case strings.HasPrefix(input, "$krb5tgs$"), strings.HasPrefix(input, "$krb5asrep$"):
		return explainKerberos(input)
	case c.Type == "jwt" || strings.HasPrefix(input, "eyJ"):
		return explainJWT(input)
	case strings.HasPrefix(input, "-----BEGIN "):
		return explainPEM(input)
	}
	return nil
}

// explainKerberos decodes a $krb5tgs$ or $krb5asrep$ record. Both carry the
// account info as free text that itself contains '$' characters — a
// TGS-REP's realm and SPN are joined by '$' inside the asterisk-bracketed
// group, and an AS-REP's user@REALM sits ahead of a ':' — so a naive
// split-on-'$' misparses them (verified against this exact record shape).
// This instead locates the bracketing punctuation directly, the same way
// parseKrb5 in crack_kerberos.go already does for the identical formats, and
// gives up cleanly — returning only what was already extracted, never
// slicing out of range — the moment the shape does not hold.
func explainKerberos(rec string) []explainField {
	var prefix string
	switch {
	case strings.HasPrefix(rec, "$krb5tgs$"):
		prefix = "$krb5tgs$"
	case strings.HasPrefix(rec, "$krb5asrep$"):
		prefix = "$krb5asrep$"
	default:
		return nil
	}

	etype, rest, ok := strings.Cut(strings.TrimPrefix(rec, prefix), "$")
	if !ok || etype == "" {
		return nil
	}
	var out []explainField
	if info, known := krbEtypes[etype]; known {
		out = append(out, explainField{"etype", etype + " (" + info.name + ")", info.note})
	} else {
		out = append(out, explainField{"etype", etype, ""})
	}

	switch prefix {
	case "$krb5tgs$":
		// rest = *user$realm$spn*$<checksum>$<edata> — the account group is
		// everything between the opening '*' and the LAST '*' in the record
		// (checksum/edata are hex and never contain one).
		if !strings.HasPrefix(rest, "*") {
			return out
		}
		star := strings.LastIndex(rest, "*")
		if star <= 0 {
			return out
		}
		fields := strings.Split(rest[1:star], "$")
		if len(fields) > 0 && fields[0] != "" {
			out = append(out, explainField{"user", fields[0], ""})
		}
		if len(fields) > 1 && fields[1] != "" {
			out = append(out, explainField{"realm", fields[1], ""})
		}
		if len(fields) > 2 && fields[2] != "" {
			out = append(out, explainField{"SPN", fields[2], ""})
		}
	case "$krb5asrep$":
		// rest = user@REALM:<checksum>$<edata>
		account, _, ok := strings.Cut(rest, ":")
		if !ok {
			return out
		}
		user, realm, ok := strings.Cut(account, "@")
		if !ok {
			return out
		}
		if user != "" {
			out = append(out, explainField{"user", user, ""})
		}
		if realm != "" {
			out = append(out, explainField{"realm", realm, ""})
		}
	}
	return out
}

// explainJWT decodes a JWT's header and, where present, a few
// engagement-relevant claims. A record that is not exactly three
// dot-separated parts, or whose header does not decode as base64url JSON, is
// left unexplained rather than partially guessed.
func explainJWT(tok string) []explainField {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil
	}
	var out []explainField
	if alg, ok := header["alg"].(string); ok {
		note := ""
		switch strings.ToLower(alg) {
		case "none":
			note = "unsigned — the signature is not verified at all"
		case "hs256", "hs384", "hs512":
			note = "HMAC: the signing key is a secret and is crackable offline"
		}
		out = append(out, explainField{"alg", alg, note})
	}
	if typ, ok := header["typ"].(string); ok {
		out = append(out, explainField{"typ", typ, ""})
	}
	if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		var claims map[string]any
		if json.Unmarshal(payload, &claims) == nil {
			for _, k := range []string{"sub", "iss", "aud"} {
				if v, ok := claims[k].(string); ok {
					out = append(out, explainField{k, v, ""})
				}
			}
		}
	}
	if parts[2] == "" {
		out = append(out, explainField{"signature", "(empty)", "no signature present"})
	}
	return out
}

// explainPEM reports a PEM block's key type and whether it carries a
// passphrase to recover. A block with no recognizable BEGIN line has already
// been excluded by explainRecord's prefix check; a missing END line does not
// prevent reading the header this function actually looks at.
func explainPEM(pem string) []explainField {
	line, _, _ := strings.Cut(pem, "\n")
	label := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "-----BEGIN "), "-----")
	out := []explainField{{"block", label, ""}}
	if strings.Contains(pem, "Proc-Type: 4,ENCRYPTED") || strings.Contains(pem, "DEK-Info:") {
		out = append(out, explainField{"encrypted", "yes", "legacy PEM encryption; crackable"})
	} else if strings.Contains(label, "ENCRYPTED") {
		out = append(out, explainField{"encrypted", "yes", "PKCS#8 encrypted private key"})
	} else {
		out = append(out, explainField{"encrypted", "no", "no passphrase to recover"})
	}
	return out
}

// renderExplain formats decoded fields for the terminal: four-space indent,
// label left-aligned to the widest label in the set, and a note appended
// after an em dash when the field carries one.
func renderExplain(fs []explainField) string {
	if len(fs) == 0 {
		return ""
	}
	wLabel := 0
	for _, f := range fs {
		if n := len(f.Label); n > wLabel {
			wLabel = n
		}
	}
	var sb strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&sb, "    %-*s  %s", wLabel, f.Label, f.Value)
		if f.Note != "" {
			fmt.Fprintf(&sb, " — %s", f.Note)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
