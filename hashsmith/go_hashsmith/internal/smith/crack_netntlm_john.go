package smith

// John's NetNTLM record spellings.
//
// John writes two forms for these formats. One is a pwdump-shaped
// "user:::<lm>:<nt>:<challenge>" line, which lines up field-for-field with
// hashcat's "user::domain:lm:nt:challenge" except that John leaves the domain
// empty and writes the literal text "lm-hash" where the LM response would go
// when it does not have one. The other is a self-describing envelope:
//
//	$NETNTLM$<server challenge>$<NT response>
//	$NETNTLMv2$<identity>$<server challenge>$<NT proof>$<blob>
//
// The envelope form is the one worth reading carefully, because NTLMv2's
// identity is upper(user)+domain and John stores it ALREADY CONCATENATED.
// Re-uppercasing it would be wrong: the spec uppercases the user and takes
// the domain verbatim, so an identity whose domain half is lower case must
// not be folded. It is passed through untouched.
//
// John also has $NETLM$, $NETHALFLM$, $NETLMv2$ and $MSCHAPv2$ records. Those
// are not handled here because there is no type for them — they are LM-based
// responses and a different challenge protocol, which is missing capability
// rather than a missing spelling.

import (
	"errors"
	"strings"
)

// johnNetNTLMv1 reads "$NETNTLM$<challenge>$<NT response>" into the
// colon-separated form the v1 verifier parses. The LM field is left empty:
// this spelling carries no LM response, and the verifier only consults it to
// detect extended session security.
func johnNetNTLMv1(target string) (normalized string, ok bool) {
	const prefix = "$NETNTLM$"
	if !strings.HasPrefix(target, prefix) {
		return "", false
	}
	f := strings.Split(strings.TrimPrefix(target, prefix), "$")
	if len(f) != 2 || !isHex(f[0]) || !isHex(f[1]) {
		return "", false
	}
	return "::" + ":" + ":" + f[1] + ":" + f[0], true
}

// johnNetNTLMv2 reads "$NETNTLMv2$<identity>$<challenge>$<proof>$<blob>".
// The identity is returned separately because it must NOT be re-uppercased.
func johnNetNTLMv2(target string) (ident, srvChal, ntProof, blob string, ok bool) {
	const prefix = "$NETNTLMv2$"
	if !strings.HasPrefix(strings.ToUpper(target), strings.ToUpper(prefix)) {
		return "", "", "", "", false
	}
	f := strings.Split(target[len(prefix):], "$")
	if len(f) != 4 || f[0] == "" || !isHex(f[1]) || !isHex(f[2]) || !isHex(f[3]) {
		return "", "", "", "", false
	}
	return f[0], f[1], f[2], f[3], true
}

// isJohnNetNTLMRecord reports whether a record uses one of the two envelopes
// this file reads, for the detection table.
func isJohnNetNTLMRecord(s string) bool {
	t := strings.TrimSpace(s)
	if _, ok := johnNetNTLMv1(t); ok {
		return true
	}
	_, _, _, _, ok := johnNetNTLMv2(t)
	return ok
}

// johnNetNTLMTypes names the types those envelopes resolve to.
func johnNetNTLMTypes() []string { return []string{"netntlmv1", "netntlmv2"} }

var errNotJohnNetNTLM = errors.New("not a John NetNTLM record")
