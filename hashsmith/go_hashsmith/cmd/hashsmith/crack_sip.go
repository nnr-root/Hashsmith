package main

// SIP digest authentication (HTTP Digest / RFC 2617), the $sip$ format:
//
//	$sip$*<srv>*<cli>*<user>*<realm>*<method>*<uriproto>*<uridomain>*<uriip>*
//	     <nonce>*<nc>*<cnonce>*<qop>*<directive>*<response>
//
//	HA1 = md5(user:realm:pass)   (MD5-sess: md5(HA1:nonce:cnonce))
//	HA2 = md5(method:uri)
//	response = md5(HA1:nonce:HA2)                       (no qop)
//	         = md5(HA1:nonce:nc:cnonce:qop:HA2)         (with qop)

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
)

func md5HexStr(s string) string {
	d := md5.Sum([]byte(s))
	return hex.EncodeToString(d[:])
}

func verifySIP(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$sip$*") {
		return false, errors.New("invalid SIP hash (missing $sip$* prefix)")
	}
	f := strings.Split(targetHash, "*")
	// f[0]="$sip$"; fields 1..14 as documented above.
	if len(f) < 15 {
		return false, errors.New("invalid SIP hash (too few fields)")
	}
	user, realm, method := f[3], f[4], f[5]
	uriProto, uriDomain, uriIP := f[6], f[7], f[8]
	nonce, nc, cnonce, qop, directive := f[9], f[10], f[11], f[12], f[13]
	want := f[14]

	uri := uriProto + ":" + uriDomain
	if uriIP != "" {
		uri += ":" + uriIP
	}

	ha1 := md5HexStr(user + ":" + realm + ":" + candidate)
	if strings.EqualFold(directive, "MD5-sess") {
		ha1 = md5HexStr(ha1 + ":" + nonce + ":" + cnonce)
	}
	ha2 := md5HexStr(method + ":" + uri)

	var resp string
	if qop != "" {
		resp = md5HexStr(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		resp = md5HexStr(ha1 + ":" + nonce + ":" + ha2)
	}
	return strings.EqualFold(resp, want), nil
}
