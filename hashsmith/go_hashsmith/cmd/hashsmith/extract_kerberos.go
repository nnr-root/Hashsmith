package main

// Kerberos artifacts: the ticket files an engagement actually picks up.
//
// Three converters, one shared problem. A Kerberos ticket's encrypted part is
// what gets cracked, and in every one of these files it is buried inside DER
// that the container does not describe — so the work is not cryptography, it
// is getting to the right OCTET STRING without guessing.
//
// What comes out is $krb5tgs$: the service ticket's enc-part, split after its
// first sixteen bytes because RC4-HMAC puts the confounder and checksum there
// and John's record keeps them as a separate field.

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ── A DER walker ──────────────────────────────────────────────────────────────

// derValue is one tag-length-value triple.
//
// off is where the value's BODY begins, counted from the start of the document
// the value was parsed out of. A reader that only needs the bytes can ignore
// it; a reader that has to modify the document in place — SNMPv3 zeroes its
// own authentication parameters before hashing — cannot work without it.
type derValue struct {
	class       byte // 0 universal, 1 application, 2 context, 3 private
	constructed bool
	tag         int
	body        []byte
	off         int
}

// derParse reads one value and returns it with whatever follows. base is where
// b begins inside the document, so that off is absolute.
func derParse(b []byte) (derValue, []byte, error) { return derParseAt(b, 0) }

func derParseAt(b []byte, base int) (derValue, []byte, error) {
	var v derValue
	if len(b) < 2 {
		return v, nil, io.ErrUnexpectedEOF
	}
	id := b[0]
	v.class = id >> 6
	v.constructed = id&0x20 != 0
	v.tag = int(id & 0x1f)
	i := 1
	if v.tag == 0x1f { // high tag number, seven bits at a time
		v.tag = 0
		for {
			if i >= len(b) {
				return v, nil, io.ErrUnexpectedEOF
			}
			v.tag = v.tag<<7 | int(b[i]&0x7f)
			more := b[i]&0x80 != 0
			i++
			if !more {
				break
			}
			if v.tag > 1<<20 {
				return v, nil, errors.New("DER tag number is implausible")
			}
		}
	}
	if i >= len(b) {
		return v, nil, io.ErrUnexpectedEOF
	}
	length := int(b[i])
	i++
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 || i+n > len(b) {
			return v, nil, errors.New("unsupported DER length")
		}
		length = 0
		for k := 0; k < n; k++ {
			length = length<<8 | int(b[i+k])
		}
		i += n
	}
	if length < 0 || i+length > len(b) {
		return v, nil, io.ErrUnexpectedEOF
	}
	v.body = b[i : i+length]
	v.off = base + i
	return v, b[i+length:], nil
}

// derChildren splits a constructed value into its elements.
func derChildren(v derValue) ([]derValue, error) {
	if !v.constructed {
		return nil, errors.New("this DER value is primitive and has no elements")
	}
	var out []derValue
	rest := v.body
	at := v.off
	for len(rest) > 0 {
		child, remaining, err := derParseAt(rest, at)
		if err != nil {
			return nil, err
		}
		out = append(out, child)
		at += len(rest) - len(remaining)
		rest = remaining
	}
	return out, nil
}

// derUnwrap steps through the wrappers Kerberos puts around every structure:
// an [APPLICATION n] tag whose whole content is one SEQUENCE, and a context
// tag whose whole content is one explicitly-tagged value. Both are there for
// the encoding's benefit and neither is a level anyone counting fields means.
func derUnwrap(v derValue) derValue {
	for v.constructed && v.class != 0 {
		children, err := derChildren(v)
		if err != nil || len(children) != 1 {
			return v
		}
		v = children[0]
	}
	return v
}

// derAt descends a path of element indices, unwrapping at every step, which is
// what makes a path here read the same way as the field numbers in RFC 4120.
func derAt(b []byte, path ...int) (derValue, error) {
	v, _, err := derParse(b)
	if err != nil {
		return v, err
	}
	for _, i := range path {
		v = derUnwrap(v)
		children, err := derChildren(v)
		if err != nil {
			return v, err
		}
		if i < 0 || i >= len(children) {
			return v, fmt.Errorf("this structure has %d elements, not %d", len(children), i+1)
		}
		v = children[i]
	}
	return derUnwrap(v), nil
}

// derInt reads a small non-negative INTEGER.
func derInt(v derValue) (int, error) {
	if v.tag != 2 || v.class != 0 || v.constructed {
		return 0, errors.New("this DER value is not an INTEGER")
	}
	if len(v.body) == 0 || len(v.body) > 4 {
		return 0, errors.New("this INTEGER is not a small one")
	}
	n := 0
	for _, c := range v.body {
		n = n<<8 | int(c)
	}
	return n, nil
}

// ── The encrypted part of a ticket ────────────────────────────────────────────

// krbTicketEncPart pulls the etype and the cipher out of a DER-encoded Ticket.
//
//	Ticket ::= [APPLICATION 1] SEQUENCE {
//	    tkt-vno [0], realm [1], sname [2], enc-part [3] EncryptedData }
//	EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] }
//
// kvno is OPTIONAL, so the cipher is not reliably the third element — it is
// found by its context tag instead of by counting, which is the difference
// between a reader that works on every ticket and one that works on the
// tickets its author happened to have.
func krbTicketEncPart(ticket []byte) (etype int, cipher []byte, err error) {
	encPart, err := derAt(ticket, 3)
	if err != nil {
		return 0, nil, errors.New("this is not a Kerberos Ticket: it has no enc-part")
	}
	children, err := derChildren(encPart)
	if err != nil {
		return 0, nil, err
	}
	etype = -1
	for _, c := range children {
		if c.class != 2 { // context-specific
			continue
		}
		inner := derUnwrap(c)
		switch c.tag {
		case 0:
			if etype, err = derInt(inner); err != nil {
				return 0, nil, err
			}
		case 2:
			if inner.tag != 4 || inner.class != 0 {
				return 0, nil, errors.New("a ticket's cipher is not an OCTET STRING")
			}
			cipher = inner.body
		}
	}
	if etype < 0 || len(cipher) < 17 {
		return 0, nil, errors.New("this ticket carries no usable encrypted part")
	}
	return etype, cipher, nil
}

// krbTGSRecord spells the record John's krb5tgs format reads. The split after
// sixteen bytes is not arbitrary: RC4-HMAC's output begins with an eight-byte
// confounder and an eight-byte checksum, and the format keeps them in their
// own field because the check only needs those.
func krbTGSRecord(name string, etype int, cipher []byte) string {
	if name != "" {
		return fmt.Sprintf("$krb5tgs$%d$*%s*$%s$%s", etype, name,
			hex.EncodeToString(cipher[:16]), hex.EncodeToString(cipher[16:]))
	}
	return fmt.Sprintf("$krb5tgs$%d$%s$%s", etype,
		hex.EncodeToString(cipher[:16]), hex.EncodeToString(cipher[16:]))
}

// ── .kirbi (mimikatz KRB-CRED) ────────────────────────────────────────────────

func runExtractKirbi(args []string) error {
	return runFileRecordExtractor("kirbi2smith", args, extractKirbiRecords)
}

// extractKirbiRecords reads a mimikatz ticket export.
//
//	KRB-CRED ::= [APPLICATION 22] SEQUENCE {
//	    pvno [0], msg-type [1], tickets [2] SEQUENCE OF Ticket, enc-part [3] }
//
// Every ticket in the file is emitted, not just the first: a .kirbi exported
// from a session can carry several, and picking one would silently discard
// the others.
func extractKirbiRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// mimikatz also writes the same structure as hex in a text export.
	if decoded, ok := decodeHexFile(data); ok {
		data = decoded
	}
	if len(data) == 0 || data[0] != 0x76 {
		return nil, errors.New("this file does not begin with a KRB-CRED tag, so it is not a .kirbi ticket")
	}
	tickets, err := derAt(data, 2)
	if err != nil {
		return nil, errors.New("this KRB-CRED carries no ticket list")
	}
	children, err := derChildren(tickets)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(fileBaseName(path), ".kirbi")

	var records []string
	for _, ticket := range children {
		etype, cipher, err := krbTicketEncPart(reencode(ticket))
		if err != nil {
			continue
		}
		records = append(records, krbTGSRecord(name, etype, cipher))
	}
	if len(records) == 0 {
		return nil, errors.New("no ticket in this .kirbi carried an encrypted part this tool can read")
	}
	return records, nil
}

// reencode puts a parsed value back on the wire so it can be walked as a
// document in its own right.
func reencode(v derValue) []byte {
	id := v.class<<6 | byte(v.tag&0x1f)
	if v.constructed {
		id |= 0x20
	}
	out := []byte{id}
	n := len(v.body)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	default:
		var length []byte
		for m := n; m > 0; m >>= 8 {
			length = append([]byte{byte(m)}, length...)
		}
		out = append(out, byte(0x80|len(length)))
		out = append(out, length...)
	}
	return append(out, v.body...)
}

// decodeHexFile reports whether a file is one long hex string and decodes it.
func decodeHexFile(data []byte) ([]byte, bool) {
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, string(data))
	if len(s) < 4 || len(s)%2 != 0 || !isHex(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

func fileBaseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ── krb5 credential cache (/tmp/krb5cc_NNNN) ──────────────────────────────────

func runExtractCCache(args []string) error {
	return runFileRecordExtractor("ccache2smith", args, extractCCacheRecords)
}

// ccacheTicketInitial is the ticket flag that marks a credential obtained
// directly from the AS rather than from a TGS exchange.
const ccacheTicketInitial = 0x40000000

// extractCCacheRecords reads MIT krb5's credential cache.
//
// The cache is a flat binary log with no index: to reach the Nth credential
// you must walk the N-1 before it, and each one carries two principals, a key
// block, a variable list of addresses and a variable list of authorization
// data. None of that is wanted. It is walked because the ticket sits after it.
//
// Credentials with the INITIAL flag are skipped. Those are AS replies,
// encrypted under the USER's key rather than a service account's, and John's
// krb5tgs format is not the one that reads them — emitting them here would
// hand back records that cannot crack.
//
// The flag word is stored in the cache's own byte order rather than network
// order, which is why it is byte-swapped before it is tested; a reader that
// forgets is left testing bit 6 of the wrong end and drops the wrong
// credentials.
func extractCCacheRecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := &byteReader{b: data}
	tag, err := r.take(2)
	if err != nil || tag[0] != 0x05 {
		return nil, errors.New("this file does not begin with the krb5 credential cache tag")
	}
	version := int(tag[1])
	// Versions 1 and 2 predate the name-type field in a principal and are
	// long gone; refusing them beats reading a version 3 layout out of one.
	if version != 3 && version != 4 {
		return nil, fmt.Errorf("krb5 credential cache version %d is not supported (this reads versions 3 and 4)", version)
	}
	if version == 4 {
		// A version 4 cache opens with a length-prefixed field block.
		n, err := r.take(2)
		if err != nil {
			return nil, errors.New("truncated credential cache header")
		}
		if err := r.skip(int(binary.BigEndian.Uint16(n))); err != nil {
			return nil, errors.New("truncated credential cache header")
		}
	}
	if err := ccacheSkipPrincipal(r, version); err != nil {
		return nil, fmt.Errorf("reading the cache's primary principal: %w", err)
	}

	var records []string
	for r.pos < len(data) {
		record, err := ccacheCredential(r, version)
		if err != nil {
			break
		}
		if record != "" {
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no service ticket in this cache carried an encrypted part this tool can read (an INITIAL ticket is an AS reply, not a TGS one)")
	}
	return records, nil
}

// ccacheSkipPrincipal walks one principal without keeping it.
func ccacheSkipPrincipal(r *byteReader, version int) error {
	if version != 1 {
		if _, err := r.uint32(); err != nil { // name type
			return err
		}
	}
	count, err := r.uint32()
	if err != nil || count > 1<<10 {
		return errors.New("implausible principal component count")
	}
	// Version 1 counted the realm as one of the components.
	if version == 1 {
		if count == 0 {
			return errors.New("implausible principal component count")
		}
		count--
	}
	if err := ccacheSkipData(r); err != nil { // realm
		return err
	}
	for i := uint32(0); i < count; i++ {
		if err := ccacheSkipData(r); err != nil {
			return err
		}
	}
	return nil
}

func ccacheSkipData(r *byteReader) error {
	_, err := ccacheData(r)
	return err
}

func ccacheData(r *byteReader) ([]byte, error) {
	n, err := r.uint32()
	if err != nil || n > 1<<24 {
		return nil, errors.New("implausible counted-string length in this cache")
	}
	return r.take(int(n))
}

// ccacheCredential walks one credential and returns a record for it, or an
// empty string when the credential is one to skip.
func ccacheCredential(r *byteReader, version int) (string, error) {
	if err := ccacheSkipPrincipal(r, version); err != nil { // client
		return "", err
	}
	if err := ccacheSkipPrincipal(r, version); err != nil { // server
		return "", err
	}
	// The keyblock is THREE sixteen-bit fields and then the key: a key
	// type, an enctype that repeats it, and a length. Every other
	// variable-length field in this file is prefixed with a THIRTY-TWO bit
	// length, so a reader that reuses the counted-string helper here reads
	// the key type and the enctype as one length and walks off the end of
	// the file, usually without an error.
	keyHeader, err := r.take(6)
	if err != nil {
		return "", err
	}
	if err := r.skip(int(binary.BigEndian.Uint16(keyHeader[4:6]))); err != nil {
		return "", err
	}
	if err := r.skip(4 * 4); err != nil { // authtime, starttime, endtime, renew_till
		return "", err
	}
	if _, err := r.byte(); err != nil { // is_skey
		return "", err
	}
	flags, err := r.uint32()
	if err != nil {
		return "", err
	}
	for _, counted := range []int{2, 2} { // addresses, then authorization data
		n, err := r.uint32()
		if err != nil || n > 1<<16 {
			return "", errors.New("implausible list length in this cache")
		}
		for i := uint32(0); i < n; i++ {
			if err := r.skip(counted); err != nil {
				return "", err
			}
			if err := ccacheSkipData(r); err != nil {
				return "", err
			}
		}
	}
	ticket, err := ccacheData(r)
	if err != nil {
		return "", err
	}
	if err := ccacheSkipData(r); err != nil { // second ticket
		return "", err
	}

	if swapUint32(flags)&ccacheTicketInitial != 0 {
		return "", nil
	}
	etype, cipher, err := krbTicketEncPart(ticket)
	if err != nil {
		return "", nil
	}
	return krbTGSRecord("", etype, cipher), nil
}

func swapUint32(v uint32) uint32 {
	return v>>24 | v>>8&0xff00 | v<<8&0xff0000 | v<<24
}

// ── kdcdump ───────────────────────────────────────────────────────────────────

func runExtractKDCDump(args []string) error {
	return runFileRecordExtractor("kdcdump2smith", args, extractKDCDumpRecords)
}

// extractKDCDumpRecords reads a KDC key dump.
//
// The dump is a principal name on a line of its own followed by "etype,key"
// lines. Only two enctypes give something crackable and they give DIFFERENT
// things: 23 is the RC4 key, which IS the NT hash, so the record is an NTLM
// one; 18 is an AES key derived from the password with the principal as salt,
// so the record has to rebuild that salt — realm first, then the principal
// with any "/" removed, which is the string-to-key salt Kerberos specifies and
// which nothing in the dump spells out.
func extractKDCDumpRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	name := ""
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) == 1 {
			name = line
			continue
		}
		key := strings.TrimSpace(fields[1])
		if !isHex(key) {
			continue
		}
		switch strings.TrimSpace(fields[0]) {
		case "23":
			if len(key) == 32 {
				records = append(records, "$NT$"+strings.ToLower(key))
			}
		case "18":
			principal, realm, ok := strings.Cut(name, "@")
			if !ok {
				continue
			}
			salt := realm + strings.ReplaceAll(principal, "/", "")
			records = append(records, "$krb18$"+salt+"$"+strings.ToLower(key))
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no RC4 or AES-256 keys found in this dump")
	}
	return records, nil
}
