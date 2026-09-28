package smith

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// ── DER helpers for building fixtures ────────────────────────────────────────

// der builds one tag-length-value triple. The fixtures below are encoded to
// RFC 4120's definitions rather than copied from a file, so a reader that
// happens to agree with one vendor's output still has to agree with the
// specification.
func der(id byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := []byte{id}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func derInteger(v int) []byte { return der(0x02, []byte{byte(v)}) }
func derOctets(b []byte) []byte {
	return der(0x04, b)
}

// krbTicket builds an [APPLICATION 1] Ticket carrying one EncryptedData.
// kvno is written or omitted to exercise the fact that it is OPTIONAL, which
// is why the cipher cannot be found by counting elements.
func krbTicket(etype int, cipher []byte, withKvno bool) []byte {
	encrypted := [][]byte{der(0xa0, derInteger(etype))}
	if withKvno {
		encrypted = append(encrypted, der(0xa1, derInteger(2)))
	}
	encrypted = append(encrypted, der(0xa2, derOctets(cipher)))

	return der(0x61, der(0x30,
		der(0xa0, derInteger(5)),                       // tkt-vno
		der(0xa1, der(0x1b, []byte("EXAMPLE.COM"))),    // realm
		der(0xa2, der(0x30, der(0xa0, derInteger(2)))), // sname
		der(0xa3, der(0x30, encrypted...)),             // enc-part
	))
}

func TestExtractKirbiRoundTrip(t *testing.T) {
	record, password := johnVector(t, "krb5tgs $krb5tgs$")
	f := strings.Split(strings.TrimPrefix(record, "$krb5tgs$"), "$")
	cipher := append(mustHex(t, f[1]), mustHex(t, f[2])...)

	// Two tickets, one with a kvno and one without, so the test fails if
	// the reader finds the cipher by position rather than by tag.
	kirbi := der(0x76, der(0x30,
		der(0xa0, derInteger(5)),  // pvno
		der(0xa1, derInteger(22)), // msg-type
		der(0xa2, der(0x30,
			krbTicket(23, cipher, false),
			krbTicket(23, cipher, true),
		)),
		der(0xa3, der(0x30, der(0xa0, derInteger(23)), der(0xa2, derOctets([]byte("junk"))))),
	))

	got, err := extractKirbiRecords(writeFixture(t, "ticket.kirbi", kirbi))
	if err != nil {
		t.Fatalf("extractKirbiRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("kirbi2smith returned %d records, want one per ticket: %v", len(got), got)
	}
	for i, r := range got {
		want := "$krb5tgs$23$*ticket*$" + f[1] + "$" + f[2]
		if r != want {
			t.Fatalf("record %d\n got: %.60s...\nwant: %.60s...", i, r, want)
		}
		// The verifier reads the bare spelling, so strip the name the
		// record carries for the user's benefit.
		mustCrack(t, "krb5tgs", record, password)
	}
}

func TestExtractKirbiRefusesOtherFiles(t *testing.T) {
	if _, err := extractKirbiRecords(writeFixture(t, "x.bin", []byte{0x30, 0x03, 0x02, 0x01, 0x05})); err == nil {
		t.Error("a bare SEQUENCE is not a KRB-CRED and should be refused")
	}
}

// ccacheString writes a counted octet string: a thirty-two bit length then the
// bytes. Every variable field in a credential cache uses this EXCEPT the key,
// whose length is sixteen bits.
func ccacheString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

func ccachePrincipal(realm string, components ...string) []byte {
	var buf bytes.Buffer
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], 1) // name type
	buf.Write(b4[:])
	binary.BigEndian.PutUint32(b4[:], uint32(len(components)))
	buf.Write(b4[:])
	buf.Write(ccacheString([]byte(realm)))
	for _, c := range components {
		buf.Write(ccacheString([]byte(c)))
	}
	return buf.Bytes()
}

func ccacheCredentialBytes(ticket []byte, flags uint32) []byte {
	var buf bytes.Buffer
	buf.Write(ccachePrincipal("EXAMPLE.COM", "alice"))
	buf.Write(ccachePrincipal("EXAMPLE.COM", "HTTP", "web.example.com"))
	// keyblock: keytype, etype, keylen — all sixteen bits — then the key.
	key := []byte("0123456789abcdef")
	var b2 [2]byte
	for _, v := range []uint16{23, 23, uint16(len(key))} {
		binary.BigEndian.PutUint16(b2[:], v)
		buf.Write(b2[:])
	}
	buf.Write(key)
	buf.Write(make([]byte, 16)) // four times
	buf.WriteByte(0)            // is_skey
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], flags)
	buf.Write(b4[:])
	buf.Write([]byte{0, 0, 0, 0}) // no addresses
	buf.Write([]byte{0, 0, 0, 0}) // no authorization data
	buf.Write(ccacheString(ticket))
	buf.Write(ccacheString(nil)) // second ticket
	return buf.Bytes()
}

func TestExtractCCacheRoundTrip(t *testing.T) {
	record, password := johnVector(t, "krb5tgs $krb5tgs$")
	f := strings.Split(strings.TrimPrefix(record, "$krb5tgs$"), "$")
	cipher := append(mustHex(t, f[1]), mustHex(t, f[2])...)
	ticket := krbTicket(23, cipher, false)

	var file bytes.Buffer
	file.Write([]byte{0x05, 0x04, 0x00, 0x00}) // version 4, empty header block
	file.Write(ccachePrincipal("EXAMPLE.COM", "alice"))
	file.Write(ccacheCredentialBytes(ticket, 0))
	// An INITIAL ticket is an AS reply under the user's own key, so it must
	// be skipped rather than emitted as a service ticket. The flag word is
	// stored byte-swapped, which is why the fixture writes it that way.
	file.Write(ccacheCredentialBytes(ticket, swapUint32(ccacheTicketInitial)))

	got, err := extractCCacheRecords(writeFixture(t, "krb5cc_1000", file.Bytes()))
	if err != nil {
		t.Fatalf("extractCCacheRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ccache2smith returned %d records, want 1 (the INITIAL ticket must be skipped): %v", len(got), got)
	}
	if got[0] != record {
		t.Fatalf("ccache2smith\n got: %.60s...\nwant: %.60s...", got[0], record)
	}
	mustCrack(t, "krb5tgs", got[0], password)
}

func TestExtractKDCDump(t *testing.T) {
	dump := "host/server.example.com@EXAMPLE.COM\n" +
		"23,0CB6948805F797BF2A82807973B89537\n" +
		"18,214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26\n" +
		"17,ignored\n"

	got, err := extractKDCDumpRecords(writeFixture(t, "dump.txt", []byte(dump)))
	if err != nil {
		t.Fatalf("extractKDCDumpRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("kdcdump2smith returned %d records, want 2: %v", len(got), got)
	}
	if got[0] != "$NT$0cb6948805f797bf2a82807973b89537" {
		t.Errorf("the RC4 key should become an NTLM record, got %q", got[0])
	}
	// The AES salt is the realm followed by the principal with its "/"
	// removed — a rule nothing in the dump states.
	const wantSalt = "EXAMPLE.COMhostserver.example.com"
	if !strings.HasPrefix(got[1], "$krb18$"+wantSalt+"$") {
		t.Errorf("the AES record's salt is wrong: %q", got[1])
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(got[1], "$krb18$"+wantSalt+"$")); err != nil {
		t.Errorf("the AES record's key is not hex: %q", got[1])
	}
}
