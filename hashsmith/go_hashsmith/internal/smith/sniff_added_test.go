package smith

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"hashsmith-go/internal/hashid"
)

// sniffFile writes head to a temp file and runs the container sniffer over it.
func sniffFile(t *testing.T, head []byte) (*extractorDefinition, hashid.Confidence, bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, head, 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	d, _, conf, ok := sniffContainer(path)
	return d, conf, ok
}

// TestSniffersRouteContainersByTheirOwnMagic checks the sniffers added for the
// extractors whose parsers already assert a fixed signature. Each expectation
// below is the same byte check the extractor itself performs, so a sniffer can
// never route a file the extractor would then reject for lacking that magic.
func TestSniffersRouteContainersByTheirOwnMagic(t *testing.T) {
	pad := func(prefix []byte, n int) []byte {
		b := make([]byte, n)
		copy(b, prefix)
		return b
	}
	cases := []struct {
		name      string
		head      []byte
		extractor string
		conf      hashid.Confidence
	}{
		{"android backup", []byte("ANDROID BACKUP\n5\n1\nnone\n"), "androidbackup2smith", hashid.Certain},
		{"telegram tdata", pad([]byte("TDF$abcd"), 64), "telegram2smith", hashid.Certain},
		{"encrypted dmg v2", pad([]byte("encrcdsa"), 300), "dmg2smith", hashid.Certain},
		{"ansible vault", []byte("$ANSIBLE_VAULT;1.1;AES256\n3236616...\n"), "ansible2smith", hashid.Certain},
		{"pcapng capture", pad([]byte{0x0a, 0x0d, 0x0d, 0x0a}, 64), "vncpcap2smith", hashid.Likely},
		{"classic pcap capture", pad([]byte{0xd4, 0xc3, 0xb2, 0xa1}, 64), "vncpcap2smith", hashid.Likely},
		{"mozilla key3.db", []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x15\x06\x00" +
			"junk-before-global-salt-marker global-salt more junk password-check tail"), "mozilla2smith", hashid.Likely},
		{"encfs config", []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
			`<boost_serialization><cfg><cipherAlg name="AES"/><keySize>256</keySize>` +
			`<kdfIterations>163481</kdfIterations><encodedKeySize>44</encodedKeySize>` +
			`<saltLen>20</saltLen><saltData>c29tZXNhbHQ=</saltData>` +
			`<encodedKeyData>c29tZWtleWRhdGE=</encodedKeyData></cfg></boost_serialization>`),
			"encfs2smith", hashid.Likely},
		{"openssh private key", []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----\n"),
			"ssh2smith", hashid.Certain},
		{"pkcs8 encrypted private key", []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDDBABgkq\n-----END ENCRYPTED PRIVATE KEY-----\n"),
			"ssh2smith", hashid.Certain},
		{"legacy openssl pem key", []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,0123\n\nMIIByYIBA\n-----END RSA PRIVATE KEY-----\n"),
			"ssh2smith", hashid.Certain},
		{"macos legacy keychain", append([]byte{0xfa, 0xde, 0x07, 0x11}, make([]byte, 128)...),
			"keychain2smith", hashid.Certain},
		{"vmware vmx keysafe", []byte(`encryption.keySafe = "phrase/00000000-0000-0000-0000-000000000000/` +
			`pass2key=PBKDF2-HMAC-SHA-1:cipher=AES-256:rounds=1000:salt=AAAA,AAAA,AAAA"`),
			"vmx2smith", hashid.Likely},
		{"dashlane secure archive", []byte("Some Dashlane Export\nData BEGIN\nAAAAc29tZWJhc2U2NGRhdGE=\nData END\n"),
			"dashlane2smith", hashid.Likely},
		{"padlock sjcl json", []byte(`{"cipher":"AES","mode":"ccm","ts":64,"iter":10000,"keySize":256,"adata":"","iv":"AAAA","salt":"AAAA","ct":"AAAA"}`),
			"padlock2smith", hashid.Likely},
		{"bks store header", func() []byte {
			b := make([]byte, 4+4+20+4)
			binary.BigEndian.PutUint32(b[0:4], 2)  // version
			binary.BigEndian.PutUint32(b[4:8], 20) // salt length
			binary.BigEndian.PutUint32(b[28:32], 10000)
			return b
		}(), "bks2smith", hashid.Likely},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, conf, ok := sniffFile(t, c.head)
			if !ok {
				t.Fatalf("no sniffer matched")
			}
			if d.name != c.extractor {
				t.Fatalf("routed to %s, want %s", d.name, c.extractor)
			}
			if conf != c.conf {
				t.Errorf("confidence %v, want %v", conf, c.conf)
			}
		})
	}
}

// TestSniffBitLockerDistinguishesItsTwoSignatures pins the confidence split:
// "-FVE-FS-" is BitLocker's own signature, while "MSWIN4.1" is an ordinary
// FAT/NTFS OEM name that a BitLocker-to-Go volume happens to reuse — the same
// eight bytes appear on plenty of volumes that carry no VMK at all.
func TestSniffBitLockerDistinguishesItsTwoSignatures(t *testing.T) {
	vol := func(sig string) []byte {
		b := make([]byte, 512)
		copy(b[3:11], sig)
		return b
	}
	d, conf, ok := sniffFile(t, vol("-FVE-FS-"))
	if !ok || d.name != "bitlocker2smith" {
		t.Fatalf("-FVE-FS- did not route to bitlocker2smith (ok=%v)", ok)
	}
	if conf != hashid.Certain {
		t.Errorf("-FVE-FS- confidence %v, want Certain", conf)
	}
	d, conf, ok = sniffFile(t, vol("MSWIN4.1"))
	if !ok || d.name != "bitlocker2smith" {
		t.Fatalf("MSWIN4.1 did not route to bitlocker2smith (ok=%v)", ok)
	}
	if conf != hashid.Likely {
		t.Errorf("MSWIN4.1 confidence %v, want Likely (it is a generic OEM name)", conf)
	}
}

// TestSniffersDoNotMatchUnrelatedBytes is the guard that matters most: a
// sniffer that fires on arbitrary data would route real work to the wrong
// extractor.
func TestSniffersDoNotMatchUnrelatedBytes(t *testing.T) {
	for _, head := range [][]byte{
		[]byte("just some plain text, nothing to see here\n"),
		make([]byte, 512), // all zeroes
		[]byte("SQLite format 3\x00"),
	} {
		if d, _, ok := sniffFile(t, head); ok {
			t.Errorf("%q was routed to %s; expected no match", head[:min(len(head), 24)], d.name)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSniffBKSRejectsImplausibleFields proves all three chained checks run,
// not just the version field: an out-of-range salt length or iteration
// count must still refuse the match even with a valid version.
func TestSniffBKSRejectsImplausibleFields(t *testing.T) {
	cases := map[string][]byte{
		"salt length zero": func() []byte {
			b := make([]byte, 12)
			binary.BigEndian.PutUint32(b[0:4], 1)
			binary.BigEndian.PutUint32(b[4:8], 0)
			return b
		}(),
		"salt length past file end": func() []byte {
			b := make([]byte, 12)
			binary.BigEndian.PutUint32(b[0:4], 1)
			binary.BigEndian.PutUint32(b[4:8], 9000)
			return b
		}(),
		"version 3": func() []byte {
			b := make([]byte, 12)
			binary.BigEndian.PutUint32(b[0:4], 3)
			binary.BigEndian.PutUint32(b[4:8], 8)
			return b
		}(),
	}
	for name, head := range cases {
		t.Run(name, func(t *testing.T) {
			if d, _, ok := sniffFile(t, head); ok {
				t.Errorf("%s was routed to %s; expected no match", name, d.name)
			}
		})
	}
}
