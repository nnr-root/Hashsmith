package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hashsmith-go/internal/hashid"
	"io"
	"os"
	"strings"
	"unicode/utf16"
)

// sniffHeadBytes is how much of a file the magic-byte checks see. 4 KiB covers
// every signature below with room for the ones with offset headers.
const sniffHeadBytes = 4096

// magicSniff builds the common case: a fixed byte prefix identifies the
// format on its own, so the caller supplies the confidence it is willing to
// assert for that prefix — hashid.Certain for a signature nothing else
// plausibly starts with, something lower for one that is merely suggestive.
func magicSniff(magic []byte, evidence string, confidence hashid.Confidence) func([]byte) (hashid.Evidence, hashid.Confidence, bool) {
	return func(head []byte) (hashid.Evidence, hashid.Confidence, bool) {
		if len(head) >= len(magic) && string(head[:len(magic)]) == string(magic) {
			return hashid.Evidence(evidence), confidence, true
		}
		return "", 0, false
	}
}

// sniffKeePass reads the KDBX version words after the two signature words, so
// the answer names KDBX 3 versus 4 — which decides whether the KDF is AES or
// Argon2 and therefore how expensive the crack will be. Both signature words
// matching is as specific as file magic gets, so this is hashid.Certain.
func sniffKeePass(head []byte) (hashid.Evidence, hashid.Confidence, bool) {
	if len(head) < 12 {
		return "", 0, false
	}
	if binary.LittleEndian.Uint32(head[0:4]) != 0x9AA2D903 {
		return "", 0, false
	}
	sig2 := binary.LittleEndian.Uint32(head[4:8])
	if sig2 != 0xB54BFB67 && sig2 != 0xB54BFB66 && sig2 != 0xB54BFB65 {
		return "", 0, false
	}
	major := binary.LittleEndian.Uint16(head[10:12])
	return hashid.Evidence(fmt.Sprintf(
		"signature 0x9AA2D903 0x%08X, KDBX %d.x", sig2, major)), hashid.Certain, true
}

// sniffPKCS12 recognizes a .pfx/.p12 keystore.
//
// The raw two-byte prefix {0x30, 0x82} is only a DER SEQUENCE header with a
// two-byte length — that is the start of *any* DER-encoded structure over 256
// bytes (an X.509 certificate, a CMS/PKCS#7 blob, an RSA key, ...), not
// something unique to PKCS#12. PFX is specifically defined as
// SEQUENCE { version INTEGER, authSafe ContentInfo, ... }, so this checks
// that the SEQUENCE's very first child is the INTEGER tag holding PKCS#12's
// version 3 — a cheap, real structural constraint that a generic DER
// SEQUENCE (an X.509 certificate's first child is another SEQUENCE, not an
// INTEGER) will not usually satisfy. It is still not a full ASN.1 walk of the
// ContentInfo that follows, so this reports hashid.Likely, not Certain — the
// same distinction Task 10 drew between a checksum-verified match and a
// structural-only one.
func sniffPKCS12(head []byte) (hashid.Evidence, hashid.Confidence, bool) {
	if len(head) < 7 {
		return "", 0, false
	}
	if head[0] != 0x30 || head[1] != 0x82 {
		return "", 0, false
	}
	if head[4] != 0x02 || head[5] != 0x01 || head[6] != 0x03 {
		return "", 0, false
	}
	return hashid.Evidence("DER SEQUENCE whose first element is INTEGER 3 " +
		"(PFX ::= SEQUENCE{version INTEGER, ...}); the ContentInfo that " +
		"follows was not parsed, so this is a structural match, not a full decode"), hashid.Likely, true
}

// utf16LEBytes encodes s as little-endian UTF-16, the encoding an OLE2/CFBF
// directory entry stores its name in.
func utf16LEBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

var (
	encryptionInfoUTF16   = utf16LEBytes("EncryptionInfo")
	encryptedPackageUTF16 = utf16LEBytes("EncryptedPackage")
)

// sniffOffice recognizes the OLE2/CFBF compound-file magic that every
// pre-2007 Office document (and an encrypted 2007+ one, which MS-OFFCRYPTO
// wraps back into a CFBF container) starts with. That magic alone proves
// only "OLE2 compound file" — it is shared by .msi installers, Outlook .msg,
// Thumbs.db, and any unencrypted legacy .doc/.xls/.ppt that office2smith has
// nothing to do with, so a bare magic match reports hashid.Likely, not
// Certain.
//
// This looks deeper before giving up: a genuine MS-OFFCRYPTO document's
// directory holds an "EncryptionInfo" stream (and an "EncryptedPackage"
// stream for the 2007+ CryptoAPI/Agile schemes), and CFBF stores directory
// entry names as UTF-16LE. For a small file — the common case for a captured
// encrypted document — that directory sits well inside the first 4 KiB, so
// finding either name there is real, format-specific evidence and earns
// hashid.Certain instead of a guess from the container magic alone.
func sniffOffice(head []byte) (hashid.Evidence, hashid.Confidence, bool) {
	if len(head) < 4 || head[0] != 0xD0 || head[1] != 0xCF || head[2] != 0x11 || head[3] != 0xE0 {
		return "", 0, false
	}
	if bytes.Contains(head, encryptionInfoUTF16) || bytes.Contains(head, encryptedPackageUTF16) {
		return hashid.Evidence("OLE2 compound document containing an EncryptionInfo/EncryptedPackage " +
			"directory entry (MS-OFFCRYPTO encrypted document)"), hashid.Certain, true
	}
	return hashid.Evidence("OLE2 compound document header only; no EncryptionInfo/EncryptedPackage " +
		"directory entry found in the first 4 KiB, so this could equally be a legacy .doc/.xls/.ppt, " +
		"an .msi installer, or an Outlook .msg rather than an encrypted Office document"), hashid.Likely, true
}

// installSniffers attaches the magic-byte recognizers to the extractor
// registry. It lives here rather than in the registry literal so the registry
// stays a readable one-line-per-extractor table.
//
// Two extractors deliberately have no sniffer even though a naive one would
// be easy to write:
//
//   - truecrypt2smith: a TrueCrypt volume's header is itself encrypted with
//     the (unknown) password — the format is designed for plausible
//     deniability, so a real volume's first bytes are indistinguishable from
//     random data. The "TRUE" magic only appears in the *decrypted* header,
//     which is what cracking recovers, not something a file sniffer can see.
//     A signature here would never fire on a genuine volume, so it is left
//     out rather than published as a working check that isn't one.
//   - bitcoin2smith: Bitcoin Core's newer wallets are plain SQLite databases,
//     but "SQLite format 3\x00" is the generic SQLite header shared by
//     thousands of unrelated applications (browsers, chat apps, other
//     password managers). It carries no wallet-specific evidence, so
//     matching on it and calling the result even "likely" would be exactly
//     the dishonest-loose-signature failure this task warns against.
//     (The legacy Berkeley DB wallet.dat format has no sniffer either — it
//     shares its magic with every other BDB-backed application file.)
func installSniffers() {
	set := func(name string, fn func([]byte) (hashid.Evidence, hashid.Confidence, bool)) {
		d, ok := findExtractor(name)
		if !ok {
			panic("sniffer for unknown extractor " + name)
		}
		d.sniff = fn
	}
	set("keepass2smith", sniffKeePass)
	set("zip2smith", magicSniff([]byte("PK\x03\x04"), "ZIP local file header", hashid.Certain))
	set("7z2smith", magicSniff([]byte("7z\xBC\xAF\x27\x1C"), "7-Zip signature", hashid.Certain))
	set("rar2smith", magicSniff([]byte("Rar!\x1A\x07"), "RAR signature (RAR4/RAR5 share this prefix)", hashid.Certain))
	set("pdf2smith", magicSniff([]byte("%PDF-"), "PDF header", hashid.Certain))
	set("pfx2smith", sniffPKCS12)
	set("gpg2smith", magicSniff([]byte("-----BEGIN PGP"), "ASCII-armoured OpenPGP block", hashid.Certain))
	set("ssh2smith", magicSniff([]byte("-----BEGIN OPENSSH PRIVATE KEY"), "OpenSSH private key", hashid.Certain))
	set("luks2smith", magicSniff([]byte("LUKS\xBA\xBE"), "LUKS1 header", hashid.Certain))
	set("pwsafe2smith", magicSniff([]byte("PWS3"), "Password Safe v3 header tag; a bare 4-byte format "+
		"tag with no secondary structural check beyond the signature itself", hashid.Certain))
	set("office2smith", sniffOffice)
	set("hccapx2smith", magicSniff([]byte("HCPX"), "hccapx capture", hashid.Certain))
}

func init() { installSniffers() }

// sniffContainer reports which extractor handles a file, if any, and how
// confident that routing is.
func sniffContainer(path string) (*extractorDefinition, hashid.Evidence, hashid.Confidence, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", 0, false
	}
	defer f.Close()

	head := make([]byte, sniffHeadBytes)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, "", 0, false
	}
	head = head[:n]

	for i := range universalExtractorRegistry {
		d := &universalExtractorRegistry[i]
		if d.sniff == nil {
			continue
		}
		if ev, conf, ok := d.sniff(head); ok {
			return d, ev, conf, true
		}
	}
	return nil, "", 0, false
}

// renderContainerIdentification tells the user this is a container and what to
// run on it. Extraction is NOT performed automatically: it writes files and can
// be slow, and identify is a read-only question. The confidence word is
// whatever the sniffer that matched actually reported — never a hardcoded
// "certain" — so a structural-only match (PKCS#12, a bare OLE2 header) reads
// as "likely" rather than claiming a proof it didn't perform.
func renderContainerIdentification(path string, d *extractorDefinition, ev hashid.Evidence, conf hashid.Confidence) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %s        %s\n", d.input, conf.String())
	if ev != "" {
		fmt.Fprintf(&sb, "  %s\n", ev)
	}
	fmt.Fprintf(&sb, "\n  This is a container, not a hash. Extract the record first:\n")
	fmt.Fprintf(&sb, "      hashsmith %s -f %s\n", d.name, path)
	return sb.String()
}

// sniffCoverage reports how many extractors can be auto-routed. The gap is
// published by `identify --coverage` rather than left as an unstated limit.
func sniffCoverage() (withSniff, total int) {
	total = len(universalExtractorRegistry)
	for i := range universalExtractorRegistry {
		if universalExtractorRegistry[i].sniff != nil {
			withSniff++
		}
	}
	return withSniff, total
}
