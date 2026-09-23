package main

// The shared half of the OpenDocument extractors.
//
// StarOffice 1.x and LibreOffice write the same kind of file — a ZIP whose
// META-INF/manifest.xml describes how content.xml was encrypted — and the two
// John converters for them differ only in which record they emit and how much
// of the manifest they read. The walk itself is one piece of code.
//
// Everything needed to check a password is in the manifest, in the clear: the
// salt, the IV, the iteration count, and a checksum over the DECRYPTED
// content. The ciphertext is only there to be checksummed.

import (
	"archive/zip"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// odfManifestEntry is the encryption data the manifest records for one file
// inside the package.
type odfManifestEntry struct {
	checksum     string
	checksumType string
	iv           string
	salt         string
	iterations   string
	keySize      string
	algorithm    string
	startKeyGen  string
	// wholePackage is set when the manifest describes ODF 1.2's
	// encrypted-package form, where the whole archive is one blob rather
	// than a set of separately encrypted parts. Nothing here reads that.
	wholePackage bool
}

// readODFManifest walks the manifest and returns the encryption data recorded
// for content.xml.
//
// It walks tokens rather than unmarshalling a struct because the encryption
// data is NESTED inside the file-entry it belongs to: the reader has to know
// which entry it is inside when it meets a checksum, and a document has
// several entries, only one of which is content.xml.
//
// Attributes are matched on their local name alone. StarOffice's manifest
// namespace is openoffice.org's and LibreOffice's is OASIS's, and a reader
// that pinned either would read exactly one of the two families.
func readODFManifest(r io.Reader) (odfManifestEntry, error) {
	var entry odfManifestEntry
	dec := xml.NewDecoder(r)
	inTarget := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return entry, errors.New("META-INF/manifest.xml is not well-formed XML")
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			if end, ok := tok.(xml.EndElement); ok && end.Name.Local == "file-entry" {
				inTarget = false
			}
			continue
		}
		attr := func(name string) string {
			for _, a := range start.Attr {
				if a.Name.Local == name {
					return a.Value
				}
			}
			return ""
		}
		switch start.Name.Local {
		case "file-entry":
			path := attr("full-path")
			if path == "encrypted-package" {
				entry.wholePackage = true
			}
			inTarget = path == "content.xml"
		case "encryption-data":
			if inTarget {
				entry.checksum = attr("checksum")
				entry.checksumType = attr("checksum-type")
			}
		case "algorithm":
			if inTarget {
				entry.iv = attr("initialisation-vector")
				entry.algorithm = attr("algorithm-name")
			}
		case "key-derivation":
			if inTarget {
				entry.salt = attr("salt")
				entry.iterations = attr("iteration-count")
				if k := attr("key-size"); k != "" {
					entry.keySize = k
				}
			}
		case "start-key-generation":
			if inTarget {
				entry.startKeyGen = attr("start-key-generation-name")
			}
		}
	}
	return entry, nil
}

// odfPackage opens the document and returns its manifest entry and the head of
// content.xml.
func odfPackage(path string, contentBytes int) (odfManifestEntry, []byte, error) {
	var entry odfManifestEntry
	zr, err := zip.OpenReader(path)
	if err != nil {
		return entry, nil, errors.New("this file is not a ZIP, so it is not an OpenDocument package")
	}
	defer zr.Close()

	var manifest, content *zip.File
	for _, f := range zr.File {
		switch f.Name {
		case "META-INF/manifest.xml":
			manifest = f
		case "content.xml":
			content = f
		}
	}
	if manifest == nil || content == nil {
		return entry, nil, errors.New("this ZIP has no META-INF/manifest.xml and content.xml pair")
	}

	mf, err := manifest.Open()
	if err != nil {
		return entry, nil, err
	}
	defer mf.Close()
	if entry, err = readODFManifest(mf); err != nil {
		return entry, nil, err
	}

	cf, err := content.Open()
	if err != nil {
		return entry, nil, err
	}
	defer cf.Close()
	stream, err := io.ReadAll(io.LimitReader(cf, int64(contentBytes)))
	if err != nil {
		return entry, nil, err
	}
	return entry, stream, nil
}

// odfBase64 decodes one manifest field, naming it when it will not decode.
func odfBase64(name, s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the manifest's %s is not base64", name)
	}
	return b, nil
}

// ── LibreOffice / OpenOffice ──────────────────────────────────────────────────

func runExtractLibreOffice(args []string) error {
	return runFileRecordExtractor("libreoffice2smith", args, extractLibreOfficeRecords)
}

// extractLibreOfficeRecords converts an encrypted OpenDocument file.
//
// Two versions share this shape and differ only in primitives: ODF 1.1 hashes
// the password with SHA-1 and encrypts with Blowfish-CFB, ODF 1.2 hashes with
// SHA-256 and encrypts with AES-256-CBC. Both stretch with PBKDF2-HMAC-SHA1
// regardless, which is the detail that looks like a mistake and is not.
//
// The manifest names the checksum algorithm and the start-key algorithm
// separately, and they MUST agree: the start key is what the checksum is
// computed over. A document naming SHA-1 for one and SHA-256 for the other
// describes a derivation nothing implements, so it is refused rather than
// guessed at — a record built from a disagreeing pair would be a record that
// cannot crack.
//
// ODF 1.2 can also encrypt the whole package as a single blob rather than
// encrypting each part. That form puts no per-part checksum in the manifest
// and is a different problem; it is named and refused.
func extractLibreOfficeRecords(path string) ([]string, error) {
	entry, content, err := odfPackage(path, 1024)
	if err != nil {
		return nil, err
	}
	if entry.wholePackage {
		return nil, errors.New("this document uses ODF 1.2 whole-package encryption, which carries no per-part checksum to check a password against")
	}
	if entry.checksum == "" || entry.iv == "" || entry.salt == "" || entry.iterations == "" {
		return nil, errors.New("this document is not encrypted: its manifest carries no checksum, IV and salt for content.xml")
	}
	if len(content) == 0 {
		return nil, errors.New("content.xml is empty")
	}

	cipherType, err := odfAlgorithmCode(entry.algorithm)
	if err != nil {
		return nil, err
	}
	checksumType, err := odfDigestCode("checksum", entry.checksumType)
	if err != nil {
		return nil, err
	}
	// The start-key algorithm defaults to SHA-1 when the manifest omits it,
	// which is what an ODF 1.1 document does.
	startKey := 0
	if entry.startKeyGen != "" {
		if startKey, err = odfDigestCode("start key", entry.startKeyGen); err != nil {
			return nil, err
		}
	}
	if startKey != checksumType {
		return nil, fmt.Errorf("this document's checksum (%s) and start key (%s) name different digests, which is a combination nothing implements",
			entry.checksumType, entry.startKeyGen)
	}
	keySize := entry.keySize
	if keySize == "" {
		keySize = "16"
	}

	checksum, err := odfBase64("checksum", entry.checksum)
	if err != nil {
		return nil, err
	}
	iv, err := odfBase64("initialisation vector", entry.iv)
	if err != nil {
		return nil, err
	}
	salt, err := odfBase64("salt", entry.salt)
	if err != nil {
		return nil, err
	}
	return []string{fmt.Sprintf("$odf$*%d*%d*%s*%s*%s*%d*%s*%d*%s*0*%s",
		cipherType, checksumType, entry.iterations, keySize,
		hexString(checksum), len(iv), hexString(iv),
		len(salt), hexString(salt), hexString(content))}, nil
}

// odfAlgorithmCode maps the manifest's cipher name to the record's number.
func odfAlgorithmCode(name string) (int, error) {
	switch {
	case containsFold(name, "Blowfish CFB"):
		return 0, nil
	case containsFold(name, "aes256-cbc"):
		return 1, nil
	case name == "":
		return 0, errors.New("this document's manifest names no encryption algorithm")
	default:
		return 0, fmt.Errorf("this document uses %q, which is neither Blowfish CFB nor aes256-cbc", name)
	}
}

// odfDigestCode maps a checksum or start-key algorithm name to its number.
// The names carry a suffix — "SHA1/1K", "SHA256/1K" — that says how much of
// the stream the checksum covers, and it is the digest that matters here.
func odfDigestCode(what, name string) (int, error) {
	switch {
	case containsFold(name, "SHA256"):
		return 1, nil
	case containsFold(name, "SHA1"):
		return 0, nil
	default:
		return 0, fmt.Errorf("this document's %s algorithm %q is neither SHA-1 nor SHA-256", what, name)
	}
}

// hexString is hex.EncodeToString under a name that reads at the call site.
func hexString(b []byte) string { return hex.EncodeToString(b) }

// containsFold reports whether s holds substr, ignoring case, which is how the
// manifest's algorithm names have to be matched: the case of "SHA1/1K" is not
// fixed across writers.
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(substr))
}
