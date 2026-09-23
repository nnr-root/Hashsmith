package smith

// A reader for Apple's property lists, in both the shapes a system actually
// writes: the binary format and the XML one.
//
// This exists because the interesting Apple artifacts are plists containing
// plists. A macOS account's password material is a binary plist stored as a
// DATA VALUE inside another binary plist, and there is no way to reach it
// without decoding the outer one first — which is why a scan for a magic
// string works for some Apple formats and not for this.
//
// Only what those artifacts use is decoded: dictionaries, arrays, data,
// strings and integers. Dates, reals, sets and UIDs are recognised so that
// walking past them works, and then discarded.

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

// plistValue is one decoded value. Exactly one field is meaningful, chosen by
// kind, which keeps the reader's callers from having to type-assert.
type plistValue struct {
	kind plistKind
	dict map[string]plistValue
	arr  []plistValue
	data []byte
	str  string
	num  int64
}

type plistKind uint8

const (
	plistOther plistKind = iota
	plistDict
	plistArray
	plistData
	plistString
	plistInt
	plistBool
)

func (v plistValue) at(key string) (plistValue, bool) {
	if v.kind != plistDict {
		return plistValue{}, false
	}
	got, ok := v.dict[key]
	return got, ok
}

// plistParse reads either shape, choosing by the header.
func plistParse(b []byte) (plistValue, error) {
	if len(b) >= 8 && string(b[:8]) == "bplist00" {
		return binaryPlistParse(b)
	}
	return xmlPlistParse(b)
}

// ── The binary format ─────────────────────────────────────────────────────────

const bplistTrailerSize = 32

type bplistReader struct {
	b          []byte
	offsets    []uint64
	refSize    int
	numObjects uint64
}

// binaryPlistParse decodes a binary plist from its trailer backwards.
//
// The trailer is the only fixed landmark: it says how many objects there are,
// where their offset table is, how wide an offset is and how wide a reference
// is. Everything else is reached through that table, so a file is read from
// its last thirty-two bytes first.
func binaryPlistParse(b []byte) (plistValue, error) {
	var zero plistValue
	if len(b) < 8+bplistTrailerSize {
		return zero, errors.New("this binary plist is too short to hold a trailer")
	}
	t := b[len(b)-bplistTrailerSize:]
	offsetSize := int(t[6])
	refSize := int(t[7])
	numObjects := binary.BigEndian.Uint64(t[8:16])
	topObject := binary.BigEndian.Uint64(t[16:24])
	tableAt := binary.BigEndian.Uint64(t[24:32])

	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 {
		return zero, errors.New("this binary plist states an implausible integer width")
	}
	if numObjects == 0 || numObjects > 1<<24 {
		return zero, errors.New("this binary plist states an implausible object count")
	}
	end := tableAt + numObjects*uint64(offsetSize)
	if tableAt < 8 || end > uint64(len(b)-bplistTrailerSize) {
		return zero, errors.New("this binary plist's offset table does not fit in the file")
	}

	r := &bplistReader{b: b, refSize: refSize, numObjects: numObjects}
	r.offsets = make([]uint64, numObjects)
	for i := uint64(0); i < numObjects; i++ {
		at := tableAt + i*uint64(offsetSize)
		r.offsets[i] = bplistUint(b[at : at+uint64(offsetSize)])
	}
	if topObject >= numObjects {
		return zero, errors.New("this binary plist's root object is out of range")
	}
	// Depth is bounded so that a file whose references form a cycle stops
	// rather than recursing until the stack goes.
	return r.object(topObject, 0)
}

func bplistUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

const bplistMaxDepth = 32

func (r *bplistReader) object(index, depth uint64) (plistValue, error) {
	var zero plistValue
	if depth > bplistMaxDepth {
		return zero, errors.New("this binary plist nests too deeply")
	}
	if index >= r.numObjects {
		return zero, errors.New("this binary plist references an object that does not exist")
	}
	at := r.offsets[index]
	if at >= uint64(len(r.b)) {
		return zero, errors.New("this binary plist's offset table points outside the file")
	}
	marker := r.b[at]
	kind, low := marker>>4, uint64(marker&0x0f)
	at++

	// A length of 0x0f means the real length is the integer object that
	// follows, which is how a collection or string longer than fourteen
	// entries is written.
	length := low
	if kind != 0x0 && kind != 0x8 && low == 0x0f {
		if at >= uint64(len(r.b)) {
			return zero, io.ErrUnexpectedEOF
		}
		intMarker := r.b[at]
		if intMarker>>4 != 0x1 {
			return zero, errors.New("this binary plist's length is not an integer")
		}
		n := uint64(1) << (intMarker & 0x0f)
		at++
		if at+n > uint64(len(r.b)) || n > 8 {
			return zero, io.ErrUnexpectedEOF
		}
		length = bplistUint(r.b[at : at+n])
		at += n
	}

	switch kind {
	case 0x0: // the singletons
		switch low {
		case 0x08:
			return plistValue{kind: plistBool}, nil
		case 0x09:
			return plistValue{kind: plistBool, num: 1}, nil
		}
		return plistValue{kind: plistOther}, nil

	case 0x1: // integer, 2^low bytes
		n := uint64(1) << low
		if at+n > uint64(len(r.b)) || n > 8 {
			return zero, io.ErrUnexpectedEOF
		}
		return plistValue{kind: plistInt, num: int64(bplistUint(r.b[at : at+n]))}, nil

	case 0x2, 0x3: // real, date — walked past, not decoded
		return plistValue{kind: plistOther}, nil

	case 0x4: // data
		if at+length > uint64(len(r.b)) {
			return zero, io.ErrUnexpectedEOF
		}
		return plistValue{kind: plistData, data: r.b[at : at+length]}, nil

	case 0x5: // ASCII string
		if at+length > uint64(len(r.b)) {
			return zero, io.ErrUnexpectedEOF
		}
		return plistValue{kind: plistString, str: string(r.b[at : at+length])}, nil

	case 0x6: // UTF-16BE string, length in CHARACTERS rather than bytes
		n := length * 2
		if at+n > uint64(len(r.b)) {
			return zero, io.ErrUnexpectedEOF
		}
		units := make([]uint16, length)
		for i := uint64(0); i < length; i++ {
			units[i] = binary.BigEndian.Uint16(r.b[at+i*2:])
		}
		return plistValue{kind: plistString, str: string(utf16.Decode(units))}, nil

	case 0x8: // UID
		return plistValue{kind: plistOther}, nil

	case 0xa, 0xc: // array, set
		refs, err := r.refs(at, length)
		if err != nil {
			return zero, err
		}
		out := plistValue{kind: plistArray}
		for _, ref := range refs {
			v, err := r.object(ref, depth+1)
			if err != nil {
				return zero, err
			}
			out.arr = append(out.arr, v)
		}
		return out, nil

	case 0xd: // dictionary: all the keys, then all the values
		refs, err := r.refs(at, length*2)
		if err != nil {
			return zero, err
		}
		out := plistValue{kind: plistDict, dict: make(map[string]plistValue, length)}
		for i := uint64(0); i < length; i++ {
			key, err := r.object(refs[i], depth+1)
			if err != nil {
				return zero, err
			}
			value, err := r.object(refs[length+i], depth+1)
			if err != nil {
				return zero, err
			}
			if key.kind == plistString {
				out.dict[key.str] = value
			}
		}
		return out, nil
	}
	return plistValue{kind: plistOther}, nil
}

func (r *bplistReader) refs(at, count uint64) ([]uint64, error) {
	n := count * uint64(r.refSize)
	if count > r.numObjects || at+n > uint64(len(r.b)) {
		return nil, errors.New("this binary plist's collection does not fit in the file")
	}
	out := make([]uint64, count)
	for i := uint64(0); i < count; i++ {
		out[i] = bplistUint(r.b[at+i*uint64(r.refSize) : at+(i+1)*uint64(r.refSize)])
	}
	return out, nil
}

// ── The XML format ────────────────────────────────────────────────────────────

// xmlPlistParse reads the shape `plutil -convert xml1` writes, which is also
// what a user pastes when they have run `defaults read`.
//
// A <dict> is a FLAT list of alternating <key> and value elements rather than
// a nested structure, so the reader has to remember whether the last thing it
// saw was a key. That is the only awkward part of the format and the only
// place a reader goes wrong quietly.
func xmlPlistParse(b []byte) (plistValue, error) {
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return plistValue{}, errors.New("this file is not a property list")
		}
		if err != nil {
			return plistValue{}, errors.New("this property list is not well-formed XML")
		}
		if start, ok := tok.(xml.StartElement); ok {
			switch start.Name.Local {
			case "plist":
				continue
			default:
				return xmlPlistValue(dec, start, 0)
			}
		}
	}
}

func xmlPlistValue(dec *xml.Decoder, start xml.StartElement, depth int) (plistValue, error) {
	var zero plistValue
	if depth > bplistMaxDepth {
		return zero, errors.New("this property list nests too deeply")
	}
	switch start.Name.Local {
	case "dict":
		out := plistValue{kind: plistDict, dict: map[string]plistValue{}}
		key := ""
		haveKey := false
		for {
			tok, err := dec.Token()
			if err != nil {
				return zero, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					text, err := xmlPlistText(dec)
					if err != nil {
						return zero, err
					}
					key, haveKey = text, true
					continue
				}
				v, err := xmlPlistValue(dec, t, depth+1)
				if err != nil {
					return zero, err
				}
				if haveKey {
					out.dict[key] = v
					haveKey = false
				}
			case xml.EndElement:
				if t.Name.Local == "dict" {
					return out, nil
				}
			}
		}
	case "array":
		out := plistValue{kind: plistArray}
		for {
			tok, err := dec.Token()
			if err != nil {
				return zero, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := xmlPlistValue(dec, t, depth+1)
				if err != nil {
					return zero, err
				}
				out.arr = append(out.arr, v)
			case xml.EndElement:
				if t.Name.Local == "array" {
					return out, nil
				}
			}
		}
	case "data":
		text, err := xmlPlistText(dec)
		if err != nil {
			return zero, err
		}
		// The encoder wraps base64 at column 76 and indents it.
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
				return -1
			}
			return r
		}, text)
		raw, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return zero, errors.New("a <data> element is not base64")
		}
		return plistValue{kind: plistData, data: raw}, nil
	case "integer":
		text, err := xmlPlistText(dec)
		if err != nil {
			return zero, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if err != nil {
			return zero, fmt.Errorf("an <integer> element reads %q", text)
		}
		return plistValue{kind: plistInt, num: n}, nil
	case "string":
		text, err := xmlPlistText(dec)
		if err != nil {
			return zero, err
		}
		return plistValue{kind: plistString, str: text}, nil
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return zero, err
		}
		n := int64(0)
		if start.Name.Local == "true" {
			n = 1
		}
		return plistValue{kind: plistBool, num: n}, nil
	}
	if err := dec.Skip(); err != nil {
		return zero, err
	}
	return plistValue{kind: plistOther}, nil
}

func xmlPlistText(dec *xml.Decoder) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			return sb.String(), nil
		}
	}
}
