package smith

import (
	"regexp"
	"strings"
	"testing"
)

// TestJohnDynamicCorpus is the measurement that matters: every $dynamic_N$
// record in John's own test set that Hashsmith claims must crack with the
// password John ships for it, and must not crack with any other.
//
// The count is pinned so that a change which quietly stops reading a family of
// expressions is a failing test rather than a smaller number nobody notices.
func TestJohnDynamicCorpus(t *testing.T) {
	// 159 with dynamic_1507, which the engine used to decline.
	const wantClaimed = 159
	re := regexp.MustCompile(`\$dynamic_\d+\$`)
	claimed := 0
	for _, r := range loadJohnCorpus(t) {
		if !re.MatchString(r.hash) || !isJohnDynamic(r.hash) {
			continue
		}
		claimed++
		ok, err := verifyJohnDynamic(r.hash, r.pass)
		if err != nil || !ok {
			t.Errorf("%s: rejected the password John ships: ok=%v err=%v", r.format, ok, err)
			continue
		}
		if bad, _ := verifyJohnDynamic(r.hash, r.pass+"x"); bad {
			t.Errorf("%s: accepted a wrong password", r.format)
		}
	}
	if claimed != wantClaimed {
		t.Errorf("claimed %d of John's dynamic records, want %d", claimed, wantClaimed)
	}
}

// TestJohnDynamicExpressions pins the expression language itself, one
// construct at a time, against records built by hand.
func TestJohnDynamicExpressions(t *testing.T) {
	for _, tc := range []struct {
		name, record, pass string
	}{
		// A bare digest, and the nesting that makes the hex spelling matter:
		// dynamic_2 hashes the thirty-two characters of a hex digest.
		{"raw md5", "$dynamic_0$5a105e8b9d40e1329780d62ea2265d8a", "test1"},
		{"md5 of hex md5", "$dynamic_2$418d89a45edadb8ce4da17e07f72536c", "test1"},
		// A salt, on either side.
		{"salt then password", "$dynamic_4$c02e8eef3eaa1a813c2ff87c1780f9ed$123456", "test1"},
		// A username, both as a marker and as a login before the record.
		{"username marker", "$dynamic_37$13db5f41191e8e7ea5141b16cd58c75af5e27071$$Ujohn", "test1"},
		{"username as a login", "john:$dynamic_37$13db5f41191e8e7ea5141b16cd58c75af5e27071", "test1"},
		// A second salt.
		{"second salt", "$dynamic_16$5ce496c635f96ac1ccd87518d4274b49$aaaSXB$$2salt2", "test1"},
		// A hex-encoded salt, and one that hides the username inside itself.
		{"hex salt", "$dynamic_6$ad14afbbf0e16d4ad8c8985263a3d051$HEX$247824", "test"},
		{"hex salt carrying a marker", "$dynamic_1015$1d586cc8d137e5f1733f234d224393e8$HEX$f063f05d242455706f737467726573", "openwall"},
		// A literal run with no separator before it: md5(md5($s.$p):$s).
		{"literal inside an expression", "$dynamic_1350$c1f58952ab714b5ef76926628f6e0b16$92", "blondie"},
		// A padded operand, written as a suffix on the variable.
		{"null-padded password", "$dynamic_1010$B137F09CF92F465CABCA06AB1B283C1F", "lastwolf"},
		// Base64 rather than hex, and UTF-16.
		{"base64 digest of utf16", "$dynamic_1032$6Pl/upEE0epQR5SObftn+s2fW3M=", "password"},
		// A digest stored truncated, and one stored padded with zeros.
		{"truncated digest", "$dynamic_1029$e4ad93ca07acb8d908a3aa41e920ea4f", "iloveyou"},
		{"digest padded with zeros", "$dynamic_1401$27f6a9d892475e6ce0391de8d2d893f700000000$$Uusername", "password"},
		// LinkedIn's dump, SHA-1 with its first five hex digits zeroed.
		{"linkedin's zeroed prefix", "$dynamic_26$00000E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	} {
		if !isJohnDynamic(tc.record) {
			t.Errorf("%s: not claimed", tc.name)
			continue
		}
		if types := detectHashTypes(tc.record); !containsString(types, "dynamic") {
			t.Errorf("%s: detectHashTypes did not offer dynamic: %v", tc.name, types)
		}
		if ok, err := verifyJohnDynamic(tc.record, tc.pass); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.name, ok, err)
		}
		if bad, _ := verifyJohnDynamic(tc.record, tc.pass+"x"); bad {
			t.Errorf("%s: accepted a wrong password", tc.name)
		}
	}
}

// TestJohnDynamicDeclines pins what the engine will not claim. A record it
// cannot evaluate is left for something else to read rather than claimed and
// then failed, so each of these must be refused at detection.
func TestJohnDynamicDeclines(t *testing.T) {
	for _, tc := range []struct{ name, record string }{
		// An expression naming a value the expression does not carry.
		// dynamic_1507 used to be the example here; its constant turned
		// out to be published, so the case is pinned with an inline
		// expression instead — the behaviour still has to hold for any
		// record that names something the expression does not define.
		{"a value the expression does not carry", "@dynamic=sha1($const.$p)@" + strings.Repeat("ab", 20)},
		// A number John does not define.
		{"an undefined number", "$dynamic_99999$5a105e8b9d40e1329780d62ea2265d8a"},
		// Cisco's PIX and ASA records are dynamic_19 and dynamic_20, but they
		// store the digest in PIX's own base64 rather than the hex the
		// expression produces.
		{"cisco pix", "$dynamic_19$2KFQnbNIdI.2KYOU"},
		{"cisco asa", "$dynamic_20$h3mJrcH0901pqX/m$alex"},
		// Malformed records.
		{"no number", "$dynamic_$5a105e8b9d40e1329780d62ea2265d8a"},
		{"no digest", "$dynamic_0$"},
		{"not a dynamic record at all", "5a105e8b9d40e1329780d62ea2265d8a"},
	} {
		if isJohnDynamic(tc.record) {
			t.Errorf("%s: claimed a record it cannot answer for", tc.name)
		}
	}
}

// TestJohnDynamicSpecTable checks the transcription itself: every expression
// John ships must parse, or be one of the named few that cannot.
func TestJohnDynamicSpecTable(t *testing.T) {
	var unsupported, parsed int
	for number := range johnDynamicSpecs {
		c := compileDynamic(number)
		if c.err == nil {
			parsed++
			continue
		}
		unsupported++
		msg := c.err.Error()
		if !strings.Contains(msg, "are not supported") && !strings.Contains(msg, "defined outside the format") {
			t.Errorf("dynamic_%d: %v", number, msg)
		}
	}
	if parsed+unsupported != len(johnDynamicSpecs) {
		t.Fatal("the spec table lost entries")
	}
	// All 446 of John's expressions now parse. dynamic_1507 was the last
	// holdout, and it turned out not to be a holdout at all: John prints
	// its expression with a $const, but the constant is in the
	// configuration file John ships, not in a per-installation secret. See
	// john_dynamic_spec.go.
	//
	// Every name in the table resolves too: Skein raised that number by 36,
	// HAVAL by 135, Tiger by 9 and Panama by the last 9.
	if parsed != len(johnDynamicSpecs) {
		t.Errorf("%d of %d expressions parse, want all of them", parsed, len(johnDynamicSpecs))
	}
}

// TestJohnDynamic1507 pins McAfee's master password against the two vectors
// John publishes for it, in run/dynamic.conf, beside the constant itself.
//
// The constant is four bytes and two of them are control characters, so it can
// only be written as an escape — which is why the expression parser learned
// \\xNN at the same time. Getting the escape wrong puts the eight characters
// that spell the bytes into the digest instead of the four bytes, and the
// result is a format that parses, runs, and answers nothing.
func TestJohnDynamic1507(t *testing.T) {
	for _, tc := range []struct{ digest, password string }{
		{"d4eaf666d09316f9d61b14753353a73d5fbcf048", "test"},
		{"9dbe0d0ea16ae0a14c0c81a7c962b5a16e777259", "test1"},
	} {
		record := "$dynamic_1507$" + tc.digest
		if !isJohnDynamic(record) {
			t.Fatalf("%s: the engine still declines this record", tc.password)
		}
		ok, err := verifyJohnDynamic(record, tc.password)
		if err != nil || !ok {
			t.Errorf("%s: ok=%v err=%v", tc.password, ok, err)
		}
		if bad, _ := verifyJohnDynamic(record, tc.password+"x"); bad {
			t.Errorf("%s: accepted a wrong password", tc.password)
		}
	}
}

// The escape has to produce BYTES, not the characters that spell them.
func TestDynLiteralHexEscapes(t *testing.T) {
	got := dynLiteralBytes(`\x01\x0f\x0d\x33`)
	want := []byte{0x01, 0x0f, 0x0d, 0x33}
	if string(got) != string(want) {
		t.Errorf("dynLiteralBytes gave % x, want % x", got, want)
	}
	// A truncated or non-hex escape is left alone rather than swallowed.
	if string(dynLiteralBytes(`\xZZ`)) != `\xZZ` {
		t.Errorf("a non-hex escape should pass through unchanged")
	}
}
