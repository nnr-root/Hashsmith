package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// TestJohnSpellings runs John's spelling of each record through the verifier
// Hashsmith already had, and then the spelling Hashsmith writes through the
// same verifier, so neither reading can regress without the other noticing.
func TestJohnSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, typ, format, own, ownPass string
	}{
		{"CRC-32", "crc32-hashcat", "CRC32 $crc32$", "fa455f6b:00000000", "ripper"},
		{"CRC-32C", "crc32c-hashcat", "CRC32 $crc32c$", "98a61e94:00000000", "ripper"},
		{"iSCSI CHAP", "chap", "chap $chap$", "81474a4f7a3dbf22e071a02c10e54b47:abcdef0123456789:1b", "hashsmith"},
		{"scrypt, crypt spelling", "scrypt", "scrypt $7$", "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=", "hashcat"},
		{"scrypt, the Perl module's", "scrypt", "scrypt $scryptkdf.pm$", "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=", "hashcat"},
		{"MongoDB MONGODB-CR", "mongodb", "MongoDB $mongodb$", "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM=", "hashsmith"},
		{"MongoDB SCRAM-SHA-1", "mongodb", "scram $scram$", "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM=", "hashsmith"},
		{"plaintext", "plaintext", "plaintext $0$", "hashcat", "hashcat"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.name, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.name, ok, err)
		}
		if bad, _ := verifyCandidate(pass+"x", record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.name)
		}
		// Hashsmith's own spelling of the same format must keep working.
		if ok, err := verifyCandidate(tc.ownPass, tc.own, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: its own spelling regressed: ok=%v err=%v", tc.name, ok, err)
		}
	}
}

// TestJohnSpellingsRefused pins the records these readers must not claim: a
// prefix alone is not enough, the fields behind it have to parse.
func TestJohnSpellingsRefused(t *testing.T) {
	for _, tc := range []struct{ name, record string }{
		{"a seeded CRC with no seed", "$crc32$fa455f6b"},
		{"a seeded CRC whose words are not hex", "$crc32$zzzzzzzz.fa455f6b"},
		{"a CHAP record with too few fields", "$chap$0*cc7e5247514551acdcbf782c4027bfb1"},
		{"a $7$ record with no digest", "$7$C6..../....SodiumChloride"},
		{"a Perl scrypt record with a bad count", "$ScryptKDF.pm$x*8*1*bjZkemVmZ3lWVi42*cmBflTPsqGIbg9ZIJRTQdbic8OCUH+904TFmNPBkuEA="},
		{"a MongoDB record naming the network hash", "$mongodb$1$sa$75692b1d11c072c6c79332e248c4f699"},
		{"a SCRAM record with too few fields", "$scram$someadmin$10000$wf42AF7JaU1NSeBaSmkKzw=="},
	} {
		if types := detectHashTypes(tc.record); len(types) > 0 {
			t.Errorf("%s: claimed as %v", tc.name, types)
		}
	}
}

// TestMacOSLegacyHashes covers the two hashes macOS used before PBKDF2. Both
// are a salt and a digest run together, so the length is the signature.
func TestMacOSLegacyHashes(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"xsha", "xsha"},
		{"xsha512", "xsha512"},
		{"xsha512", "xsha512 $lion$"},
		{"xsha512", "XSHA512-opencl"},
		{"xsha512", "XSHA512-free-opencl $lion$"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.format, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.format, ok, err)
		}
		if bad, _ := verifyCandidate(pass+"x", record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.format)
		}
	}
	// A record of the wrong length is not one of these, whatever it contains.
	for _, bad := range []string{
		"12345678F9083C7F66F46A0A102E4CC17EC08C8AF12057",    // a hex digit short
		"12345678F9083C7F66F46A0A102E4CC17EC08C8AF120571BB", // one too many
		"f9083c7f66f46a0a102e4cc17ec08c8af120571b",          // a bare SHA-1
	} {
		if isXSHA(bad) || isXSHA512(bad) {
			t.Errorf("%q: claimed as a macOS hash", bad)
		}
	}
}

// TestTrueCryptJohnSpelling covers John's TrueCrypt records, which name the
// derivation in the prefix and then write the header as hashcat does.
func TestTrueCryptJohnSpelling(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"truecrypt-ripemd160", "tc_ripemd160"},
		{"truecrypt-sha512", "tc_sha512"},
		{"truecrypt-whirlpool", "tc_whirlpool"},
		{"truecrypt-ripemd160-boot-xts512", "tc_ripemd160boot"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.format, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.format, ok, err)
		}
		if bad, _ := verifyCandidate(pass+"x", record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.format)
		}
	}
}

// TestInlineDynamicExpression covers John's spelling for an expression given
// on the spot rather than chosen from its table — which is also how a scheme
// this tool has never heard of can be cracked without writing any code.
func TestInlineDynamicExpression(t *testing.T) {
	for _, tc := range []struct{ name, record, pass string }{
		{"John's own vector", "@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72", "abc"},
		{"a salted expression", "@dynamic=sha256($s.md5($p))@7fe4ed912863a25e8209de72f19b21535951cd77be956a3cd11f3474f54c261b$NaCl", "secret"},
	} {
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
	// An expression naming a hash this engine does not have is refused rather
	// than claimed, exactly as a numbered record naming one would be.
	if isJohnDynamic("@dynamic=tiger($p)@c099bbd00faf33027ab55bfb4c3a67f19ecd8eb950078ed2") {
		t.Error("claimed an expression it cannot run")
	}
	if isJohnDynamic("@dynamic=md5($p)900150983cd24fb0d6963f7d28e17f72") {
		t.Error("claimed an expression that was never closed")
	}
}

// TestCisco4Envelope covers John's $cisco4$ spelling of a Cisco type 4 hash.
func TestCisco4Envelope(t *testing.T) {
	record, pass := johnVector(t, "Raw-SHA256 $cisco4$")
	if types := detectHashTypes(record); !containsString(types, "cisco4") {
		t.Errorf("detectHashTypes did not offer cisco4: %v", types)
	}
	if ok, err := verifyCandidate(pass, record, "cisco4", "", "prefix"); err != nil || !ok {
		t.Errorf("rejected the right password: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyCandidate(pass+"x", record, "cisco4", "", "prefix"); bad {
		t.Error("accepted a wrong password")
	}
}

// TestSmallJohnFormats covers four formats John reads that Hashsmith did not,
// each against John's own vector.
func TestSmallJohnFormats(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"azuread", "AzureAD"},
		{"known-hosts", "known_hosts $known_hosts$"},
		{"zipmonster", "ZipMonster $zipmonster$"},
		{"dummy", "dummy $dummy$"},
		{"p5k2", "PBKDF2-HMAC-SHA1 $p5k2$"},
		{"ike", "IKE $ike$"},
		{"office-old", "oldoffice"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.format, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.format, ok, err)
		}
		if bad, _ := verifyCandidate("x"+pass, record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong password", tc.format)
		}
	}
}

// TestAzureADDerivation states what an Azure AD record actually protects. The
// password never reaches PBKDF2: the NTLM hash does, written as upper-case hex
// in UTF-16LE. Anyone holding the on-premises hash can check a candidate
// against the cloud record without knowing the password, which is worth
// pinning so the reading is not "simplified" into hashing the password.
func TestAzureADDerivation(t *testing.T) {
	record, pass := johnVector(t, "AzureAD")
	salt, rounds, digest, err := azureADFields(record)
	if err != nil {
		t.Fatal(err)
	}
	if rounds != 100 {
		t.Errorf("read %d rounds, want 100", rounds)
	}
	key := utf16le(strings.ToUpper(hex.EncodeToString(ntHash(pass))))
	if got := pbkdf2.Key(key, salt, rounds, len(digest), sha256.New); !hmac.Equal(got, digest) {
		t.Error("the stated derivation does not reproduce the record")
	}
	// Hashing the password itself must NOT reproduce it.
	if got := pbkdf2.Key([]byte(pass), salt, rounds, len(digest), sha256.New); hmac.Equal(got, digest) {
		t.Error("the record is a PBKDF2 over the password after all")
	}
}

// TestKnownHostsCandidateIsAHostname pins what a known_hosts entry answers
// for. The secret is a hostname or address, not a password, so the wordlist
// that cracks one is a list of machines.
func TestKnownHostsCandidateIsAHostname(t *testing.T) {
	record, host := johnVector(t, "known_hosts $known_hosts$")
	if ok, err := verifyKnownHosts(record, host); err != nil || !ok {
		t.Fatalf("rejected the right host: ok=%v err=%v", ok, err)
	}
	for _, other := range []string{"213.100.98.218", "213.100.98.21", "example.com", ""} {
		if bad, _ := verifyKnownHosts(record, other); bad {
			t.Errorf("%q: accepted the wrong host", other)
		}
	}
}

// TestRoutingAuthentication covers the keyed-MAC members of the routing
// family against John's own captures.
func TestRoutingAuthentication(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"net-ah", "net-ah $net-ah$"},
		{"rsvp", "rsvp $rsvp$"},
		{"ospf", "ospf $ospf$"},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, tc.typ) {
			t.Errorf("%s: detectHashTypes did not offer %s: %v", tc.format, tc.typ, types)
		}
		if ok, err := verifyCandidate(pass, record, tc.typ, "", "prefix"); err != nil || !ok {
			t.Errorf("%s: rejected the right key: ok=%v err=%v", tc.format, ok, err)
		}
		if bad, _ := verifyCandidate("x"+pass, record, tc.typ, "", "prefix"); bad {
			t.Errorf("%s: accepted a wrong key", tc.format)
		}
	}
}

// TestOSPFApad pins RFC 5709's filler, which is the one thing about OSPF's
// cryptographic authentication that cannot be guessed from the packet: the
// authentication field is set to 0x878FE1F3 repeated before the MAC is taken,
// and a MAC over the packet alone does not match.
func TestOSPFApad(t *testing.T) {
	if got := hex.EncodeToString(ospfApad(20)); got != "878fe1f3878fe1f3878fe1f3878fe1f3878fe1f3" {
		t.Errorf("Apad = %s", got)
	}
	record, pass := johnVector(t, "ospf $ospf$")
	_, packet, digest, err := routingRecord(record, "$ospf$")
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha1.New, []byte(pass))
	mac.Write(packet)
	if hmac.Equal(mac.Sum(nil), digest) {
		t.Error("the MAC over the packet alone matched, so Apad is not part of this record after all")
	}
}

// TestAHIsTruncated pins that an AH record carries ninety-six bits of a MAC
// rather than a whole one, and that the check compares exactly what is there.
func TestAHIsTruncated(t *testing.T) {
	record, pass := johnVector(t, "net-ah $net-ah$")
	_, packet, digest, err := routingRecord(record, "$net-ah$")
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 12 {
		t.Fatalf("AH digest is %d bytes, want 12", len(digest))
	}
	mac := hmac.New(md5.New, []byte(pass))
	mac.Write(packet)
	full := mac.Sum(nil)
	if !hmac.Equal(full[:12], digest) {
		t.Error("the first twelve bytes of the MAC are not what the record holds")
	}
	if hmac.Equal(full, digest) {
		t.Error("the record holds a whole MAC, so the truncation is not real")
	}
}

// TestKerberosDatabaseKeys covers the long-term keys a KDC stores, which are
// the key itself rather than something encrypted with it.
func TestKerberosDatabaseKeys(t *testing.T) {
	for _, tc := range []struct {
		format string
		size   int
	}{
		{"krb5-17 $krb17$", 16},
		{"krb5-18 $krb18$", 32},
	} {
		record, pass := johnVector(t, tc.format)
		if types := detectHashTypes(record); !containsString(types, "krb5-key") {
			t.Errorf("%s: detectHashTypes did not offer krb5-key: %v", tc.format, types)
		}
		etype, salt, key, err := krbDBKeyFields(record)
		if err != nil {
			t.Fatalf("%s: %v", tc.format, err)
		}
		if len(key) != tc.size {
			t.Errorf("%s: key is %d bytes, want %d", tc.format, len(key), tc.size)
		}
		// The salt is the principal with no separator, so it is neither hex
		// nor random — worth pinning, because reading it as either would
		// silently change every derivation.
		if salt == "" || isHex(salt) {
			t.Errorf("%s: salt %q does not look like a principal", tc.format, salt)
		}
		if ok, err := verifyKrbDBKey(record, pass); err != nil || !ok {
			t.Errorf("%s: rejected the right password: ok=%v err=%v", tc.format, ok, err)
		}
		if bad, _ := verifyKrbDBKey(record, pass+"x"); bad {
			t.Errorf("%s: accepted a wrong password", tc.format)
		}
		// The two etypes differ only in key length, so a record must not
		// verify under the other one's reading.
		other := map[string]string{"krb17": "krb18", "krb18": "krb17"}[etype]
		swapped := strings.Replace(record, "$"+etype+"$", "$"+other+"$", 1)
		if _, err := verifyKrbDBKey(swapped, pass); err == nil {
			t.Errorf("%s: read as %s as well", tc.format, other)
		}
	}
}

// TestMSKrb5Spelling pins John's spelling of an etype-23 pre-authentication
// record, which writes the checksum before the encrypted timestamp where
// hashcat runs the two together with the checksum last.
func TestMSKrb5Spelling(t *testing.T) {
	record, pass := johnVector(t, "krb5pa-md5 $mskrb5$")
	if types := detectHashTypes(record); !containsString(types, "krb5pa") {
		t.Errorf("detectHashTypes did not offer krb5pa: %v", types)
	}
	rewritten, ok := johnMSKrb5Record(record)
	if !ok {
		t.Fatal("the record did not read")
	}
	if !strings.HasPrefix(rewritten, "$krb5pa$23$") {
		t.Errorf("rewritten as %q", rewritten)
	}
	if ok, err := verifyKrb5(record, pass); err != nil || !ok {
		t.Errorf("rejected the right password: ok=%v err=%v", ok, err)
	}
	// A record whose fields are the wrong length is not this format.
	for _, bad := range []string{
		"$mskrb5$$$958db4ddb514a6cc8be1b1ccf82b0191",
		"$mskrb5$$$958db4ddb514a6cc8be1b1ccf82b01$0904",
	} {
		if isJohnMSKrb5(bad) {
			t.Errorf("%q: claimed", bad)
		}
	}
}
