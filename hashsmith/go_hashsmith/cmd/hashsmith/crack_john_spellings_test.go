package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
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

// TestVaultAndKeystoreRecords covers the three password stores whose John
// records this reads.
func TestVaultAndKeystoreRecords(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"jks-keystore", "keystore $keystore$"},
		{"1password", "agilekeychain $agilekeychain$"},
		{"1password-cloud", "cloudkeychain $cloudkeychain$"},
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

// TestKeystoreIsTheStoresOwnDigest pins what a keystore record checks. The
// digest closes the file and covers the password, the constant and every byte
// before it — so a change anywhere in the store must break it, which is also
// what makes the check as cheap as one SHA-1.
func TestKeystoreIsTheStoresOwnDigest(t *testing.T) {
	record, pass := johnVector(t, "keystore $keystore$")
	store, digest, err := keystoreFields(record)
	if err != nil {
		t.Fatal(err)
	}
	h := sha1.New()
	h.Write(utf16be(pass))
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(store)
	if !hmac.Equal(h.Sum(nil), digest) {
		t.Fatal("the stated construction does not reproduce the digest")
	}
	// Without the constant it does not match, so the constant is load-bearing
	// rather than decoration.
	h2 := sha1.New()
	h2.Write(utf16be(pass))
	h2.Write(store)
	if hmac.Equal(h2.Sum(nil), digest) {
		t.Error("the digest does not include Sun's constant after all")
	}
	// A single changed byte anywhere in the store breaks it.
	tampered := append([]byte(nil), store...)
	tampered[len(tampered)/2] ^= 1
	h3 := sha1.New()
	h3.Write(utf16be(pass))
	h3.Write([]byte("Mighty Aphrodite"))
	h3.Write(tampered)
	if hmac.Equal(h3.Sum(nil), digest) {
		t.Error("the digest does not cover the store")
	}
}

// TestRAKPAndPMKIDSpellings covers two captures John writes with different
// punctuation from hashcat: the IPMI RAKP exchange and a WPA PMKID.
func TestRAKPAndPMKIDSpellings(t *testing.T) {
	record, pass := johnVector(t, "RAKP $rakp$")
	if types := detectHashTypes(record); !containsString(types, "ipmi") {
		t.Errorf("detectHashTypes did not offer ipmi: %v", types)
	}
	if ok, err := verifyCandidate(pass, record, "ipmi", "", "prefix"); err != nil || !ok {
		t.Errorf("RAKP: rejected the right password: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyCandidate("x"+pass, record, "ipmi", "", "prefix"); bad {
		t.Error("RAKP: accepted a wrong password")
	}

	// The PMKID record is cracked two ways, and both readings are offered
	// because the record cannot say which secret the operator holds.
	pmkid, passphrase := johnVector(t, "wpapsk")
	types := detectHashTypes(pmkid)
	for _, want := range []string{"wpa", "wpa-pmk"} {
		if !containsString(types, want) {
			t.Errorf("detectHashTypes did not offer %s: %v", want, types)
		}
	}
	if ok, err := verifyCandidate(passphrase, pmkid, "wpa", "", "prefix"); err != nil || !ok {
		t.Errorf("PMKID: rejected the right passphrase: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyCandidate(passphrase+"x", pmkid, "wpa", "", "prefix"); bad {
		t.Error("PMKID: accepted a wrong passphrase")
	}
	// And the same record answers for a PMK given directly, which is the
	// second reading the prototype offers.
	pmkRecord, pmk := johnVector(t, "wpapsk-pmk")
	if ok, err := verifyCandidate(pmk, pmkRecord, "wpa-pmk", "", "prefix"); err != nil || !ok {
		t.Errorf("PMK: rejected the right PMK: ok=%v err=%v", ok, err)
	}
	// A line with colons is hashcat's own spelling and must not be rewritten.
	if _, ok := johnWPAPMKIDRecord("2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4:ed487162465a774bfba60eb603a39f3a"); ok {
		t.Error("claimed hashcat's colon-separated record as John's")
	}
}

// TestWPAPSKBlob covers John's WPA record, which encodes the whole handshake
// as one structure rather than naming its fields.
func TestWPAPSKBlob(t *testing.T) {
	record, pass := johnVector(t, "wpapsk $wpapsk$")
	types := detectHashTypes(record)
	for _, want := range []string{"wpa", "wpa-pmk"} {
		if !containsString(types, want) {
			t.Errorf("detectHashTypes did not offer %s: %v", want, types)
		}
	}
	if ok, err := verifyCandidate(pass, record, "wpa", "", "prefix"); err != nil || !ok {
		t.Errorf("rejected the right passphrase: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyCandidate(pass+"x", record, "wpa", "", "prefix"); bad {
		t.Error("accepted a wrong passphrase")
	}
	// The same capture answers for a PMK given directly.
	pmkRecord, pmk := johnVector(t, "wpapsk-pmk $wpapsk$")
	if ok, err := verifyCandidate(pmk, pmkRecord, "wpa-pmk", "", "prefix"); err != nil || !ok {
		t.Errorf("rejected the right PMK: ok=%v err=%v", ok, err)
	}

	// The two readings of the encoding both produce 356 bytes, so the thing
	// that settles which is right is where the EAPOL frame lands. Pin the
	// decode by checking the rewritten record's fields rather than trusting
	// that it happened to verify.
	rewritten, ok := johnWPAPSKRecord(record)
	if !ok {
		t.Fatal("the record did not read")
	}
	f := strings.Split(rewritten, "*")
	if len(f) != 9 || f[0] != "WPA" || f[1] != "02" {
		t.Fatalf("rewritten as %q", rewritten)
	}
	if f[8] != "2" {
		t.Errorf("key version read as %q, want 2", f[8])
	}
	eapol, err := hex.DecodeString(f[7])
	if err != nil || len(eapol) < 4 {
		t.Fatalf("EAPOL frame: %v", err)
	}
	// A valid 802.1X EAPOL-Key frame: version 1 or 2, type 3, then a length
	// that accounts for the rest of the frame.
	if (eapol[0] != 1 && eapol[0] != 2) || eapol[1] != 3 {
		t.Errorf("EAPOL frame starts %x, which is not an 802.1X key frame", eapol[:4])
	}
	if got := int(eapol[2])<<8 | int(eapol[3]); got+4 != len(eapol) {
		t.Errorf("EAPOL declares %d bytes, frame is %d", got+4, len(eapol))
	}
	// The station's nonce appears inside the frame; the one the record names
	// is the access point's, so they must differ.
	if strings.Contains(f[7], f[6]) {
		t.Error("the nonce named in the record is the one inside the frame")
	}
}

// TestZeroedDigestShapes covers three records whose shape says more than
// their length: two SHA-1s with a run of zeros where a dump or a truncation
// put them, and an Oracle logon capture.
func TestZeroedDigestShapes(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"sha1-linkedin", "Raw-SHA1-Linkedin"},
		{"axcrypt-sha1", "Raw-SHA1-AxCrypt"},
		{"tripcode", "tripcode"},
		{"oracle-o5logon", "o5logon $o5logon$"},
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

	// The plain readings are still offered: a real SHA-1 can begin with five
	// zeros or end with eight, so neither shape may suppress them.
	for _, rec := range []string{
		"000007f070b64a50e9d31ac3f9eda35120e29d6c",
		"e5b1b15baef2fc90a5673262440a959200000000",
	} {
		if types := detectHashTypes(rec); !containsString(types, "sha1") {
			t.Errorf("%s: sha1 was suppressed: %v", rec, types)
		}
	}

	// And an ordinary SHA-1 is not claimed as either.
	const plain = "a9993e364706816aba3e25717850c26c9cd0d89d"
	for _, unwanted := range []string{"sha1-linkedin", "axcrypt-sha1"} {
		if types := detectHashTypes(plain); containsString(types, unwanted) {
			t.Errorf("an ordinary SHA-1 was claimed as %s", unwanted)
		}
	}
}

// TestDiskAndCertificateRecords covers a VirtualBox image and John's PKCS#12
// spelling.
func TestDiskAndCertificateRecords(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"vdi", "vdi $vdi$"},
		{"pfx", "pfx $pfxng$"},
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

	// A VirtualBox image costs BOTH iteration counts per candidate, because
	// the password protects a key and the key is what the stored hash covers.
	// Pin that the second derivation is really consulted: a record whose
	// final hash is wrong must not verify even though the first half is
	// untouched.
	record, pass := johnVector(t, "vdi $vdi$")
	r, err := parseVDI(record)
	if err != nil {
		t.Fatal(err)
	}
	if r.keyIter < 1 || r.endIter < 1 {
		t.Error("both iteration counts must be read")
	}
	f := strings.Split(record, "$")
	f[len(f)-1] = strings.Repeat("00", len(r.want))
	if bad, _ := verifyVDI(strings.Join(f, "$"), pass); bad {
		t.Error("verified a record whose final hash is wrong")
	}
}

// TestPuttyAndOpenSSLEnc covers a PuTTY key and an `openssl enc` file.
func TestPuttyAndOpenSSLEnc(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"putty", "PuTTY $putty$"},
		{"openssl-enc", "openssl-enc $openssl$"},
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

	// A PuTTY key with an unprotected private half has no passphrase to find,
	// and saying so beats returning false for every candidate.
	record, _ := johnVector(t, "PuTTY $putty$")
	if _, err := verifyPutty(strings.Replace(record, "aes256-cbc", "none", 1), "x"); err == nil {
		t.Error("claimed to check an unencrypted PuTTY key")
	}
}

// TestOpenSSLEncRejectsPaddingAlone pins the reason `openssl enc` needs more
// than a padding check. Valid padding happens by chance about once in 256
// tries, so a run of that length would stop on a wrong answer; requiring the
// plaintext to be text as well is what makes the check mean something.
func TestOpenSSLEncRejectsPaddingAlone(t *testing.T) {
	record, pass := johnVector(t, "openssl-enc $openssl$")
	r, err := parseOpenSSLEnc(record)
	if err != nil {
		t.Fatal(err)
	}
	var paddingOnly, accepted int
	for i := 0; i < 20000; i++ {
		guess := "wrong-" + strconv.Itoa(i)
		key, iv := evpBytesToKey(r.newHash, []byte(guess), r.salt, 1, r.keyLen, 16)
		block, _ := aes.NewCipher(key)
		plain := make([]byte, len(r.sample))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, r.sample)
		n := int(plain[len(plain)-1])
		ok := n >= 1 && n <= 16 && n <= len(plain)
		for j := 0; ok && j < n; j++ {
			if int(plain[len(plain)-1-j]) != n {
				ok = false
			}
		}
		if ok {
			paddingOnly++
		}
		if got, _ := verifyOpenSSLEnc(record, guess); got {
			accepted++
		}
	}
	if paddingOnly == 0 {
		t.Error("twenty thousand wrong passwords produced no valid padding at all, so this test is not measuring what it claims")
	}
	if accepted != 0 {
		t.Errorf("%d wrong passwords were accepted", accepted)
	}
	t.Logf("of 20000 wrong passwords, %d produced valid padding and %d were accepted", paddingOnly, accepted)
	// And the right one still verifies.
	if ok, err := verifyOpenSSLEnc(record, pass); err != nil || !ok {
		t.Errorf("the right password stopped verifying: ok=%v err=%v", ok, err)
	}
}

// TestEnpassIsAPageMAC covers Enpass, and pins that the check is SQLCipher's
// page MAC rather than a decryption: nothing is decrypted, and the MAC key
// comes from the encryption key with its own salt rather than from the
// password.
func TestEnpassIsAPageMAC(t *testing.T) {
	record, pass := johnVector(t, "enpass $enpass$")
	if types := detectHashTypes(record); !containsString(types, "enpass") {
		t.Errorf("detectHashTypes did not offer enpass: %v", types)
	}
	if ok, err := verifyEnpass(record, pass); err != nil || !ok {
		t.Errorf("rejected the right password: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyEnpass(record, pass+"x"); bad {
		t.Error("accepted a wrong password")
	}
	r, err := parseEnpass(record)
	if err != nil {
		t.Fatal(err)
	}
	// Deriving the MAC key straight from the password, or from the encryption
	// key without the XORed salt, must NOT reproduce the page's MAC — those
	// are the two plausible simplifications, and both are wrong.
	salt := r.page[:sqlCipherSaltLen]
	key := pbkdf2.Key([]byte(pass), salt, r.iterations, 32, sha1.New)
	n := len(r.page)
	want := r.page[n-sqlCipherReserve+16 : n-sqlCipherReserve+16+sha1.Size]
	for name, hmacKey := range map[string][]byte{
		"from the password": pbkdf2.Key([]byte(pass), salt, 2, 32, sha1.New),
		"same salt":         pbkdf2.Key(key, salt, 2, 32, sha1.New),
		"the key itself":    key,
	} {
		mac := hmac.New(sha1.New, hmacKey)
		mac.Write(r.page[sqlCipherSaltLen : n-sqlCipherReserve])
		mac.Write(r.page[n-sqlCipherReserve : n-sqlCipherReserve+16])
		mac.Write([]byte{1, 0, 0, 0})
		if hmac.Equal(mac.Sum(nil), want) {
			t.Errorf("the MAC key derived %s also matches, so the derivation is not what it claims", name)
		}
	}
}

// TestDigestAuthentication covers the two digest mechanisms, and pins the one
// place they differ: HTTP Digest hashes the credentials to hex and uses that,
// while SASL's mixes the raw sixteen bytes with the nonces. Reading either as
// the other builds a plausible chain that never matches, so the test checks
// that swapping them fails.
func TestDigestAuthentication(t *testing.T) {
	for _, tc := range []struct{ typ, format string }{
		{"http-digest", "hdaa $response$"},
		{"digest-md5", "dmd5 $digest-md5$"},
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

	// The SASL vector is RFC 2831's own example, so the hex reading of its
	// first stage is worth ruling out explicitly.
	record, pass := johnVector(t, "dmd5 $digest-md5$")
	d, err := parseSASLDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	ha1Hex := md5HexOf(md5HexOf(d.user, d.realm, pass), d.nonce, d.cnonce)
	ha2 := md5HexOf("AUTHENTICATE", d.uri)
	if strings.EqualFold(md5HexOf(ha1Hex, d.nonce, d.nc, d.cnonce, d.qop, ha2), d.response) {
		t.Error("the hex reading of the first stage also matches, so the two mechanisms are not distinguished")
	}
}

// TestLastPassBothSpellings covers John's LastPass verifier and hashcat's,
// which share a derivation and differ in what they encrypt with it: hashcat
// encrypts one block of the address under an IV the record carries, John the
// whole address with PKCS#7 padding and no chaining.
func TestLastPassBothSpellings(t *testing.T) {
	record, pass := johnVector(t, "LastPass $lastpass$")
	if types := detectHashTypes(record); !containsString(types, "lastpass") {
		t.Errorf("detectHashTypes did not offer lastpass: %v", types)
	}
	if ok, err := verifyLastPass(record, pass); err != nil || !ok {
		t.Errorf("rejected the right password: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyLastPass(record, pass+"x"); bad {
		t.Error("accepted a wrong password")
	}
	// hashcat's spelling must keep working.
	const hc = "02eb97e869e0ddc7dc760fc633b4b54d:100100:pmix@trash-mail.com:9b071db7b8e265d4cadd3eb65ac0864a"
	if ok, err := verifyLastPass(hc, "hashcat"); err != nil || !ok {
		t.Errorf("hashcat's LastPass record regressed: ok=%v err=%v", ok, err)
	}
	// A record whose verifier is not a whole number of blocks is not one.
	if isJohnLastPass("$lastpass$a@b$500$YWJj") {
		t.Error("claimed a record whose verifier is not block-aligned")
	}
}

// TestTezosFundraiser covers the 2017 fundraiser wallet, and pins the twist
// that separates its derivation from ordinary BIP-39: the password goes into
// the SALT, after the literal "mnemonic" and the email address, rather than
// into the passphrase. Reading it the BIP-39 way produces a valid-looking
// wallet that is not this one.
func TestTezosFundraiser(t *testing.T) {
	record, pass := johnVector(t, "tezos $tezos$")
	if types := detectHashTypes(record); !containsString(types, "tezos") {
		t.Errorf("detectHashTypes did not offer tezos: %v", types)
	}
	if ok, err := verifyTezos(record, pass); err != nil || !ok {
		t.Errorf("rejected the right password: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyTezos(record, pass+"x"); bad {
		t.Error("accepted a wrong password")
	}
	r, err := parseTezos(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.keyHash) != 20 {
		t.Fatalf("key hash is %d bytes, want 20", len(r.keyHash))
	}
	// BIP-39's own reading — password as the passphrase, salt just
	// "mnemonic" — must not reproduce the wallet.
	seed := pbkdf2.Key([]byte(r.mnemonic), []byte("mnemonic"+pass), r.iterations, 64, sha512.New)
	pub := ed25519.NewKeyFromSeed(seed[:32]).Public().(ed25519.PublicKey)
	h, _ := blake2b.New(20, nil)
	h.Write(pub)
	if hmac.Equal(h.Sum(nil), r.keyHash) {
		t.Error("the plain BIP-39 reading also matches, so the email is not part of the salt")
	}
}

// TestBlackberryES10 covers BES10, and pins the shape of its work factor: the
// salt is mixed in once and then never again, so the ninety-nine rounds that
// follow hash nothing but the digest. Re-appending the salt each round — the
// obvious alternative reading — gives a different answer.
func TestBlackberryES10(t *testing.T) {
	record, pass := johnVector(t, "Blackberry-ES10 $bbes10$")
	if types := detectHashTypes(record); !containsString(types, "bbes10") {
		t.Errorf("detectHashTypes did not offer bbes10: %v", types)
	}
	if ok, err := verifyBlackberryES10(record, pass); err != nil || !ok {
		t.Errorf("rejected the right password: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifyBlackberryES10(record, pass+"x"); bad {
		t.Error("accepted a wrong password")
	}
	_, salt, want, err := blackberryFields(record)
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.New()
	h.Write([]byte(pass))
	h.Write([]byte(salt))
	d := h.Sum(nil)
	for i := 1; i < 100; i++ {
		h.Reset()
		h.Write(d)
		h.Write([]byte(salt)) // the reading this test rules out
		d = h.Sum(nil)
	}
	if hmac.Equal(d, want) {
		t.Error("re-salting each round also matches, so the rounds are not over the digest alone")
	}
}
