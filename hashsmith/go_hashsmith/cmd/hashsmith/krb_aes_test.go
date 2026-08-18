package main

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// AES-CTS Kerberos primitives + the four AES etype-17/18 example vectors.
func TestKrb5AES(t *testing.T) {
	// RFC 3961 / 3962 primitive vectors.
	if got := hex.EncodeToString(nfold([]byte("012345"), 8)); got != "be072631276b1955" {
		t.Errorf("nfold: %s", got)
	}
	tkey := pbkdf2.Key([]byte("password"), []byte("ATHENA.MIT.EDUraeburn"), 1, 32, sha1.New)
	if got := hex.EncodeToString(aesDK(tkey, []byte("kerberos"), 32)); got != "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161" {
		t.Errorf("string2key aes256: %s", got)
	}
	// RFC 3962 AES-CTS vector.
	ct, _ := hex.DecodeString("c6353568f2bf8cb4d8a580362da7ff7f97")
	if got := string(aesCTSDecrypt([]byte("chicken teriyaki"), ct)); got != "I would like the " {
		t.Errorf("CTS: %q", got)
	}

	// The four hashcat AES Kerberos example vectors (password "hashcat").
	cases := []string{
		"$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e",
		"$krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0",
		"$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333",
		"$krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770",
	}
	for _, h := range cases {
		if ok, err := verifyKrb5(h, "hashcat"); err != nil || !ok {
			t.Errorf("AES Kerberos verify failed for %.24s…: ok=%v err=%v", h, ok, err)
		}
		if ok, _ := verifyKrb5(h, "wrong"); ok {
			t.Errorf("AES Kerberos should reject wrong pass for %.24s…", h)
		}
	}
}
