package main

import "testing"

func TestHashcatVendorRecordVectors(t *testing.T) {
	cases := []struct {
		mode, typ, target string
	}{
		{"22301", "telegram-passcode", "$telegram$0*518c001aeb3b4ae96c6173be4cebe60a85f67b1e087b045935849e2f815b5e41*25184098058621950709328221838128"},
		{"31300", "ms-sntp", "$sntp-ms$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380"},
		{"33900", "citrix-pbkdf2", "5567243c55099b6b10a714a350db53beea8be6ac9c247fd40fea7e96d206a9f11fd1c45735556ac2004138640de206d0e1522607ab3c3f92816156d2d7845068e"},
		{"28400", "bcrypt-sha512", "$2a$12$KhivLhCuLhSyMBOxLxCyLu78x4z2X/EJdZNfS3Gy36fvRt56P2jbS"},
		{"30601", "passlib-bcrypt-sha256", "$bcrypt-sha256$v=2,t=2b,r=12$KSOjON/ciJR86a00N5q61.$AmWZucQuHk13FGkQWhgMeiFvBfm2GCy"},
		{"30700", "anope-sha256", "sha256:ab67666e1f91cd38c0ab5bee9c8d2132eca7460354477109a739d4e735b14131:47bcfd0d573653943231df07445da774e5d06465c897ce40578b120bde187e26"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			if got := canonicalHashType(tc.mode); got != tc.typ {
				t.Fatalf("mode alias = %q, want %q", got, tc.typ)
			}
			ok, err := verifyCandidate("hashcat", tc.target, tc.mode, "", "prefix")
			if err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			if bad, err := verifyCandidate("wrong-password", tc.target, tc.mode, "", "prefix"); err != nil || bad {
				t.Fatalf("wrong password: ok=%v err=%v", bad, err)
			}
		})
	}
}

func TestVendorRecordDetection(t *testing.T) {
	for target, want := range map[string]string{
		"$telegram$0*518c001aeb3b4ae96c6173be4cebe60a85f67b1e087b045935849e2f815b5e41*25184098058621950709328221838128":                              "telegram-passcode",
		"$sntp-ms$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380": "ms-sntp",
		"5567243c55099b6b10a714a350db53beea8be6ac9c247fd40fea7e96d206a9f11fd1c45735556ac2004138640de206d0e1522607ab3c3f92816156d2d7845068e":          "citrix-pbkdf2",
		"$bcrypt-sha256$v=2,t=2b,r=12$KSOjON/ciJR86a00N5q61.$AmWZucQuHk13FGkQWhgMeiFvBfm2GCy":                                                        "passlib-bcrypt-sha256",
		"sha256:ab67666e1f91cd38c0ab5bee9c8d2132eca7460354477109a739d4e735b14131:47bcfd0d573653943231df07445da774e5d06465c897ce40578b120bde187e26":   "anope-sha256",
	} {
		got := detectHashTypes(target)
		if len(got) != 1 || got[0] != want {
			t.Errorf("detection = %v, want [%s]", got, want)
		}
	}
}

func TestVendorJohnAliases(t *testing.T) {
	if ok, err := verifyCandidate("openwall123", telegramDesktopPublishedRecord, "john:telegram", "", "prefix"); err != nil || !ok {
		t.Fatalf("John telegram alias: ok=%v err=%v", ok, err)
	}
	passlib := "$bcrypt-sha256$v=2,t=2b,r=12$KSOjON/ciJR86a00N5q61.$AmWZucQuHk13FGkQWhgMeiFvBfm2GCy"
	if ok, err := verifyCandidate("hashcat", passlib, "john:bcrypt-sha256", "", "prefix"); err != nil || !ok {
		t.Fatalf("John bcrypt-sha256 dispatch: ok=%v err=%v", ok, err)
	}
}

func TestVendorRecordMalformedInputs(t *testing.T) {
	for typ, target := range map[string]string{
		"telegram-passcode":     "$telegram$0*bad*bad",
		"ms-sntp":               "$sntp-ms$bad$bad",
		"citrix-pbkdf2":         "5bad",
		"passlib-bcrypt-sha256": "$bcrypt-sha256$bad",
		"anope-sha256":          "sha256:bad:bad",
	} {
		if _, err := verifyCandidate("hashcat", target, typ, "", "prefix"); err == nil {
			t.Errorf("%s malformed record was accepted", typ)
		}
	}
}
