package main

import "testing"

func TestPasslibPBKDF2Vectors(t *testing.T) {
	vectors := []struct {
		password, target string
	}{
		{"password", "$pbkdf2-sha256$6400$.6UI/S.nXIk8jcbdHx3Fhg$98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44"},
		{"hashsmith", "$pbkdf2-sha1$1000$c2FsdHk$TX4yNQQZVOCfG5gIIedaYDjifAE"},
		{"hashsmith", "$pbkdf2-sha256$1000$c2FsdHk$99l/T.rA4M56GE61YX3FCRYy6M2JM73eGkSVqbwggDY"},
		{"hashsmith", "$pbkdf2-sha512$1000$c2FsdHk$46H1UX84CF/CtUdeJF51PxwS9GOLR2Gb0SCwA8og0Qvf0pRq7yqrNkP6oUwFADk3UU90M7IUXgwXJz2oFBfQug"},
	}
	for _, tc := range vectors {
		if ok, err := verifyPasslibPBKDF2(tc.target, tc.password); err != nil || !ok {
			t.Errorf("Passlib vector failed: ok=%v err=%v", ok, err)
		}
		if ok, _ := verifyPasslibPBKDF2(tc.target, "wrong"); ok {
			t.Error("Passlib accepted the wrong password")
		}
		if got := detectHashTypes(tc.target); len(got) != 1 || got[0] != "passlib-pbkdf2" {
			t.Errorf("detectHashTypes(Passlib) = %v", got)
		}
	}
}

func TestWerkzeugVectors(t *testing.T) {
	vectors := []string{
		"pbkdf2:sha256:1000$salty$f7d97f4feac0e0ce7a184eb5617dc5091632e8cd8933bdde1a4495a9bc208036",
		"scrypt:1024:8:1$salty$3efd3817c49ce62e9d99ac0351928b3dd77f8d05c619836a4e26691dd3990eeaf5de217ddc2d0a9fbab75f0a37b9c7989466484a2796d36b109ea3e644c3da5f",
	}
	for _, target := range vectors {
		if ok, err := verifyWerkzeug(target, "hashsmith"); err != nil || !ok {
			t.Errorf("Werkzeug vector failed: ok=%v err=%v", ok, err)
		}
		if ok, _ := verifyWerkzeug(target, "wrong"); ok {
			t.Error("Werkzeug accepted the wrong password")
		}
		if got := detectHashTypes(target); len(got) != 1 || got[0] != "werkzeug" {
			t.Errorf("detectHashTypes(Werkzeug) = %v", got)
		}
	}
}

func TestASPNetIdentityVectors(t *testing.T) {
	vectors := []struct {
		target  string
		version int
	}{
		{"AAABAgMEBQYHCAkKCwwNDg+Ky5554+IoJfqS5hXxjS0w0jPNKExk4LZOmo818o/5sg==", 2},
		{"AQAAAAEAAC7gAAAAEBAREhMUFRYXGBkaGxwdHh9USoGEDJIxFUc0beM8B4/IEdus8IdgkrsjqG8Dcfo45w==", 3},
		{"AQAAAAIAAYagAAAAECAhIiMkJSYnKCkqKywtLi/ybYxC0Bq/+AGe4PMPgrfdplwVZMI04qy1RcSic3+RGg==", 3},
	}
	for _, tc := range vectors {
		parsed, err := parseASPNetIdentity(tc.target)
		if err != nil || parsed.version != tc.version {
			t.Errorf("parse ASP.NET Identity: version=%v err=%v", parsed, err)
			continue
		}
		if ok, err := verifyASPNetIdentity(tc.target, "hashsmith"); err != nil || !ok {
			t.Errorf("ASP.NET Identity vector failed: ok=%v err=%v", ok, err)
		}
		if ok, _ := verifyASPNetIdentity(tc.target, "wrong"); ok {
			t.Error("ASP.NET Identity accepted the wrong password")
		}
		if got := detectHashTypes(tc.target); len(got) != 1 || got[0] != "aspnet-identity" {
			t.Errorf("detectHashTypes(ASP.NET Identity) = %v", got)
		}
	}
}

func TestCiscoType4Vector(t *testing.T) {
	const target = "2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI"
	if ok, err := verifyCiscoType4(target, "hashcat"); err != nil || !ok {
		t.Fatalf("Cisco type 4 vector failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyCiscoType4(target, "wrong"); ok {
		t.Fatal("Cisco type 4 accepted the wrong password")
	}
	if got := detectHashTypes("$4$" + target); len(got) != 1 || got[0] != "cisco4" {
		t.Fatalf("detectHashTypes(Cisco type 4) = %v", got)
	}
}

func TestExpandedGenericPBKDF2Vectors(t *testing.T) {
	for _, target := range []string{
		"sha224:1000:c2FsdHk=:13SPE+vQqIMlOFur8NAr9I5IlADF98iOgIL7NQ==",
		"sha384:1000:c2FsdHk=:+8SYHIdkk91h80WjIrtRQDoLnA08MxVC0AvPdfeiBMKAemMqsXYagbSSTa93WEyn",
	} {
		if ok, err := verifyPBKDF2(target, "hashsmith"); err != nil || !ok {
			t.Errorf("expanded generic PBKDF2 failed: ok=%v err=%v", ok, err)
		}
		if !isGenericPBKDF2(target) {
			t.Error("expanded generic PBKDF2 was not detected")
		}
	}
}

func TestFrameworkKDFCostLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		verify func(string, string) (bool, error)
		target string
	}{
		{"Passlib", verifyPasslibPBKDF2, "$pbkdf2-sha256$100000001$c2FsdHk$99l/T.rA4M56GE61YX3FCRYy6M2JM73eGkSVqbwggDY"},
		{"Werkzeug PBKDF2", verifyWerkzeug, "pbkdf2:sha256:100000001$salty$f7d97f4feac0e0ce7a184eb5617dc5091632e8cd8933bdde1a4495a9bc208036"},
		{"Werkzeug scrypt", verifyWerkzeug, "scrypt:1073741824:8:1$salty$3efd3817c49ce62e9d99ac0351928b3dd77f8d05c619836a4e26691dd3990eeaf5de217ddc2d0a9fbab75f0a37b9c7989466484a2796d36b109ea3e644c3da5f"},
	} {
		if _, err := tc.verify(tc.target, "hashsmith"); err == nil {
			t.Errorf("%s accepted unsafe cost parameters", tc.name)
		}
	}
}
