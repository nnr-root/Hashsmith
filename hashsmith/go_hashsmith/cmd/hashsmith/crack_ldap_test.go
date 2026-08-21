package main

import "testing"

// LDAP salted-digest vectors (passphrase "hashsmith"), Python-generated.
func TestLDAPVectors(t *testing.T) {
	lines := []string{
		"{SSHA}QZdDbujQQyJjuC5FgKJZDvWEEBxzNGx0",
		"{SMD5}8XX/GhGj2YU+bCV3oANYZnM0bHQ=",
		"{SSHA256}v899PtNSobzUUSUrJ2GzKL4UcX5TglI5TTExOzl4Bz5zNGx0",
		"{SSHA384}dMI2f7UnK1V4vzNmHwiwXQSo9M7P+E/uXloACOKdJnrtNXI9KAhYEChC841TBJHmczRsdA==",
		"{SSHA512}jxx7Zc2ON06RjKvCHpyjQ1k/okyfsU+EPKfKFvGVHiXaZVuCQrt8n51mtVmAMsueKXh4cXEVzNb82t+VJUfVvXM0bHQ=",
		"{MD5}7RpMtgLUUJCZkfoO5rrQmQ==",
		"{SHA}RQUXZOCQC4oaCFQepq7KUF1s0/A=",
		"{SHA256}O3h3L2ZjwOCBzF5fg/BZpKhSQmqKiZAg1BiH72R/IwM=",
		"{SHA384}PbLcdf3sjK2lCby7GbtzomYW9cpjeUSiBH8ih9BY63GrMfBGR/JowIkOMeZrWZha",
		"{SHA512}BThRci5BCaR8q3hzbTuYPOHwTK60nlvcKkuHItfcEIrrYd91XQ8HmzX3nzDG8MV33PlHSNoTfRt1avHzB7Dlfw==",
	}
	for i, line := range lines {
		if ok, err := verifyLDAP(line, "hashsmith"); err != nil || !ok {
			t.Errorf("LDAP vector %d verify failed: ok=%v err=%v", i, ok, err)
		}
		if ok, _ := verifyLDAP(line, "wrong"); ok {
			t.Errorf("LDAP vector %d should reject the wrong passphrase", i)
		}
		if got := detectHashTypes(line); len(got) != 1 || got[0] != "ldap" {
			t.Errorf("detectHashTypes(vector %d) = %v, want [ldap]", i, got)
		}
	}
}

func TestLDAPPracticalVariants(t *testing.T) {
	for _, target := range []string{
		"{md5}7RpMtgLUUJCZkfoO5rrQmQ", // lowercase tag, unpadded Base64
		"{sha}RQUXZOCQC4oaCFQepq7KUF1s0/A",
	} {
		if ok, err := verifyLDAP(target, "hashsmith"); err != nil || !ok {
			t.Errorf("verifyLDAP(%q) = %v, %v", target, ok, err)
		}
		if got := detectHashTypes(target); len(got) != 1 || got[0] != "ldap" {
			t.Errorf("detectHashTypes(%q) = %v", target, got)
		}
	}
}

func TestLDAPCrypt(t *testing.T) {
	target := "{CRYPT}$1$abcdefgh$t4yIjTehTKVzyLza7AROx."
	if ok, err := verifyLDAP(target, "hashsmith"); err != nil || !ok {
		t.Fatalf("verifyLDAP({CRYPT}) = %v, %v", ok, err)
	}
	if ok, _ := verifyLDAP(target, "wrong"); ok {
		t.Fatal("{CRYPT} accepted the wrong password")
	}
	if got := detectHashTypes(target); len(got) != 1 || got[0] != "ldap" {
		t.Fatalf("detectHashTypes({CRYPT}) = %v, want [ldap]", got)
	}
}
