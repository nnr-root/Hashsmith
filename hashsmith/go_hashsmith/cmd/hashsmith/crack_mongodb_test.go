package main

import "testing"

// MongoDB SCRAM-SHA-1 vector (user "admin", passphrase "hashsmith"), Python-generated.
func TestMongoDBVector(t *testing.T) {
	h := "$mongodb-scram$0$admin$10000$ABEiM0RVZnc=$LQB5XFSjMV1evSGM1T44f917wkM="
	if ok, err := verifyMongoDB(h, "hashsmith"); err != nil || !ok {
		t.Errorf("MongoDB verify failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyMongoDB(h, "wrong"); ok {
		t.Error("MongoDB should reject the wrong passphrase")
	}
	if got := detectHashTypes(h); len(got) != 1 || got[0] != "mongodb" {
		t.Errorf("detectHashTypes(mongodb) = %v", got)
	}
}

func TestMongoDBSCRAMSHA256Vectors(t *testing.T) {
	const prefix = "$mongodb-scram$"
	vectors := []string{
		prefix + "1$hashcat$15000$Wfq3vMoqSEAwCyLsQF/hk5C5cB0aLtWS9FHeuw==$OUYBeh+/fypyyQaXfFg1Yvi8+qSXl+I1CHioOrdgtJw=",
		prefix + "2$hashcat$15000$Wfq3vMoqSEAwCyLsQF/hk5C5cB0aLtWS9FHeuw==$KSsV1BssuAHZMF4l6ziZ/5LGjA/qsCBcf++HroqpGNY=",
	}
	for _, target := range vectors {
		if ok, err := verifyMongoDB(target, "123hashcat"); err != nil || !ok {
			t.Errorf("MongoDB SCRAM-SHA-256 vector failed: ok=%v err=%v", ok, err)
		}
		if ok, _ := verifyMongoDB(target, "wrong"); ok {
			t.Error("MongoDB SCRAM-SHA-256 accepted the wrong password")
		}
		if got := detectHashTypes(target); len(got) != 1 || got[0] != "mongodb" {
			t.Errorf("detectHashTypes(MongoDB SHA-256) = %v", got)
		}
	}
}

func TestMongoDBSCRAMSHA256SASLprep(t *testing.T) {
	// RFC 4013 maps the soft hyphen away, so both candidates must derive the
	// same SHA-256 key. This record was generated from "IX".
	target := "$mongodb-scram$1$IX$4096$c2FsdHNhbHQ=$9Z0EoeLxUdxgC/gc+oQWy0nrlhFRRqlula1RZqLyxcU="
	for _, password := range []string{"IX", "I\u00adX"} {
		if ok, err := verifyMongoDB(target, password); err != nil || !ok {
			t.Errorf("SASLprep candidate %q failed: ok=%v err=%v", password, ok, err)
		}
	}
}
