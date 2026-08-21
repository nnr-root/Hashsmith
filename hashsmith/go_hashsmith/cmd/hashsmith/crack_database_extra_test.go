package main

import "testing"

func TestMySQL8CachingSHA2Vector(t *testing.T) {
	const target = "$mysql$A$005*06437A150142644D74187A6A2F0D7971094F2575*48667A67485366745A304F6A487A73704250663465337A7530325157687A51364A384D737554424939702E"
	if ok, err := verifyMySQL8(target, "password"); err != nil || !ok {
		t.Fatalf("MySQL 8 vector failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyMySQL8(target, "wrong"); ok {
		t.Fatal("MySQL 8 accepted the wrong password")
	}
	if got := detectHashTypes(target); len(got) != 1 || got[0] != "mysql8" {
		t.Fatalf("detectHashTypes(MySQL 8) = %v", got)
	}
}

func TestMySQL8RoundTrip(t *testing.T) {
	target, err := encodeMySQL8("hashsmith", []byte("0123456789abcdefghij"), 5)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := verifyMySQL8(target, "hashsmith"); err != nil || !ok {
		t.Fatalf("MySQL 8 round trip failed: ok=%v err=%v", ok, err)
	}
	if _, err := parseMySQL8("$mysql$A$000*00*00"); err == nil {
		t.Fatal("MySQL 8 parser accepted malformed fields")
	}
}
