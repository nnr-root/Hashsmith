package hashid

import (
	"reflect"
	"testing"
)

func always(e Evidence) func(Input) (Evidence, bool) {
	return func(Input) (Evidence, bool) { return e, true }
}

func never() func(Input) (Evidence, bool) {
	return func(Input) (Evidence, bool) { return "", false }
}

// The cascade's defining property: the first exclusive match wins outright and
// every later prototype is dropped from what crack sees.
func TestFirstExclusiveMatchWinsOutright(t *testing.T) {
	table := []Prototype{
		{Types: []string{"a"}, Display: "A", Tier: TierSignature, Exclusive: true,
			Match: never(), Rationale: "x"},
		{Types: []string{"b", "b2"}, Display: "B", Tier: TierSignature, Exclusive: true,
			Match: always("hit b"), Rationale: "x"},
		{Types: []string{"c"}, Display: "C", Tier: TierSignature, Exclusive: true,
			Match: always("hit c"), Rationale: "x"},
		{Types: []string{"d"}, Display: "D", Tier: TierShape, Exclusive: false,
			Match: always("hit d"), Rationale: "x"},
	}
	got := DetectTypes(table, Input{Normalized: "irrelevant"})
	want := []string{"b", "b2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DetectTypes = %v, want %v", got, want)
	}
}

// Identify still gets to see what was ruled out; crack never does.
func TestSuppressedMatchesAreReportedNotDropped(t *testing.T) {
	table := []Prototype{
		{Types: []string{"b"}, Display: "B", Tier: TierSignature, Exclusive: true,
			Match: always("hit b"), Rationale: "x"},
		{Types: []string{"c"}, Display: "C", Tier: TierShape, Exclusive: false,
			Match: always("hit c"), Rationale: "x"},
	}
	ms := Evaluate(table, Input{Normalized: "irrelevant"})
	if len(ms) != 2 {
		t.Fatalf("Evaluate returned %d matches, want 2", len(ms))
	}
	if ms[0].Suppressed {
		t.Error("winning match must not be marked suppressed")
	}
	if !ms[1].Suppressed {
		t.Error("match after an exclusive winner must be marked suppressed")
	}
}

// With no exclusive match, every non-exclusive match is returned in table
// order — this is today's trailing `switch len(t)` behaviour.
func TestNoExclusiveMatchReturnsEveryShapeMatch(t *testing.T) {
	table := []Prototype{
		{Types: []string{"a"}, Display: "A", Tier: TierSignature, Exclusive: true,
			Match: never(), Rationale: "x"},
		{Types: []string{"md5"}, Display: "MD5", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
		{Types: []string{"ntlm"}, Display: "NTLM", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
	}
	got := DetectTypes(table, Input{Normalized: "5f4dcc3b5aa765d61d8327deb882cf99"})
	want := []string{"md5", "ntlm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DetectTypes = %v, want %v", got, want)
	}
}

// Compute-based prototypes contribute their computed names at their own table
// position, which is what lets a late cascade branch like detectCompatSaltedTypes
// keep its precedence.
func TestComputePrototypeSuppliesTypesAtItsOwnPosition(t *testing.T) {
	table := []Prototype{
		{Types: []string{"early"}, Display: "Early", Tier: TierSignature, Exclusive: true,
			Match: never(), Rationale: "x"},
		{Display: "Computed", Tier: TierStructural, Exclusive: true,
			Compute:   func(Input) ([]string, bool) { return []string{"c1", "c2"}, true },
			Rationale: "x"},
		{Types: []string{"late"}, Display: "Late", Tier: TierSignature, Exclusive: true,
			Match: always("hit late"), Rationale: "x"},
	}
	got := DetectTypes(table, Input{Normalized: "x"})
	want := []string{"c1", "c2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DetectTypes = %v, want %v (the computed prototype precedes 'late')", got, want)
	}
}

func TestComputePrototypeThatDoesNotMatchIsSkipped(t *testing.T) {
	table := []Prototype{
		{Display: "Computed", Tier: TierStructural, Exclusive: true,
			Compute: func(Input) ([]string, bool) { return nil, false }, Rationale: "x"},
		{Types: []string{"late"}, Display: "Late", Tier: TierSignature, Exclusive: true,
			Match: always("hit late"), Rationale: "x"},
	}
	if got := DetectTypes(table, Input{Normalized: "x"}); !reflect.DeepEqual(got, []string{"late"}) {
		t.Fatalf("DetectTypes = %v, want [late]", got)
	}
}

func TestNoMatchReturnsNil(t *testing.T) {
	table := []Prototype{
		{Types: []string{"a"}, Display: "A", Tier: TierSignature, Exclusive: true,
			Match: never(), Rationale: "x"},
	}
	if got := DetectTypes(table, Input{Normalized: "zzz"}); got != nil {
		t.Fatalf("DetectTypes = %v, want nil", got)
	}
}

// Duplicate -t names across prototypes must not produce duplicate candidates
// for crack to try twice.
func TestDetectTypesDeduplicates(t *testing.T) {
	table := []Prototype{
		{Types: []string{"md5"}, Display: "MD5", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
		{Types: []string{"md5"}, Display: "MD5 again", Tier: TierShape,
			Match: always("32 hex"), Rationale: "x"},
	}
	got := DetectTypes(table, Input{Normalized: "x"})
	if !reflect.DeepEqual(got, []string{"md5"}) {
		t.Fatalf("DetectTypes = %v, want [md5]", got)
	}
}
