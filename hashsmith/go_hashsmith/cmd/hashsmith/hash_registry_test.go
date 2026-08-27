package main

import "testing"

func TestUniversalHashRegistryIntegrity(t *testing.T) {
	registry := universalHashRegistry
	if registry == nil {
		t.Fatal("universal registry is nil")
	}
	if len(registry.formats) == 0 || len(registry.aliases) == 0 || len(registry.vectors) == 0 {
		t.Fatalf("incomplete registry: formats=%d aliases=%d vectors=%d",
			len(registry.formats), len(registry.aliases), len(registry.vectors))
	}

	seenOrder := make(map[string]bool, len(registry.order))
	for _, name := range registry.order {
		if seenOrder[name] {
			t.Errorf("format %q occurs twice in registry order", name)
		}
		seenOrder[name] = true
		format := registry.formats[name]
		if format == nil || format.name != name {
			t.Errorf("format index mismatch for %q", name)
		}
		if got := canonicalHashType(name); got != name {
			t.Errorf("canonical format %q resolves to %q", name, got)
		}
		if format.description == "" || format.group == "" {
			t.Errorf("format %q lacks catalogue metadata", name)
		}
	}
	if len(seenOrder) != len(registry.formats) {
		t.Errorf("order contains %d formats; index contains %d", len(seenOrder), len(registry.formats))
	}

	for alias, canonical := range registry.aliases {
		format := registry.formats[canonical]
		if format == nil {
			t.Errorf("alias %q points to absent format %q", alias, canonical)
			continue
		}
		if got := canonicalHashType(alias); got != canonical {
			t.Errorf("alias %q resolves to %q, want %q", alias, got, canonical)
		}
		found := false
		for _, backref := range format.aliases {
			if backref == alias {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("format %q lacks alias back-reference %q", canonical, alias)
		}
	}

	vectorTotal := 0
	for name, format := range registry.formats {
		vectorTotal += len(format.vectors)
		for _, vector := range format.vectors {
			if vector.typ != name {
				t.Errorf("vector indexed under %q names %q", name, vector.typ)
			}
		}
	}
	if vectorTotal != len(registry.vectors) {
		t.Errorf("format vectors total %d; registry has %d", vectorTotal, len(registry.vectors))
	}
}

func TestUniversalHashRegistryMetrics(t *testing.T) {
	registry := universalHashRegistry
	provenance := map[vectorSource]int{}
	for _, vector := range registry.vectors {
		provenance[vector.source]++
	}
	if registry.numericAliases() < 400 {
		t.Fatalf("only %d numeric compatibility identifiers", registry.numericAliases())
	}
	if got := len(registry.formats) + len(registry.aliases); got <= len(registry.formats) {
		t.Fatalf("accepted identifier total %d did not include aliases", got)
	}
	t.Logf("universal formats=%d accepted identifiers=%d numeric aliases=%d vectors=%d",
		len(registry.formats), len(registry.formats)+len(registry.aliases),
		registry.numericAliases(), len(registry.vectors))
	t.Logf("vector provenance: published=%d cross-checked=%d regression=%d",
		provenance[srcPublished], provenance[srcCrosschecked], provenance[srcRegression])
}
