package smith

import "testing"

func TestSplitKeyspaceEvenDivision(t *testing.T) {
	got := splitKeyspace(100, 25)
	want := []chunkRange{{0, 25}, {25, 25}, {50, 25}, {75, 25}}
	if len(got) != len(want) {
		t.Fatalf("got %d chunks, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSplitKeyspacePartialFinalChunk(t *testing.T) {
	got := splitKeyspace(105, 25)
	want := []chunkRange{{0, 25}, {25, 25}, {50, 25}, {75, 25}, {100, 5}}
	if len(got) != len(want) {
		t.Fatalf("got %d chunks, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSplitKeyspaceSmallerThanOneChunk(t *testing.T) {
	got := splitKeyspace(10, 25)
	want := []chunkRange{{0, 10}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestSplitKeyspaceZeroTotal(t *testing.T) {
	if got := splitKeyspace(0, 25); len(got) != 0 {
		t.Fatalf("got %+v, want empty", got)
	}
}

func TestChunkQueuePullOrderAndExhaustion(t *testing.T) {
	q := newChunkQueue([]chunkRange{{0, 10}, {10, 10}, {20, 10}})
	c, ok := q.next()
	if !ok || c != (chunkRange{0, 10}) {
		t.Fatalf("first pull: got %+v ok=%v, want {0 10} true", c, ok)
	}
	c, ok = q.next()
	if !ok || c != (chunkRange{10, 10}) {
		t.Fatalf("second pull: got %+v ok=%v, want {10 10} true", c, ok)
	}
	c, ok = q.next()
	if !ok || c != (chunkRange{20, 10}) {
		t.Fatalf("third pull: got %+v ok=%v, want {20 10} true", c, ok)
	}
	if _, ok := q.next(); ok {
		t.Fatal("fourth pull should be empty, got ok=true")
	}
}

func TestChunkQueueRequeueGoesToFront(t *testing.T) {
	q := newChunkQueue([]chunkRange{{0, 10}, {10, 10}})
	first, _ := q.next() // {0 10}
	q.requeue(first)
	c, ok := q.next()
	if !ok || c != first {
		t.Fatalf("requeued chunk should come back first: got %+v ok=%v", c, ok)
	}
	c, ok = q.next()
	if !ok || c != (chunkRange{10, 10}) {
		t.Fatalf("got %+v ok=%v, want {10 10} true", c, ok)
	}
}
