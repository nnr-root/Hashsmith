package main

import "hashsmith-go/internal/bcryptlane"

// newLaneHasher reports whether typ has an interleaved multi-candidate core for
// this target and, if so, returns a factory producing one hasher per worker.
//
// It returns a FACTORY rather than a shared *Hasher on purpose: the hasher owns
// reusable lane scratch so a batch allocates nothing, which makes it unsafe for
// concurrent use. One per worker, never one shared.
//
// bcrypt only, single target only. Every lane in a batch executes the same
// iteration count in lockstep, so they must share one cost and one salt - which
// is true of one target and false of a dump. Dumps keep the scalar path.
func newLaneHasher(typ, targetHash, salt, saltMode string) (func() *bcryptlane.Hasher, bool) {
	if canonicalHashType(typ) != "bcrypt" || salt != "" {
		return nil, false
	}
	if _, err := bcryptlane.NewHasher(targetHash); err != nil {
		return nil, false
	}
	return func() *bcryptlane.Hasher {
		h, err := bcryptlane.NewHasher(targetHash)
		if err != nil {
			return nil // caller falls back to the scalar verify
		}
		return h
	}, true
}
