package smith

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"hashsmith-go/internal/bcryptlane"
)

// laneHasher verifies a batch of candidates against one target, several at a
// time, by advancing their independent computations together.
//
// Two implement it, for the same reason and by different means. bcrypt's core
// interleaves the Blowfish rounds of several candidates because a deliberately
// slow KDF has no other lever. descrypt's interleaves its DES chains because
// after the table work in descrypt_fast.go the loop is latency-bound on its
// own dependency chain rather than throughput-bound — round j cannot start
// addressing a load until round j-1 has resolved.
type laneHasher interface {
	// Run verifies len(pw) candidates, writing each verdict to out.
	//
	// An implementation must not retain pw or its elements beyond the call.
	// Callers reuse those byte slices between batches, so keeping one would
	// see it overwritten by the next group rather than hold the candidate it
	// was handed.
	Run(pw [][]byte, out []bool)
}

// newLaneHasher reports whether typ has an interleaved multi-candidate core for
// this target and, if so, returns a factory producing one hasher per worker
// and the number of candidates that core advances at a time.
//
// It returns a FACTORY rather than a shared hasher on purpose: a hasher owns
// reusable lane scratch so a batch allocates nothing, which makes it unsafe for
// concurrent use. One per worker, never one shared.
//
// Single target only, both types. Every lane in a batch runs in lockstep, so
// they must share one cost and one salt — true of one target, false of a dump.
// Dumps keep the scalar path.
func newLaneHasher(typ, targetHash, salt, saltMode string) (func() laneHasher, int, bool) {
	canon := canonicalHashType(typ)
	// LUKS's split types (luksModeSpecs) number in the dozens across
	// hash/cipher combinations, so they are handled once here via the same
	// map crack.go's own dispatch uses, rather than one switch case per
	// combination below. Only the SHA-256 ones can ever be accelerated —
	// newPBKDF2LUKSModeLaneHasher's own gate refuses the rest, falling back
	// to the scalar path exactly as every other case in this function does.
	if mode, ok := luksModeSpecs[canon]; ok {
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2LUKSModeLaneHasher(targetHash, mode) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2LUKSModeLaneHasher(targetHash, mode); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	}
	// cryptCascadeModes (VeraCrypt/TrueCrypt's split modes) is the sibling
	// map to luksModeSpecs above, handled the same way. Only its SHA-256
	// entries can ever be accelerated — every other KDF
	// (SHA-512/RIPEMD-160/Whirlpool/Streebog-512, and TrueCrypt, which
	// never offers SHA-256) falls back to the scalar path via
	// newPBKDF2VeraCryptSHA256LaneHasher's own gate.
	if mode, ok := cryptCascadeModes[canon]; ok {
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2VeraCryptSHA256LaneHasher(targetHash, mode) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2VeraCryptSHA256LaneHasher(targetHash, mode); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	}
	switch canon {
	case "bcrypt":
		if salt != "" {
			return nil, 0, false
		}
		if _, err := bcryptlane.NewHasher(targetHash); err != nil {
			return nil, 0, false
		}
		return func() laneHasher {
			h, err := bcryptlane.NewHasher(targetHash)
			if err != nil {
				return nil // caller falls back to the scalar verify
			}
			return h
		}, bcryptlane.Lanes, true
	case "descrypt":
		if salt != "" {
			return nil, 0, false
		}
		if newDescryptLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newDescryptLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, descryptLanes, true
	case "pbkdf2":
		if salt != "" {
			return nil, 0, false
		}
		// Runtime-gated, unlike bcrypt/descrypt above: both cores are a
		// straightforward regression on hardware with SHA extensions (the
		// design doc's §1 measured it directly), so neither must engage
		// there even when the target record and everything else is
		// eligible. Each hash checks its own eligibility function — both
		// currently reduce to the same AVX2-present/SHA-NI-absent check,
		// kept as separate names per hasSHA1AVX2/hasSHA256AVX2's own
		// per-hash naming rather than one shared hash-agnostic function.
		//
		// sha256 is tried first only because it is the more common
		// real-world variant (WPA2, most password managers, Django), then
		// sha1, then sha512; a record naming any one of the three always
		// falls through to its own branch regardless of this order, since
		// each newPBKDF2Sha*LaneHasher correctly refuses every other
		// algorithm's record (TestNewLaneHasherPBKDF2GateHandlesAllThreeAlgorithms).
		if pbkdf2Sha256AVX2Eligible() {
			if newPBKDF2Sha256LaneHasher(targetHash) != nil {
				return func() laneHasher {
					if h := newPBKDF2Sha256LaneHasher(targetHash); h != nil {
						return h
					}
					return nil
				}, pbkdf2Sha256Lanes, true
			}
		}
		if pbkdf2Sha1AVX2Eligible() {
			if newPBKDF2Sha1LaneHasher(targetHash) != nil {
				return func() laneHasher {
					if h := newPBKDF2Sha1LaneHasher(targetHash); h != nil {
						return h
					}
					return nil
				}, pbkdf2Sha1Lanes, true
			}
		}
		if pbkdf2Sha512AVX2Eligible() {
			if newPBKDF2Sha512LaneHasher(targetHash) != nil {
				return func() laneHasher {
					if h := newPBKDF2Sha512LaneHasher(targetHash); h != nil {
						return h
					}
					return nil
				}, pbkdf2Sha512Lanes, true
			}
		}
		return nil, 0, false
	case "1password8":
		// Format-specific reuse of the same SHA-256 core and eligibility
		// gate as the generic "pbkdf2" case above — see
		// pbkdf2Onepassword8LaneHasher's own comment for why this format
		// specifically was the first one wired this way. salt != ""
		// is not checked here: 1Password 8's own salt lives in the target
		// record's own field, never in the generic -s/-S mechanism, and
		// nothing about this format accepts an external salt argument at
		// all — unlike bcrypt/descrypt/pbkdf2 above, which are also usable
		// as bare, salt-less raw digests via -s/-S, this crack.go dispatch
		// entry for "1password8" never threads a salt argument through, so
		// there is nothing to reject.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2Onepassword8LaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2Onepassword8LaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "dogechain":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2DogechainLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2DogechainLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "cisco8":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2Cisco8LaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2Cisco8LaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "padlock":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2PadlockLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2PadlockLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "ethereum":
		// Same gate and reasoning as the "1password8" case above. A scrypt
		// ("s") record falls back to the scalar path on its own, since
		// newPBKDF2EthereumLaneHasher refuses anything that is not the
		// PBKDF2 ("p") variant.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2EthereumLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2EthereumLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "scram":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2ScramLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2ScramLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "lastpass-lp":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2LastpassLPLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2LastpassLPLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "lastpass-cli":
		// Same gate and reasoning as the "1password8" case above. A record
		// whose iterations field is 1 (a different, non-PBKDF2 function —
		// see verifyLastPassCLI's own comment) falls back to the scalar
		// path on its own, since newPBKDF2LastpassCLILaneHasher refuses it.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2LastpassCLILaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2LastpassCLILaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "django":
		// Same gate and reasoning as the "1password8" case above. A
		// pbkdf2_sha1 (or any other Django algorithm) record falls back to
		// the scalar path on its own, since newPBKDF2DjangoLaneHasher
		// refuses anything that is not pbkdf2_sha256.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2DjangoLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2DjangoLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "aix":
		// Same gate and reasoning as the "1password8" case above. A
		// {smd5}/{ssha1}/{ssha512} record falls back to the scalar path on
		// its own, since newPBKDF2AIXLaneHasher refuses anything that is
		// not {ssha256}.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2AIXLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2AIXLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "android-fde-samsung":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2AndroidSamsungFDELaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2AndroidSamsungFDELaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "passlib-pbkdf2":
		// Same gate and reasoning as the "1password8" case above. A
		// sha1/sha512 record falls back to the scalar path on its own,
		// since newPBKDF2PasslibLaneHasher refuses anything that is not
		// $pbkdf2-sha256$.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2PasslibLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2PasslibLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "werkzeug":
		// Same gate and reasoning as the "1password8" case above. Any other
		// Werkzeug method falls back to the scalar path on its own, since
		// newPBKDF2WerkzeugLaneHasher refuses anything that is not
		// "pbkdf2:sha256:...".
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2WerkzeugLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2WerkzeugLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "aspnet-identity":
		// Same gate and reasoning as the "1password8" case above. A v2
		// record, a v3 record with a non-SHA-256 PRF, or a v3 SHA-256
		// record with a subkey longer than 32 bytes all fall back to the
		// scalar path on their own, since newPBKDF2ASPNetIdentityLaneHasher
		// refuses them.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2ASPNetIdentityLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2ASPNetIdentityLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "azuresync":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2AzureSyncLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2AzureSyncLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "mozilla-nss":
		// Same gate and reasoning as the "1password8" case above. A key3.db
		// record falls back to the scalar path on its own, since
		// newPBKDF2MozillaLaneHasher refuses anything that is not key4.db's
		// AES form.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2MozillaLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2MozillaLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "stellar-wallet":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2StellarWalletLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2StellarWalletLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "apple-secure-notes":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2AppleSecureNotesLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2AppleSecureNotesLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "citrix-pbkdf2":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2CitrixPBKDF2LaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2CitrixPBKDF2LaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "azuread":
		// Same gate and reasoning as the "1password8" case above.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2AzureADLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2AzureADLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "lastpass":
		// Same gate and reasoning as the "1password8" case above. Covers
		// both record spellings verifyLastPass itself dispatches between —
		// see pbkdf2LastPassRecordsLaneHasher's own comment for why this
		// file is not named after the type the way every other case here
		// is.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2LastPassRecordsLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2LastPassRecordsLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "luks":
		// Same gate and reasoning as the "1password8" case above. Any hash
		// spec/key size the SHA-256/≤32-byte-key gate does not cover falls
		// back to the scalar path on its own, since
		// newPBKDF2LUKSLaneHasher refuses it.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2LUKSLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2LUKSLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "virtualbox-aes128", "virtualbox-aes256":
		// Same gate and reasoning as the "1password8" case above. Only
		// AES-128-XTS's 32-byte first-stage key fits a single PBKDF2
		// block; AES-256-XTS's 64-byte key falls back to the scalar path
		// on its own, since newPBKDF2VirtualBoxLaneHasher refuses anything
		// but keyWords==8.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2VirtualBoxLaneHasher(targetHash, canon) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2VirtualBoxLaneHasher(targetHash, canon); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "ansible":
		// Same gate and reasoning as the "1password8" case above — the
		// first case wired through the multi-block primitive
		// (pbkdf2HMACSHA256DeriveBatchN) rather than the single-block one,
		// since Ansible's derived key is 80 bytes.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2AnsibleLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2AnsibleLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "ldap-pbkdf2":
		// Same gate and reasoning as the "ansible" case above — another
		// multi-block-primitive user (256-byte digest, eight blocks).
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2RedHat389LaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2RedHat389LaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "encdatavault":
		// Same gate and reasoning as the "ansible" case above — another
		// multi-block-primitive user (up to 128 bytes with a keychain, four
		// blocks). The MD5 form falls back to the scalar path on its own,
		// since newPBKDF2EncDataVaultLaneHasher refuses anything but the
		// PBKDF2 form.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2EncDataVaultLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2EncDataVaultLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "bitwarden":
		// Same gate and reasoning as the "1password8" case above. Covers
		// both record shapes verifyBitwarden itself dispatches between —
		// see pbkdf2BitwardenLaneHasher's own comment for why its second
		// round needs the per-lane-salt primitive.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2BitwardenLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2BitwardenLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	case "metamask":
		// Same gate and reasoning as the "1password8" case above. The short
		// variant ("metamask-short", a distinct type name never reaching
		// this case) uses a non-standard CTR construction the batch
		// primitive does not accelerate.
		if !pbkdf2Sha256AVX2Eligible() {
			return nil, 0, false
		}
		if newPBKDF2MetaMaskLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newPBKDF2MetaMaskLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, pbkdf2Sha256Lanes, true
	}
	return nil, 0, false
}

// runLayoutLanes is runLayout's bcrypt-laned twin: identical bounds
// arithmetic, chunk striping, cur[] watermark tracking and watermark-updater
// goroutine, so --session resume, --skip/--limit slicing and the progress
// counter behave identically to every other runner. The only difference is
// the per-chunk inner loop, which buffers candidates and flushes them through
// an interleaved multi-candidate bcrypt core (bcryptlane.Hasher) instead of
// calling a scalar verify closure once per candidate.
func runLayoutLanes(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	newHasher func() laneHasher, lanes int) (string, error) {

	if resumeFrom < 0 {
		resumeFrom = 0
	}
	// bound is the exclusive end of this run's slice of the layout: the whole
	// keyspace, or resumeFrom+limit when a positive limit narrows it — whichever
	// is smaller. satAdd guards resumeFrom+limit overflowing int64.
	bound := l.total
	if limit > 0 {
		if b := satAdd(resumeFrom, limit); b < bound {
			bound = b
		}
	}
	if bound == 0 || resumeFrom >= bound {
		return "", nil
	}
	if workers < 1 {
		workers = 1
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	firstChunk := resumeFrom / keyspaceChunk
	nextChunk := firstChunk
	resultCh := make(chan string, 1)

	// cur[w] is the chunk worker w is currently processing (MaxInt64 once done),
	// so min(cur)*chunk is the safe restore watermark.
	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			// Each worker owns one Hasher for the life of the run: it carries
			// reusable lane scratch and must never be shared (see lanes.go).
			var lh laneHasher
			for {
				c := atomic.AddInt64(&nextChunk, 1) - 1
				start := c * keyspaceChunk
				if start >= bound {
					atomic.StoreInt64(&cur[wID], math.MaxInt64)
					return
				}
				atomic.StoreInt64(&cur[wID], c)
				end := start + keyspaceChunk
				if end > bound {
					end = bound
				}
				from := start
				if from < resumeFrom {
					from = resumeFrom
				}
				// Count attempts in a worker-local accumulator and flush per
				// chunk, so the shared counter is not hammered once per candidate
				// (that cache-line contention otherwise caps multi-core scaling).
				if lh == nil {
					lh = newHasher()
				}
				if lh == nil { // unparseable target; the dispatcher should have caught it
					return
				}

				var local int64
				iter := 0
				cands := make([]string, 0, lanes)
				pwBuf := make([][]byte, lanes)
				outBuf := make([]bool, lanes)
				// One reusable byte buffer per lane. `pw[i] = []byte(c)`
				// allocated once per CANDIDATE, which after the interleaving
				// made descrypt's hashing about twice as fast was a
				// measurable share of the run rather than a rounding error.
				// The laneHasher contract above is what makes reuse safe.
				pwScratch := make([][]byte, lanes)
				for i := range pwScratch {
					pwScratch[i] = make([]byte, 0, 64)
				}

				// flush tests everything buffered, reporting the FIRST hit in
				// buffer order so a laned run reports the same candidate an
				// unlaned run would. Returns true when the run should stop.
				flush := func() bool {
					if len(cands) == 0 {
						return false
					}
					pw := pwBuf[:len(cands)]
					for i, c := range cands {
						pw[i] = append(pwScratch[i][:0], c...)
						pwScratch[i] = pw[i]
					}
					lh.Run(pw, outBuf[:len(cands)])
					local += int64(len(cands))
					for i, ok := range outBuf[:len(cands)] {
						if ok {
							hit := cands[i]
							atomic.AddInt64(atomicAttempts, local)
							select {
							case resultCh <- hit:
							default:
							}
							cancel()
							atomic.StoreInt64(&cur[wID], math.MaxInt64)
							return true
						}
					}
					cands = cands[:0]
					return false
				}

				for idx := from; idx < end; idx++ {
					if iter++; iter >= ctxCheckEvery {
						iter = 0
						select {
						case <-innerCtx.Done():
							// Cancelled mid-chunk: test what is buffered before
							// leaving, or those candidates are silently skipped.
							// A hit here already accumulates atomicAttempts inside
							// flush() itself, so return immediately instead of
							// falling through to the unconditional add below, which
							// would double-count attempts. atomicAttempts is not
							// progress-only: doCrack's feasibility probe divides it
							// by elapsed time for the ETA/refuse-proceed verdict,
							// under a timeout context where cancellation is routine.
							if flush() {
								return
							}
							atomic.AddInt64(atomicAttempts, local)
							return
						default:
						}
					}
					cands = append(cands, l.candidate(idx))
					if len(cands) == lanes {
						if flush() {
							return
						}
					}
				}
				// End of chunk: keyspaceChunk (4096) is a multiple of
				// the lane width, so an interior chunk's tail is always
				// empty and this flush is a no-op there. It is load-bearing for
				// the run's FINAL chunk (whose end is bound, not lane-aligned)
				// and for a resume-start chunk whose from is not lane-aligned
				// either. Dropping it would silently skip up to Lanes-1
				// candidates in those chunks. See
				// TestLanesFlushFinalChunkTail and TestLanesRespectSessionWatermark.
				if flush() {
					return
				}
				atomic.AddInt64(atomicAttempts, local)
			}
		}(w)
	}

	// watermark updater
	if watermark != nil {
		atomic.StoreInt64(watermark, resumeFrom)
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-innerCtx.Done():
					return
				case <-t.C:
					updateWatermark(cur, watermark, bound)
				}
			}
		}()
	}

	wg.Wait()
	if watermark != nil {
		updateWatermark(cur, watermark, bound)
	}
	select {
	case pw := <-resultCh:
		return pw, nil
	default:
		return "", nil
	}
}
