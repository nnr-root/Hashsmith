package smith

// Working-memory budgeting for memory-hard formats.
//
// Most formats here cost a few kilobytes per candidate, so the worker count can
// simply be the CPU count. Memory-hard KDFs break that assumption badly: a LUKS2
// header asking for Argon2id at m=1048576 wants a gibibyte per candidate, and
// ten workers on a ten-core machine would ask for ten gibibytes at once. The
// machine does not refuse — it swaps, and a format that should take a second per
// guess takes a minute.
//
// So the worker count is capped by memory as well as by cores, using the cost
// the record itself declares. An explicit -p always wins: the operator who asks
// for twenty workers gets twenty.

import (
	"errors"
	"strconv"
	"strings"
)

// memoryBudgetFraction is the share of system memory a run may use for
// candidate working sets. The rest is left for the wordlist, the potfile, the
// OS and everything else; going higher buys little because the formats this
// applies to are compute-bound once they fit.
const memoryBudgetFraction = 0.6

// memoryBudgetFallback is used when system memory cannot be determined. It is
// deliberately modest: capping too low costs some throughput, capping too high
// costs the machine.
const memoryBudgetFallback = 2 << 30 // 2 GiB

// candidateMemoryBytes reports the working memory one verification of this
// target needs, or 0 when it is small enough not to matter.
//
// It keys on the RECORD rather than on the type name, because the cap has to
// hold whether or not the operator passed -t: an auto-detected LUKS2 header
// costs exactly as much as a declared one.
func candidateMemoryBytes(typ, target string) uint64 {
	switch {
	case typ == "" || typ == "luks2":
		if p, err := parseLUKS2Params(target); err == nil {
			return p.memoryBytes()
		}
	}
	if (typ == "" || typ == "bestcrypt-v4") && strings.HasPrefix(strings.TrimSpace(target), bestCryptV4Prefix) {
		return bestCryptV4Memory
	}
	return 0
}

// workerCapForMemory returns the number of workers that fit the budget, and a
// note to show the operator when it is lower than what they would otherwise get.
func workerCapForMemory(requested int, typ, target string) (int, string) {
	per := candidateMemoryBytes(typ, target)
	if per == 0 {
		return requested, ""
	}
	budget := uint64(float64(systemMemoryBytes()) * memoryBudgetFraction)
	if budget == 0 {
		budget = memoryBudgetFallback
	}
	fit := int(budget / per)
	if fit < 1 {
		fit = 1
	}
	if fit >= requested {
		return requested, ""
	}
	return fit, "workers capped at " + strconv.Itoa(fit) + " of " + strconv.Itoa(requested) +
		": this format needs " + humanBytes(per) + " per candidate (override with -p)"
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'g', 3, 64) + " GiB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'g', 3, 64) + " MiB"
	default:
		return strconv.FormatUint(n, 10) + " B"
	}
}

// parseKDFOptions reads an "m=...,t=...,p=..." field.
func parseKDFOptions(s string) (memKiB, time, lanes uint32, err error) {
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return 0, 0, 0, errors.New("malformed KDF option " + part)
		}
		n, convErr := strconv.ParseUint(v, 10, 32)
		if convErr != nil {
			return 0, 0, 0, errors.New("malformed KDF option value " + part)
		}
		switch k {
		case "m":
			memKiB = uint32(n)
		case "t":
			time = uint32(n)
		case "p":
			lanes = uint32(n)
		default:
			return 0, 0, 0, errors.New("unknown KDF option " + k)
		}
	}
	if memKiB == 0 || time == 0 || lanes == 0 {
		return 0, 0, 0, errors.New("KDF options must set m, t and p")
	}
	return memKiB, time, lanes, nil
}
