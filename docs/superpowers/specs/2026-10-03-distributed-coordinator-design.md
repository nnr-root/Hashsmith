# WP4.2 — Lightweight Multi-Node Coordinator — Design

## Context

From the pasted "Work Package 4" roadmap: "Build a lightweight coordinator
protocol on top of the existing `--skip`/`--limit` slicing engine to
automatically slice and distribute wordlist/mask ranges across multiple
network nodes over HTTP/SSH." WP4.1 (the dynamic hash scripting half of
WP4) turned out to already exist (`internal/smith/crack_john_dynamic.go`) —
see `docs/superpowers/notes/2026-10-03-wp4-1-dynamic-hashing-already-satisfied.md`.
This spec covers the other half, which genuinely does not exist yet
(confirmed: zero `net/http` usage anywhere in `go_hashsmith` before this).

## Decisions already made (via AskUserQuestion, this session)

1. **HTTP only, no SSH bootstrap.** Workers are started manually (locally,
   or by the operator's own SSH session); the protocol itself is HTTP.
   Building an SSH client (`golang.org/x/crypto/ssh`, auth, host-key
   verification) is real added complexity for a path this session cannot
   validate against a real remote host anyway.
2. **Dynamic pull-based chunking**, not a static even split. The keyspace
   is divided into chunks (more than the worker count); each worker asks
   for one, runs it, asks for the next. Naturally load-balances across
   workers of different speed and degrades gracefully if one goes offline.
3. **Dict-mode wordlists must already exist at the same path on every
   worker.** No wordlist-content shipping over HTTP. Documented limitation,
   not a protocol feature; mask/brute-mode jobs need no file at all.
4. **Shared-secret token auth.** Every request from coordinator to worker
   carries a token; a worker rejects (401) any request without the
   matching one.

## Explicit non-goals

- **No mid-chunk cancellation.** When one worker reports `found`, the
  coordinator stops handing out new chunks immediately, but any worker
  already running a chunk finishes it — its (now-irrelevant) result is
  discarded on report-back. Real cancellation would mean threading a
  `context.Context` into `runCrack`'s own signature (it currently takes
  none) and rippling that through every call site, the same shape of
  change WP1's `newCrackCtx` signature change was — a real touch to
  heavily-tested core code for a benefit bounded by chunk size alone.
  **Note for later:** `internal/smith/keyspace.go`'s `runLayout`/
  `runLayoutFast` already accept a `context.Context` internally — so real
  cancellation, if ever wanted, has a real foothold to build from. Not
  pursued here because reaching it still means changing `runCrack`'s own
  signature, which this spec deliberately avoids.
- **No SSH**, per the decision above.
- **No wordlist shipping**, per the decision above.
- **No real multi-machine validation this session** — confirmed no second
  physical machine or cloud instance is reachable. Validation here is
  multiple local worker processes on different loopback ports, which
  exercises the real HTTP protocol and real concurrent `runCrack`
  invocations, but never a real network partition, real latency, or two
  different machines' clock/filesystem state. Named explicitly, same
  framing as WP3's hardware-blocked work.
- **No persistent job queue / restart-after-coordinator-crash.** If the
  coordinator process dies, the job is gone; re-run it. This project's
  existing `--session` mechanism already solves resumability for a single
  machine and is out of scope to extend here.

## Architecture

Two new CLI subcommands on the existing `hashsmith` binary — no new
binary, no new project, matching how `gpu`/`benchmark`/`interactive` are
already dispatched from `internal/smith/main.go`.

### `hashsmith worker`

```
hashsmith worker --listen :8745 --token <secret>
```

An HTTP server, one real endpoint:

```
POST /chunk
Header: X-Hashsmith-Token: <secret>
Body (JSON):
  {
    "type": "md5",            // -t value
    "target": "5f4dcc3b...",  // the hash to crack
    "salt": "", "saltMode": "prefix",   // -s/-S, if any
    "mode": "mask" | "brute" | "dict",
    // mode == "mask":
    "mask": "?u?l?l?l?d?d",
    "charsets": {"1": "...", "2": "...", "3": "...", "4": "..."},  // -1.. -4, if used
    // mode == "brute":
    "charset": "...", "minLen": 1, "maxLen": 8,
    // mode == "dict":
    "wordlist": "/shared/path/words.txt",
    "skip": 4000000, "limit": 1000000
  }

Response 200 (JSON):
  {"found": true, "password": "Qwerty12"}
  {"found": false}

Response 401: wrong/missing token.
Response 400: malformed request (unknown mode, missing required field for
  that mode, skip/limit missing or negative).
Response 500: the underlying runCrack call itself errored (a real internal
  error — a malformed wordlist path, an unsupported -t value, etc., not
  "not found", which is a normal 200 with found:false).
```

The handler builds a `[]string` CLI-argument slice equivalent to what a
human would type for that mode (`-t`, the target, `-M mode`, `--skip`,
`--limit`, and the mode-specific flags), under a package-level mutex (one
chunk at a time per worker process — `runCrack` shares a package-level
`exitCode` variable across calls, so serializing access is required for
correctness, not just simplicity), and calls the existing
`runCrack(args []string) error` — confirmed this session to never call
`os.Exit` itself (only `internal/smith/main.go`'s own top-level dispatch
does), so this is safe to call from inside a long-running server process.
Found/not-found comes from reading the package's `exitCode` variable
immediately after the call (0 = found, 1 = not found, consistent with how
`runCrack`'s own existing callers already read it — e.g.
`association_test.go`), and the password comes from a `-o`-style result
Hashsmith's own crack path already writes, read back after the call. (The
plan pins the exact outfile-format/flag combination that gets a clean,
single-line password back — this spec fixes the mechanism, not the exact
flag spelling.)

### `hashsmith coordinate`

```
hashsmith coordinate -t md5 5f4dcc3b5aa765d61d8327deb882cf99 \
  -M mask --mask '?u?l?l?l?d?d' \
  --workers http://host1:8745,http://host2:8745,http://127.0.0.1:8746 \
  --token <secret> \
  [--chunk-size 1000000]
```

Takes the same target/mode/mask/wordlist/salt flags a normal `hashsmith
crack` invocation would (so a user migrates from local to distributed by
adding `--workers`/`--token`, not by learning a new flag vocabulary), plus
`--workers` (comma-separated worker URLs), `--token`, and `--chunk-size`
(default picked so a typical chunk takes roughly single-digit seconds to
under a minute on a representative machine — the plan pins the exact
default from a real measurement, not a guess).

1. Computes the total keyspace by building the same `*keyspaceLayout` the
   normal crack path already builds internally for mask/brute modes
   (`maskLayout`/`bruteLayout` in `internal/smith/keyspace.go`, reading
   `.total`) — reusing existing, proven computation rather than
   re-deriving it. Dict mode's keyspace is the wordlist's line count,
   via whatever existing helper the normal dict-mode path already uses
   for its own progress reporting (the plan pins the exact function).
2. Builds a FIFO queue of `(skip, limit)` chunk ranges covering
   `[0, total)` in `--chunk-size`-sized pieces (the last chunk is
   whatever remainder is smaller than a full chunk).
3. Runs one goroutine per worker URL. Each goroutine loops: pop the next
   chunk off the queue (a mutex-guarded slice or channel) → `POST /chunk`
   to its worker with a reasonable HTTP timeout → on `found:true`, store
   the result and close a shared "done" channel so every other goroutine's
   next queue-pop sees it and exits without taking more work → on
   `found:false`, loop to the next chunk → on queue empty, exit → on
   request failure (timeout, connection refused, non-2xx other than the
   expected codes above), put the chunk back on the queue and increment
   that worker's failure count; after a small fixed number of consecutive
   failures (the plan picks the exact number, e.g. 3), stop using that
   worker for the rest of the run (it's presumed dead) rather than retry
   forever.
4. Once every goroutine has exited (either the queue drained with no find,
   or a find closed the done channel), report the result the same way a
   normal `crack` command does: print `Found: <password>` (or the
   not-found message) and the usual summary line, and set the process's
   own exit code using this project's existing script-friendly convention
   (0 = found, 1 = not found, 2 = usage/setup error) — reusing
   `main.go`'s own `exitCode` convention rather than inventing a parallel
   one.

## Error handling, summarized

| Situation | Behavior |
|---|---|
| Worker returns 401 | That worker is treated as a configuration error, not a transient failure — coordinator stops using it immediately (wrong token is not going to fix itself on retry) and warns on stderr, but keeps going with any remaining workers |
| Worker times out / connection refused | Chunk requeued; failure counted; worker dropped after the fixed retry limit |
| Worker returns 400 | A protocol bug (the coordinator sent something the worker couldn't parse) — logged loudly, that chunk is requeued once, and if it 400s again, the coordinator aborts the whole run rather than looping forever on a bug it can't route around |
| Worker returns 500 | The underlying crack attempt itself errored (bad wordlist path, bad -t, etc.) — same treatment as 400: not a transient condition, requeue once, abort the run if it recurs, since a chunk that errors here will error identically everywhere |
| All workers exhausted/dead with chunks still unassigned | Coordinator reports a clear error naming how much of the keyspace was never attempted, rather than silently reporting "not found" for a search that didn't actually cover the whole space |
| Queue drains, no worker ever found it | Normal not-found result, same as a local crack run that exhausts its keyspace |

## Testing plan

All loopback-only, per the stated scope:

1. **Protocol unit tests** (no network): the chunk-queue splitting logic
   against known keyspace totals and chunk sizes (off-by-one at the final,
   partial chunk; a keyspace smaller than one chunk; a keyspace that
   divides evenly).
2. **Worker handler tests** (`httptest.Server`, no real sockets needed):
   token rejection, malformed-mode rejection, a real mask job against a
   real target returning `found:true` with the right password, a real
   miss returning `found:false`.
3. **End-to-end test**: start 2-3 real `hashsmith worker` processes on
   different `127.0.0.1` ports (via `exec.Command` or in-process HTTP
   servers on ephemeral ports — the plan picks whichever is more directly
   testable against the real CLI entry points), run `coordinate` against
   them with a mask keyspace split into enough chunks to exercise more
   than one chunk per worker, assert the right password is found and
   reported. A second case with one worker given the wrong token, asserting
   the job still completes correctly using only the remaining workers. A
   third case killing one worker process mid-run (or just never starting
   it) and confirming its chunks get picked up by the others rather than
   silently skipped.

## Spec self-review

- **Placeholder scan:** no TBD/TODO. The two items explicitly deferred to
  the implementation plan (exact outfile-format flag combination for
  reading back a worker's found password, exact dict-mode word-count
  helper, exact default `--chunk-size` and retry-count numbers) are named
  as "the plan pins this from a real check/measurement," not left vague —
  they're implementation-detail lookups the plan is the right place to
  pin exactly, not unresolved design questions.
- **Internal consistency:** the non-goals section and the architecture
  section agree (no cancellation is designed in, not an oversight; no
  wordlist shipping is designed in, not an oversight).
- **Scope:** single cohesive subsystem (one protocol, two subcommands);
  does not need further decomposition into separate specs.
- **Ambiguity:** "found" is unambiguous (a boolean from runCrack's
  existing exitCode convention); chunk sizing's exact default number is
  the one true remaining judgment call, explicitly deferred to the plan
  with a stated reason (needs a real measurement) rather than guessed
  at here.
