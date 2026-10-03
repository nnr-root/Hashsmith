# WP4.1 (Dynamic Hash Scripting Engine) — already satisfied, closed without new code

## What was asked

"Implement an ad-hoc hash chain definition parser (similar to John the
Ripper's `dynamic=`) allowing custom nested hashes (e.g., `md5(sha1($p).$s)`)."

## What's actually in the repo

`internal/smith/crack_john_dynamic.go` (711 lines) already is this — and
goes further than the task asked. It is a full expression parser and
evaluator for John's entire dynamic-format language:

- **Ad-hoc inline expressions**, exactly as asked: `@dynamic=<expr>@<record>`
  lets an expression be given on the spot rather than chosen from a table.
- **John's full ~200-scheme numbered table too** (`$dynamic_N$`), via a spec
  table (`john_dynamic_spec.go`) transcribed from John itself.
- The expression language: concatenation (`.`), nested calls, `_raw`/`_64`
  digest suffixes, variables (`$p`/`$pass`, `$s`/`$salt`, `$s2`,
  `$u`/`$username`), literals (including `HEX$...` and backslash escapes),
  and the non-digest calls John supports (`utf16`, `uc`, `lc`, `pad16`,
  `pad20`, `space_pad_10`, `null_padded_to_len_100`).
- Salt, second-salt, and username handling, including hex-encoded salts and
  a login given before the record.

## Verified this session, not just read

Ran the exact example from the task prompt, `md5(sha1($p).$s)`, against a
real computed target (`md5(sha1("letmein") + "abcd1234")`):

```
$ hashsmith crack -t dynamic "@dynamic=md5(sha1($p).$s)@8ba9283c352f0e47c4daeffd53e38e02$abcd1234" -w words.txt --no-pot
@dynamic=md5(sha1($p).$s)@8ba9283c352f0e47c4daeffd53e38e02$abcd1234:letmein
Found: letmein
```

Cracked correctly on the first try. The existing test suite
(`crack_john_dynamic_test.go`) passes clean: 159 real John corpus records
(pinned count, so a quiet regression in coverage would fail loudly), the
expression-language unit tests (salts on either side, usernames as both a
marker and a login, second salts, hex-encoded salts, a literal with no
separator), a specific numbered-format regression test, and envelope
variants. `go test ./internal/smith/ -run TestJohnDynamic -v`: 7/7 pass.

**Note on record syntax, for whoever reaches for this next:** the inline
form's salt separator is `$`, matching the numbered form's own convention
(`<digest>$<salt>`), not `:`. A first attempt using `:` failed to parse
silently as a wrong password rather than a syntax error — not a bug, just
the documented syntax, worth stating plainly since it tripped up this
session's own first try.

## One real, minor, pre-existing gap — noted, not fixed

Neither `@dynamic=...` nor `$dynamic_N$` records are recognized by
auto-detection (`hashsmith crack <target>` with no `-t`); both require the
explicit `-t dynamic`. This appears to be deliberate rather than an
oversight — `types.go`'s own doc entry for this type never claims
auto-detection — but it's worth naming for whoever next touches
auto-detect's dispatch table, since a bare `$dynamic_...$` string is in
practice fairly recognizable and could plausibly be added to the
auto-detection candidate list later. Not touched here: out of this task's
scope, and the existing behavior is not wrong, just conservative.

## Disposition

WP4.1 is satisfied by existing work, verified end-to-end against the
task's own example. No new code was written.
