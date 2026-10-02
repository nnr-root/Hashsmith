"""Generator for sha1avx2_amd64.s — a pipelined N-chain x 8-lane AVX2 SHA-1
core. Modelled on md5avx2_gen.py's multi-chain generator shape (same
generate(n, ...) parametrization, same "generate both candidate widths, let
the differential tests and eventually real hardware decide" posture) but
with SHA-1's own round function and, critically, its own register-reuse
derivation — SHA-1 sits between MD5 (4 state, N=3) and SHA-256 (8 state,
N=1) in a way that is NOT simply "average the two register budgets": it
needs careful sequencing to reach a good number at all.

=== Register budget: 5 state + 3 scratch = 8/chain, N=2 fits exactly ===

A naive translation of the round function --
    T1 = f(b,c,d) [1-2 temps depending on round group]
    T2 = ROTL5(a) [2 temps: shift-left half + shift-right half before OR]
    new_a = T2 + T1 + e + K[t] + W[t]
    new_c = ROTL30(b) [2 more temps]
-- looks like it wants 5 state + up to 5 scratch (Ch/Parity need 1 temp for
f, Maj needs 2; ROTL5 needs 2; ROTL30 needs 2 more since it happens after
ROTL5's accumulator is already committed) = up to 10/chain, which would cap
this at N=1 (2*10=20 > 16), the same ceiling as SHA-256.

But the ROTL5(a) accumulator (call it Ta) is the ONLY value that must
survive from the start of the round to the very end (it becomes new_a once
f/e/K/W are added into it) — every other temp is short-lived and, in the
right order, reusable:

  1. Ta = ROTL5(a), using Tb as the shift-left-half builder. Tb is free the
     instant the OR into Ta completes.
  2. f(b,c,d) into Tf, reusing the NOW-FREE Tb as Maj's second temp when
     the round needs it (Ch/Parity need only Tf; Maj needs Tf AND Tb
     simultaneously: Tf=b^c, Tb=b&c, Tf=d&Tf, Tf=Tf^Tb). Tf is free the
     instant it is added into Ta below.
  3. Ta += Tf; Ta += e; Ta += K[t] (mem); Ta += W[t] (mem). Ta now holds
     new_a. Tf is free again.
  4. ROTL30(b) into Tf, using the AGAIN-free Tb as its second temp
     (Tf=b>>2, Tb=b<<30, Tf=Tf|Tb). Tf now holds new_c.

Three distinct scratch names (Ta, Tf, Tb) suffice, never more than two live
at once outside Ta's whole-round lifetime — verified by the differential
tests, not merely asserted here, since a register-reuse argument this
tight is exactly where a subtle mistake hides. 5 state + 3 scratch = 8
YMM/chain, so N*8 <= 16 permits **N=2**, with zero registers to spare
(unlike MD5's N=3 leaving one free) — there is no room for anything else,
which is why K and W stay memory-operand-only (as MD5's already are) and
nothing is cached in a register across steps.

=== State update: a ROTATING scratch pool, not a copy ===
(revised 2026-10-02 — see docs/superpowers/notes/2026-10-02-wp2-2-sha1-avx2-feasibility-spike.md
for the measurement that prompted re-deriving this)

Unlike MD5's pure rotation-of-labels, SHA-1's b->c transition is a REAL
computation (ROTL30), not a free rename — see new_c above. An earlier
version of this generator kept Ta/Tb/Tf as three FIXED physical registers
every round, distinct from the 5 state registers, and consolidated each
round's two computed values (new_a, new_c) into the freed-up old b/e
registers via two `VMOVDQU` copies — reasoning that MD5/SHA-256 avoid any
copy via pure relabeling, so SHA-1's extra computed value made "one copy"
feel unavoidable. That reasoning mixed up two different things: needing a
register to HOLD the new value (true) and needing to COPY it into a
specific, pre-chosen register (not true).

This generator is a Python script fully unrolling 80 static rounds — there
is no runtime reason the physical register playing "the b register" must
be the same one every round. Tracing liveness precisely: by the time Ta
finishes accumulating new_a's final sum, old_b's physical register is
NOT yet free (ROTL30(b), later in the same round, still needs to read it)
— so the copy felt forced if you insist on consolidating into old b's slot.
But nothing requires that consolidation. Once old_b and old_e are read for
the last time this round, their registers simply BECOME the next round's
free scratch pool, and Ta/Tf (which already hold new_a/new_c by
construction, as a side effect of the arithmetic that built them) just
BECOME the next round's "a" and "c" state registers — a relabel, exactly
like MD5/SHA-256's, just one round later than the other three:
  - old_a, old_c, old_d are each read exactly once (ROTL5(a)'s input,
    f(b,c,d)'s c operand, f(b,c,d)/new_e's d operand) and never written —
    they become new_b, new_d, new_e purely by relabeling, unchanged from
    before.
  - new_a's home is whichever register was handed to this round as a
    free scratch slot and used to build Ta — it simply continues to BE
    new_a's register for the next round, no VMOVDQU.
  - new_c's home is the free slot used to build Tf — same thing.
  - old_b and old_e's registers, no longer referenced by anything, become
    two of the next round's three free slots (joining Tb, which was
    always transient). The free pool rotates: {Ta,Tb,Tf} this round ->
    {old_b, old_e, Tb} next round -> ... — never the same three physical
    registers twice in a row, but always exactly 3, so the total budget
    (5 state + 3 free = 8/chain) is unchanged and N=2 still fits 16 YMM
    exactly.

Net effect: 2 fewer instructions per round (no `VMOVDQU` pair), 80 rounds,
2 chains per N=2 call — 320 fewer instructions per 16-lane compression,
for the identical arithmetic result (the differential tests below are
what actually proves that, not this derivation).

Regenerate with: `python3 sha1avx2_gen.py` from this directory. Do not
hand-edit sha1avx2_amd64.s — edit this file and regenerate instead.
"""

import os

LANES = 8  # AVX2: one YMM = 8x uint32


def round_kind(step):
    if step < 20:
        return 'ch'
    if step < 40:
        return 'parity'
    if step < 60:
        return 'maj'
    return 'parity'


def round_block(step, regs, free, msg_reg, kvec_reg):
    """regs is [a,b,c,d,e]. free is this round's 3 available scratch
    registers (their physical identity rotates round to round — see the
    module docstring). Returns (lines, new_regs, new_free): new_regs is
    the [a,b,c,d,e] register-role list for the NEXT round (new_a/new_c
    land in two of THIS round's free registers, used as accumulators
    directly — no copy; new_b/new_d/new_e are pure relabels of old
    a/c/d). new_free is the NEXT round's 3 free registers: old b, old e
    (no longer referenced once this round's last read of each completes),
    plus Tb (always transient).
    """
    a, b, c, d, e = regs
    Ta, Tb, Tf = free
    woff = step * LANES * 4
    koff = step * LANES * 4
    kind = round_kind(step)
    lines = ['\t// round %d (%s)  a=%s b=%s c=%s d=%s e=%s' % (step, kind, a, b, c, d, e)]

    # Ta = ROTL5(a) = ROTR(a, 27)
    lines.append('\tVPSRLD $27, %s, %s' % (a, Ta))
    lines.append('\tVPSLLD $5, %s, %s' % (a, Tb))
    lines.append('\tVPOR %s, %s, %s' % (Tb, Ta, Ta))

    if kind == 'ch':
        lines.append('\tVPXOR %s, %s, %s' % (d, c, Tf))    # Tf = c^d
        lines.append('\tVPAND %s, %s, %s' % (b, Tf, Tf))   # Tf = b&(c^d)
        lines.append('\tVPXOR %s, %s, %s' % (d, Tf, Tf))   # Tf = d^(b&(c^d)) = Ch
    elif kind == 'parity':
        lines.append('\tVPXOR %s, %s, %s' % (c, b, Tf))    # Tf = b^c
        lines.append('\tVPXOR %s, %s, %s' % (d, Tf, Tf))   # Tf = b^c^d
    else:  # maj
        lines.append('\tVPXOR %s, %s, %s' % (c, b, Tf))    # Tf = b^c
        lines.append('\tVPAND %s, %s, %s' % (c, b, Tb))    # Tb = b&c   (Tb free: ROTL5 already committed)
        lines.append('\tVPAND %s, %s, %s' % (d, Tf, Tf))   # Tf = d&(b^c)
        lines.append('\tVPXOR %s, %s, %s' % (Tb, Tf, Tf))  # Tf = (b&c)^(d&(b^c)) = Maj

    # Ta += f(b,c,d) + e + K[t] + W[t]  -> Ta = new_a
    lines.append('\tVPADDD %s, %s, %s' % (Tf, Ta, Ta))
    lines.append('\tVPADDD %s, %s, %s' % (e, Ta, Ta))
    lines.append('\tVPADDD %d(%s), %s, %s' % (koff, kvec_reg, Ta, Ta))
    lines.append('\tVPADDD %d(%s), %s, %s' % (woff, msg_reg, Ta, Ta))

    # Tf = ROTL30(b) = ROTR(b, 2)  -> Tf = new_c (Tf, Tb both free again here)
    lines.append('\tVPSRLD $2, %s, %s' % (b, Tf))
    lines.append('\tVPSLLD $30, %s, %s' % (b, Tb))
    lines.append('\tVPOR %s, %s, %s' % (Tb, Tf, Tf))
    lines.append('')

    # No copy: Ta and Tf already hold new_a/new_c by construction and simply
    # BECOME the next round's a/c registers. old b and old e are read for
    # the last time above (f(b,c,d) / ROTL30(b), and the "+e" add,
    # respectively) and now join Tb as the next round's free pool.
    new_regs = [Ta, a, Tf, c, d]  # new_a=Ta, new_b=old a (relabel),
    # new_c=Tf, new_d=old c (relabel), new_e=old d (relabel)
    new_free = [b, e, Tb]
    return lines, new_regs, new_free


HEADER = '''// Code generated by sha1avx2_gen.py. DO NOT EDIT BY HAND — edit
// sha1avx2_gen.py and regenerate with `python3 sha1avx2_gen.py` from this
// directory.
//
// AVX2 SHA-1 compression core: %(n)d independent 8-lane chains (%(group)d
// candidates in flight per call) — see sha1avx2_gen.py's module docstring
// for the register-reuse derivation (5 state + 3 scratch = 8 YMM/chain,
// N=2 fits exactly in 16 YMM with nothing to spare).
//
// Message layout: word-major, lane-minor [80][8]uint32 per chain — the
// fully expanded 80-word schedule (see sha1_scalar.go's sha1ExpandSchedule),
// word t at byte offset t*32. K layout: [80][8]uint32, step t at byte
// offset t*32, each K value pre-broadcast to all 8 lanes. State in/out
// layout: [5][8]uint32, word w (a..e, index 0..4) at byte offset w*32.
#include "textflag.h"

// func %(funcname)s(%(outlist)s *[5][8]uint32, %(msglist)s *[80][8]uint32, kvec *[80][8]uint32, %(ivlist)s *[5][8]uint32)
TEXT ·%(funcname)s(SB), NOSPLIT, $0-%(argsz)d
%(prologue)s

%(load_state)s
'''

GPR_POOL = ['AX', 'BX', 'CX', 'DX', 'SI', 'DI',
            'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']


def generate(n, funcname, outpath):
    assert n * 8 <= 16, 'too many chains for the 16-YMM budget'
    assert 3 * n + 1 <= len(GPR_POOL), 'too many chains for available GPRs'

    ymm_pool = list(range(16))
    chains = []  # per chain: [state[5], free[3]] — free's physical
    # identity rotates every round (see module docstring); only its
    # starting assignment is arbitrary (any 3 of the chain's 8 registers
    # not used as the initial state will do).
    for c in range(n):
        base = ymm_pool[c * 8:(c + 1) * 8]
        state = ['Y%d' % r for r in base[0:5]]
        free = ['Y%d' % r for r in base[5:8]]
        chains.append([state, free])

    out_regs = GPR_POOL[0:n]
    msg_regs = GPR_POOL[n:2 * n]
    iv_regs = GPR_POOL[2 * n:3 * n]
    kvec_reg = GPR_POOL[3 * n]

    argsz = 8 * (n + n + n + 1)  # out ptrs + msg ptrs + ivvec ptrs + kvec
    prologue = []
    off = 0
    for i in range(n):
        prologue.append('\tMOVQ out%d+%d(FP), %s' % (i, off, out_regs[i])); off += 8
    for i in range(n):
        prologue.append('\tMOVQ msg%d+%d(FP), %s' % (i, off, msg_regs[i])); off += 8
    for i in range(n):
        prologue.append('\tMOVQ ivvec%d+%d(FP), %s' % (i, off, iv_regs[i])); off += 8
    prologue.append('\tMOVQ kvec+%d(FP), %s' % (off, kvec_reg)); off += 8

    load_state = []
    for c in range(n):
        state, _free = chains[c]
        for w in range(5):
            load_state.append('\tVMOVDQU %d(%s), %s' % (w * LANES * 4, iv_regs[c], state[w]))

    lines = []
    for step in range(80):
        for c in range(n):
            state, free = chains[c]
            blk, new_regs, new_free = round_block(step, state, free, msg_regs[c], kvec_reg)
            lines += blk
            chains[c] = [new_regs, new_free]
    body = '\n'.join(lines)

    footer_lines = []
    for c in range(n):
        state, _free = chains[c]
        for w in range(5):
            footer_lines.append('\tVPADDD %d(%s), %s, %s' % (w * LANES * 4, iv_regs[c], state[w], state[w]))
        for w in range(5):
            footer_lines.append('\tVMOVDQU %s, %d(%s)' % (state[w], w * LANES * 4, out_regs[c]))
    footer_lines.append('\tVZEROUPPER')
    footer_lines.append('\tRET')

    header = HEADER % {
        'funcname': funcname,
        'n': n,
        'group': n * LANES,
        'outlist': ', '.join('out%d' % i for i in range(n)),
        'msglist': ', '.join('msg%d' % i for i in range(n)),
        'ivlist': ', '.join('ivvec%d' % i for i in range(n)),
        'argsz': argsz,
        'prologue': '\n'.join(prologue),
        'load_state': '\n'.join(load_state),
    }

    with open(outpath, 'w') as f:
        f.write(header)
        f.write('\n')
        f.write(body)
        f.write('\n'.join(footer_lines))
        f.write('\n')
    print('generated', outpath, 'n=', n, 'group=', n * LANES,
          'yregs/chain=8 total=', 8 * n, 'gprs=', 3 * n + 1)


if __name__ == '__main__':
    outdir = os.path.dirname(os.path.abspath(__file__))
    outpath = os.path.join(outdir, 'sha1avx2_amd64.s')

    generate(1, 'sha1g8AVX2', os.path.join(outdir, '_n1.s.tmp'))
    generate(2, 'sha1g16AVX2', os.path.join(outdir, '_n2.s.tmp'))

    with open(outpath, 'w') as out:
        with open(os.path.join(outdir, '_n1.s.tmp')) as f1:
            out.write(f1.read())
        out.write('\n')
        with open(os.path.join(outdir, '_n2.s.tmp')) as f2:
            out.write(f2.read().replace('#include "textflag.h"\n', '', 1))
    os.remove(os.path.join(outdir, '_n1.s.tmp'))
    os.remove(os.path.join(outdir, '_n2.s.tmp'))
    print('combined into', outpath)
