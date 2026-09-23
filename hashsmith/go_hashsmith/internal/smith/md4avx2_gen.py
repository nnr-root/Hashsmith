"""Generator for md4avx2_amd64.s — the pipelined 3-chain x 8-lane (24-way)
AVX2 MD4 core, the x86-64 counterpart of the arm64 NEON MD4 core in
md4neon_arm64.s.

This file is a composition of two things that already ship and are already
correct, and it deliberately invents neither:

  * md4neon_gen.py is the authority for MD4's *round structure* — the three
    16-step passes, their per-pass constants, their message-word orders,
    their shift schedules, and the fact that MD4's step has no trailing
    "+ b". Every MD4-specific table below is copied from that file, not
    re-derived from memory.

  * md5avx2_gen.py is the authority for the *AVX2 codegen* — register
    allocation, the VPADDD/VPXOR/VPOR/VPAND idioms, the memory-operand
    trick that lets constants and message words be added without spending
    a register, the shift/shift/or rotate idiom, the software-pipelined
    interleave of N independent chains, and the Plan 9 emission shape.

=== MD4 is not MD5: every difference, and where it is handled here ===

Each of these produces a plausible-looking but wrong 16-byte digest if
ported carelessly, so each is called out explicitly:

 1. 48 steps, not 64 — `for step in range(48)` in generate(), three passes
    of 16 rather than MD5's four.

 2. Three PER-PASS constants (0x00000000, 0x5A827999, 0x6ED9EBA1), not a
    64-entry per-step table — KPASS below, indexed by `step // 16` in
    kconst_of(). The constant changes 3 times per call, not 48.

    MD4's first-pass constant is 0, and `x + 0 == x`, so the pass-1 K add
    is not emitted at all (see chain_block: the VPADDD against kvec is
    conditional on the pass constant being non-zero). That removes 16 of
    the 48 dependent adds from each chain's serial critical path for free.
    kvec[0] is therefore present but never read — kept so the Go-side
    table is indexed by pass number exactly as md4neon_arm64.go's md4Kvec
    is, rather than silently renumbered.

 3. Round 2 is MAJORITY, `(b&c) | (b&d) | (c&d)` — NOT MD5's
    `(b&d) | (c&~d)`. See the 'G' branch of chain_block and the identity
    note below.

 4. NO trailing "+ b". MD5's step is `a = b + rotl(a + F + K + M, s)`;
    MD4's is `a = rotl(a + F + K + M, s)`. Concretely, md5avx2_gen.py ends
    its step with `VPADDD T, B, A` (newB = B + rotated, landing in A's
    register); this generator instead ends the rotate with
    `VPOR T, A, A`, so the rotated value lands directly in A's register
    with nothing added to it. There is no VPADDD after the rotate here —
    that absence IS difference #4.

 5. Message index order and shift amounts per pass are MD4's, taken
    verbatim from md4neon_gen.py's ORDER and SHIFT tables (copied below,
    not re-derived).

 6. AVX2 has no single-instruction vector NOT — but this core needs none,
    and takes no all-ones argument (unlike md5avx2_amd64.s, which needs
    one for its round-4 I function). MD4's round 1 F is
    `(b&c) | (~b&d)`, which is *the same function as MD5's F*, and
    md5avx2_gen.py already computes it NOT-free via the bit-select
    identity `F = d ^ (b & (c^d))` — reused verbatim here. MD4's rounds 2
    and 3 (majority and xor) contain no complement either, and MD4 has no
    round 4, so the all-ones vector MD5's I round needs is simply absent.
    md4neon_gen.py reached the same conclusion for the NEON port ("MD4 has
    no round 4 ... so the all-ones constant register MD5's I round needs
    is not needed at all here"), and this port stays consistent with it.

=== Round 2's majority in ONE scratch register (no register cost) ===

The obvious majority form, `(b&c) | (d&(b^c))`, needs two live temporaries
(one per OR operand) and would push the per-chain budget from 5 YMM to 6,
dropping the chain ceiling from 3 to 2. It is avoided by observing that
the two OR operands are DISJOINT:

    (b&c)     is set only where b == c == 1
    d&(b^c)   is set only where b != c

No bit is set in both, so their OR carries nowhere and equals their SUM.
Since the step is already accumulating into A, the two halves can simply
be added into A one at a time, reusing the single scratch T for each:

    T = B ^ C ;  T = T & D ;  A += T ;  T = B & C ;  A += T

That is 5 instructions and 1 temporary — the same instruction count as the
2-temporary VPOR form (which also needs a fifth instruction to add its
result into A), for one fewer register. Rounds 1 and 3 are unchanged from
md5avx2_gen.py's F and H shapes.

=== Register budget: why N = 3 ===

Per chain: state A,B,C,D (4 YMM) + one scratch T (1 YMM) = 5, exactly as
md5avx2_gen.py derives (B, C, D must survive each step intact to be reused
as the next step's C, D, A; only A's slot is overwritten, leaving one free
register, and the round-function value is fully consumed into A before the
rotate needs a temporary, so T serves both sequentially).

Shared registers: zero. K and M are added straight from memory via AVX2's
memory-operand VPADDD, and there is no all-ones constant (see #6 above).

So the budget is N*5 <= 16, giving N = 3 (15 of 16 YMM, one to spare).
N = 4 would need 20 YMM and must spill, which costs more than the fourth
chain gains — so 3 is the ceiling here, not merely parity with the MD5
core. Note that MD4's cheaper per-step constant handling does NOT buy a
register on x86 the way it might elsewhere: on AVX2 the per-step constant
never occupied a register in the first place (it is a memory operand), so
collapsing 64 constants to 3 saves instructions, not registers.

Regenerate with: `python3 md4avx2_gen.py` from this directory. Do not
hand-edit md4avx2_amd64.s — edit this file and regenerate instead.
"""

import os

LANES = 8  # AVX2: one YMM = 8x uint32

# --- MD4 tables, copied verbatim from md4neon_gen.py (the known-correct
# --- shipping MD4 core), NOT re-derived. Do not "simplify" these.

# Per-pass round constant. MD4 has 3 passes, not MD5's 64-step table.
KPASS = [0x00000000, 0x5A827999, 0x6ED9EBA1]

# Per-pass message word order. Pass 3's permutation has no clean closed
# form worth the risk of getting subtly wrong, so all three are literal.
ORDER = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
    [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
]

# Per-pass shift amounts, cycled across the pass's 16 steps.
SHIFT = [3, 7, 11, 19] * 4, [3, 5, 9, 13] * 4, [3, 9, 11, 15] * 4

FUNC_KIND = ['F', 'G', 'H']


def msgidx(step):
    return ORDER[step // 16][step % 16]


def shift_of(step):
    return SHIFT[step // 16][step % 16]


def func_kind(step):
    return FUNC_KIND[step // 16]


def kconst_of(step):
    return KPASS[step // 16]


def chain_block(step, regs, T, msg_reg, kvec_reg):
    A, B, C, D = regs
    kind = func_kind(step)
    mi = msgidx(step)
    s = shift_of(step)
    p = step // 16
    moff = mi * LANES * 4
    koff = p * LANES * 4
    lines = []
    lines.append('\t// step %d pass %d %s msg=%d(%s) K=0x%08x s=%d A=%s' %
                 (step, p, kind, moff, msg_reg, KPASS[p], s, A))
    if kind == 'F':
        # F(b,c,d) = (b&c) | (~b&d), computed NOT-free by the bit-select
        # identity d ^ (b & (c^d)) — identical to md5avx2_gen.py's F round,
        # because MD4's round 1 and MD5's round 1 are the same function.
        lines.append('\tVPXOR %s, %s, %s' % (D, C, T))     # T = C^D
        lines.append('\tVPAND %s, %s, %s' % (B, T, T))     # T = B&(C^D)
        lines.append('\tVPXOR %s, %s, %s' % (D, T, T))     # T = D^(B&(C^D)) = F
        lines.append('\tVPADDD %s, %s, %s' % (T, A, A))    # A += F
    elif kind == 'G':
        # MAJORITY (b&c)|(b&d)|(c&d) — NOT MD5's round 2. Split into the
        # two disjoint halves (b&c) and d&(b^c) and ADDED into A one at a
        # time (their OR equals their sum, since no bit is set in both),
        # which keeps round 2 inside the single scratch register T. See
        # the module docstring.
        lines.append('\tVPXOR %s, %s, %s' % (C, B, T))     # T = B^C
        lines.append('\tVPAND %s, %s, %s' % (D, T, T))     # T = D&(B^C)
        lines.append('\tVPADDD %s, %s, %s' % (T, A, A))    # A += D&(B^C)
        lines.append('\tVPAND %s, %s, %s' % (C, B, T))     # T = B&C
        lines.append('\tVPADDD %s, %s, %s' % (T, A, A))    # A += B&C  (= A += maj)
    else:  # H
        lines.append('\tVPXOR %s, %s, %s' % (C, B, T))     # T = B^C
        lines.append('\tVPXOR %s, %s, %s' % (D, T, T))     # T = B^C^D = H
        lines.append('\tVPADDD %s, %s, %s' % (T, A, A))    # A += H
    # A += K[pass], streamed straight from memory — costs no register.
    # Pass 1's constant is 0, so its add is the identity and is omitted
    # entirely rather than emitted for uniformity: it would sit on the
    # step's serial dependency chain for nothing.
    if kconst_of(step) != 0:
        lines.append('\tVPADDD %d(%s), %s, %s' % (koff, kvec_reg, A, A))
    # A += M[g], streamed straight from memory — costs no register.
    lines.append('\tVPADDD %d(%s), %s, %s' % (moff, msg_reg, A, A))
    # Rotate left by s: T = A<<s (A untouched), then A >>= (32-s) in place
    # (A's sum is dead once T holds A<<s), then A |= T so the rotated value
    # ends up in A's register.
    #
    # MD4 DIFFERENCE #4: this is where MD5 would do one final
    # `VPADDD T, B, A` (newB = B + rotated). MD4 has no trailing "+ b", so
    # the rotate's own OR writes A and the step ends here. The absence of a
    # VPADDD on the next line is deliberate and load-bearing.
    lines.append('\tVPSLLD $%d, %s, %s' % (s, A, T))
    lines.append('\tVPSRLD $%d, %s, %s' % (32 - s, A, A))
    lines.append('\tVPOR %s, %s, %s' % (T, A, A))
    lines.append('')
    return lines, [D, A, B, C]


HEADER = '''// Code generated by md4avx2_gen.py. DO NOT EDIT BY HAND — edit
// md4avx2_gen.py and regenerate with `python3 md4avx2_gen.py` from this
// directory.
//
// AVX2 MD4 core: %(n)d independent 8-lane MD4 chains (%(group)d candidates in
// flight per call), software-pipelined so the out-of-order core overlaps
// each chain's 48-step serial dependency latency with the others'. It is
// the x86-64 counterpart of md4neon_arm64.s and computes bit-identical
// digests; MD4 here also backs NTLM, which is MD4 over UTF-16LE(pw) rather
// than a different digest function.
//
// See md4avx2_gen.py's module docstring for the register-budget derivation
// (5 YMM/chain, 0 shared, ceiling N=3 in 16 YMM), for how round 2's
// majority function fits in one scratch register via its disjoint-halves
// identity, and for the itemised list of every way MD4 differs from the
// MD5 core this shares its codegen with.
//
// Message layout per chain: word-major, lane-minor [16][8]uint32 — word g
// at byte offset g*32. K layout: [3][8]uint32, pass p at byte offset p*32,
// each of MD4's three per-pass constants pre-broadcast to all 8 lanes by
// the Go side (pass 0's constant is 0, so it is never loaded — adding it
// would be the identity). State in/out layout: [4][8]uint32, word w at
// byte offset w*32. There is no all-ones argument: MD4 needs no vector NOT
// anywhere (its round 1 is computed by a bit-select identity, and it has no
// round 4).
#include "textflag.h"

// func %(funcname)s(%(outlist)s *[4][8]uint32, %(msglist)s *[16][8]uint32, kvec *[3][8]uint32, ivvec *[4][8]uint32)
TEXT ·%(funcname)s(SB), NOSPLIT, $0-%(argsz)d
%(prologue)s

%(load_state)s
'''

GPR_POOL = ['AX', 'BX', 'CX', 'DX', 'SI', 'DI',
            'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']


def generate(n, funcname, outpath):
    assert n * 5 <= 16, 'too many chains for the 16-YMM budget'
    assert 2 * n + 2 <= len(GPR_POOL), 'too many chains for available GPRs'

    ymm_pool = list(range(16))
    chain_regs = []  # per chain: [state[4], T]
    for c in range(n):
        base = ymm_pool[c * 5:(c + 1) * 5]
        state = ['Y%d' % r for r in base[0:4]]
        T = 'Y%d' % base[4]
        chain_regs.append([state, T])

    out_regs = GPR_POOL[0:n]
    msg_regs = GPR_POOL[n:2 * n]
    kvec_reg = GPR_POOL[2 * n]
    ivvec_reg = GPR_POOL[2 * n + 1]

    # --- prologue: load args ---
    argsz = 8 * (n + n + 1 + 1)  # out ptrs + msg ptrs + kvec + ivvec
    prologue = []
    off = 0
    for i in range(n):
        prologue.append('\tMOVQ out%d+%d(FP), %s' % (i, off, out_regs[i])); off += 8
    for i in range(n):
        prologue.append('\tMOVQ msg%d+%d(FP), %s' % (i, off, msg_regs[i])); off += 8
    prologue.append('\tMOVQ kvec+%d(FP), %s' % (off, kvec_reg)); off += 8
    prologue.append('\tMOVQ ivvec+%d(FP), %s' % (off, ivvec_reg)); off += 8

    # --- load IV into every chain's state registers ---
    load_state = []
    for c in range(n):
        state, _T = chain_regs[c]
        for w in range(4):
            load_state.append('\tVMOVDQU %d(%s), %s' % (w * LANES * 4, ivvec_reg, state[w]))

    # --- 48-step body (three passes of 16; MD5's is 64) ---
    lines = []
    for step in range(48):
        for c in range(n):
            state, T = chain_regs[c]
            blk, newstate = chain_block(step, state, T, msg_regs[c], kvec_reg)
            lines += blk
            chain_regs[c][0] = newstate
    body = '\n'.join(lines)

    # --- footer: add the chaining value back (straight from ivvec memory,
    # --- no temp register needed) and store final state to each chain's out
    footer_lines = []
    for c in range(n):
        state, _T = chain_regs[c]
        for w in range(4):
            footer_lines.append('\tVPADDD %d(%s), %s, %s' % (w * LANES * 4, ivvec_reg, state[w], state[w]))
        for w in range(4):
            footer_lines.append('\tVMOVDQU %s, %d(%s)' % (state[w], w * LANES * 4, out_regs[c]))
    footer_lines.append('\tVZEROUPPER')
    footer_lines.append('\tRET')

    header = HEADER % {
        'funcname': funcname,
        'n': n,
        'group': n * LANES,
        'outlist': ', '.join('out%d' % i for i in range(n)),
        'msglist': ', '.join('msg%d' % i for i in range(n)),
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
          'yregs/chain=5 total=', 5 * n, 'gprs=', 2 * n + 2)


if __name__ == '__main__':
    outdir = os.path.dirname(os.path.abspath(__file__))
    generate(3, 'md4g24AVX2', os.path.join(outdir, 'md4avx2_amd64.s'))
