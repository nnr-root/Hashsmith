"""Generator for md4neon_arm64.s — the pipelined 20-way NEON MD4 core.

Adapted from md5neon_gen.py (the MD5 sibling this ships alongside): same
5-chain (20-way), software-pipelined shape, retargeted at MD4's simpler
step function. MD4 has 48 steps (3 passes of 16, not 4 passes of 16), no
trailing "+ b" in the step (`a = rotl(a + f + K + M[g], s)`, not
`b + rotl(...)`), and per-pass constants (0, 0x5A827999, 0x6ED9EBA1)
instead of a 64-entry table.

Register budget per chain — MD4 needs LESS than MD5, not more, despite
round 2's majority function nominally wanting an extra temp:

  - Round 1 (F) and round 3 (H) are bitwise-identical in shape to MD5's F
    and H rounds and reuse the same 1-temp (fR) sequences: F is a select
    (VMOV B->fR then VBSL D,C,fR computing (B&C)|(~B&D)); H is two VEORs
    ((B^C)^D). Neither needs a second scratch register.

  - Round 2 (G) is the majority function (B&C)|(B&D)|(C&D), which the
    identity maj(x,y,z) = (x&y) | (z&(x^y)) turns into 4 instructions:
        fR   = B^C
        fR   = D & fR        (in place; legal ARM aliasing, dest==one src,
                               the same trick md5neon_gen.py's I round uses)
        rotR = B&C
        fR   = fR | rotR      (in place, same aliasing trick)
    This needs a second scratch register — but rotR (each chain's
    rotate/message-load temp) is free to serve as it, because this
    generator loads the step's message word into rotR AFTER computing the
    round function rather than before (md5neon_gen.py's order). The load
    has no dependency on the round function, so the reorder is free; it
    just vacates rotR for the one step in three that needs a second temp.
    So G costs zero extra registers, at the cost of reordering every
    step's instruction emission (uniformly, not just for G, to keep the
    generator simple) versus the MD5 generator.

  - MD4 has no round 4 (no `I = c^(b|~d)`), so the all-ones constant
    register MD5's I round needs (V25 there) is not needed at all here —
    one fewer *shared* register than MD5.

  - The step has no trailing "+ b": MD5 folds the running sum into A's own
    register (`A = A + f + K + M`, then `newB = B + rotl(A, s)` written
    back into A's now-dead register) — see md5neon_gen.py's header for
    that squeeze. MD4 keeps the same "accumulate into A, then let A's
    register carry the step's result" shape, it just skips the final
    "+ B": `newB = rotl(A + f + K + M, s)`, moved (not added) into A's
    register once rotated. One fewer instruction per step than MD5, no
    register-count change.

  - K is a per-PASS constant (3 values total), not a per-STEP table (48
    entries): the generator loads it once every 16 steps rather than
    once per step, using the same shared K-temp register MD5 uses, just
    loaded 3 times per call instead of 48.

Net per-chain budget is unchanged from MD5's: state A,B,C,D (4) + f-temp
(1) + rotate/message-load-temp (1) = 6 vector registers. Shared: 1
(K-temp) instead of MD5's 2 (K-temp, all-ones), since there is no I round.
Total = 6*N + 1, which for N=5 (20-way, matching the MD5 core and the
shared `neonChains` constant) is 31 of 32 registers — one register to
spare, versus MD5's exact 32/32 fit. neonChains did NOT need to change.

Regenerate with: `python3 md4neon_gen.py` from this directory. Do not
hand-edit md4neon_arm64.s — edit this file and regenerate instead.
"""

import os

# Per-pass round constant (MD4 has 3 passes, not MD5's 64-step table).
KPASS = [0x00000000, 0x5A827999, 0x6ED9EBA1]

# Per-pass message word order (brief's table, hardcoded rather than
# re-derived, since pass 3's permutation has no clean closed form worth
# the risk of getting subtly wrong).
ORDER = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
    [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
]

# Per-pass shift amounts, cycled across the pass's 16 steps (same
# "4 values repeated 4 times, indexed directly by local step" shape as
# md5neon_gen.py's S table).
SHIFT = [3, 7, 11, 19] * 4, [3, 5, 9, 13] * 4, [3, 9, 11, 15] * 4

FUNC_KIND = ['F', 'G', 'H']


def msgidx(step):
    return ORDER[step // 16][step % 16]


def shift_of(step):
    return SHIFT[step // 16][step % 16]


def func_kind(step):
    return FUNC_KIND[step // 16]


def chain_block(step, regs, fR, rotR, kR, msgBaseR, addrR):
    A, B, C, D = regs
    kind = func_kind(step)
    mi = msgidx(step)
    s = shift_of(step)
    off = mi * 16
    lines = []
    lines.append('\t// step %d %s msg=%s(off=%d) s=%d A=%s' % (step, kind, msgBaseR, off, s, A))
    if kind == 'F':
        lines.append('\tVMOV %s.B16, %s.B16' % (B, fR))
        lines.append('\tVBSL %s.B16, %s.B16, %s.B16' % (D, C, fR))
    elif kind == 'G':
        # maj(B,C,D) = (B&C) | (D&(B^C)), computed with fR and rotR as the
        # two scratch registers. rotR is free here: this step's message
        # word is not loaded until after the round function (see below),
        # unlike md5neon_gen.py which loads it first.
        lines.append('\tVEOR %s.B16, %s.B16, %s.B16' % (B, C, fR))          # fR = B^C
        lines.append('\tVAND %s.B16, %s.B16, %s.B16' % (D, fR, fR))         # fR = D&(B^C)
        lines.append('\tVAND %s.B16, %s.B16, %s.B16' % (B, C, rotR))        # rotR = B&C
        lines.append('\tVORR %s.B16, %s.B16, %s.B16' % (fR, rotR, fR))      # fR = maj(B,C,D)
    else:  # H
        lines.append('\tVEOR %s.B16, %s.B16, %s.B16' % (B, C, fR))
        lines.append('\tVEOR %s.B16, %s.B16, %s.B16' % (fR, D, fR))
    # Load this step's message word now — after the round function, not
    # before, so G's extra AND above can borrow rotR while it is still
    # free. addrR/rotR have no dependency on the round function, so this
    # reorder changes nothing but register lifetime.
    lines.append('\tADD $%d, %s, %s' % (off, msgBaseR, addrR))
    lines.append('\tVLD1 (%s), [%s.S4]' % (addrR, rotR))
    # A = A + f   (accumulate in place; old A value is dead after this read)
    lines.append('\tVADD %s.S4, %s.S4, %s.S4' % (A, fR, A))
    # A += K (per-pass constant, shared by all chains; zero in pass 1, but
    # added unconditionally for a uniform, simpler step shape)
    lines.append('\tVADD %s.S4, %s.S4, %s.S4' % (A, kR, A))
    # A += M   (rotR currently holds the freshly loaded message word)
    lines.append('\tVADD %s.S4, %s.S4, %s.S4' % (A, rotR, A))
    # rotate left by s (rotR reused; message value already consumed)
    lines.append('\tVSHL $%d, %s.S4, %s.S4' % (s, A, rotR))
    lines.append('\tVSRI $%d, %s.S4, %s.S4' % (32 - s, A, rotR))
    # MD4's step has no trailing "+ b": newB is simply the rotated sum,
    # moved (not added) into A's now-dead register (this step's retiree).
    lines.append('\tVMOV %s.B16, %s.B16' % (rotR, A))
    lines.append('')
    return lines, [D, A, B, C]


HEADER = '''// Code generated by md4neon_gen.py. DO NOT EDIT BY HAND — edit md4neon_gen.py
// and regenerate with `python3 md4neon_gen.py` from this directory.
//
// Sibling of md5neon_arm64.s (see md5neon_gen.py), retargeted at MD4: five
// independent 4-way NEON MD4 chains, software-pipelined so the
// out-of-order core overlaps their serial-dependency latency (MD4's 48
// steps are one long dependency chain per message, so throughput comes
// from independent work in flight, not from one faster hash). Register
// budget is 6 vector regs/chain (state A,B,C,D + f-temp + rotate-temp,
// same as MD5) + 1 shared (K-temp; MD4 has no round 4, so unlike MD5 no
// shared all-ones register is needed either) = 6*5+1 = 31 of 32 registers
// — one to spare, versus MD5's exact 32/32 fit. See md4neon_gen.py's
// module docstring for how round 2's majority function fits in the same
// per-chain budget as MD5's rounds despite needing an extra temp: it
// borrows the rotate/message-load register, which this core frees before
// the round function runs by loading the message word after computing F/
// G/H rather than before.
//
// The msg parameter typing mirrors md5neon_arm64.go: the production Go
// declaration in md4neon_arm64.go takes msg0..msg4 as *uint32, pointing
// directly at transposedBatch.words[c*64], rather than *[16][4]uint32 —
// the assembly only ever does byte-offset loads from that address, so the
// pointee type is immaterial to it; go vet's asmdecl check only compares
// argument sizes/offsets, which are identical for any pointer.
#include "textflag.h"

// func %(funcname)s(%(outlist)s *[4][4]uint32, %(msglist)s *uint32, kvec *[3][4]uint32, ivvec *[4][4]uint32)
TEXT ·%(funcname)s(SB), NOSPLIT, $0-%(argsz)d
%(prologue)s

%(load_state)s

'''


def generate(n, funcname, outpath):
    # One register reserved (K-temp); no second hole needed (no all-ones
    # constant, unlike MD5's I round).
    K_REG = 31
    pool = [i for i in range(32) if i != K_REG]
    assert n * 6 <= len(pool), 'too many chains for register budget'

    chain_regs = []   # per chain: (state[4], fR, rotR)
    for c in range(n):
        base = pool[c*6:(c+1)*6]
        state = ['V%d' % r for r in base[0:4]]
        fR = 'V%d' % base[4]
        rotR = 'V%d' % base[5]
        chain_regs.append([state, fR, rotR])

    kR = 'V%d' % K_REG

    # GPRs
    out_regs = ['R%d' % i for i in range(n)]
    msg_regs = ['R%d' % (n + i) for i in range(n)]
    kvec_reg = 'R%d' % (2 * n)
    iv_reg = 'R%d' % (2 * n + 1)
    addr_regs = ['R%d' % (2 * n + 2 + i) for i in range(n)]
    ivaddr_reg = 'R%d' % (2 * n + 2 + n)

    lines = []
    for step in range(48):
        if step % 16 == 0:
            p = step // 16
            lines.append('\tVLD1.P 16(%s), [%s.S4] // K[pass %d]=0x%08x, shared by all %d chains' %
                          (kvec_reg, kR, p, KPASS[p], n))
        for c in range(n):
            state, fR, rotR = chain_regs[c]
            blk, newstate = chain_block(step, state, fR, rotR, kR,
                                         msg_regs[c], addr_regs[c])
            lines += blk
            chain_regs[c][0] = newstate

    body = '\n'.join(lines)

    argsz = 8 * (n + n + 1 + 1)  # out ptrs + msg ptrs + kvec + ivvec
    prologue = []
    off = 0
    for i in range(n):
        prologue.append('\tMOVD out%d+%d(FP), %s' % (i, off, out_regs[i])); off += 8
    for i in range(n):
        prologue.append('\tMOVD msg%d+%d(FP), %s' % (i, off, msg_regs[i])); off += 8
    prologue.append('\tMOVD kvec+%d(FP), %s' % (off, kvec_reg)); off += 8
    prologue.append('\tMOVD ivvec+%d(FP), %s' % (off, iv_reg)); off += 8

    # Same word-by-word IV load-in / final store as md5neon_gen.py: chain
    # state registers are not contiguous (carved from a 31-register pool
    # with one hole at the K-temp), and ARM64's multi-register LD1/ST1
    # list form requires contiguous register numbers.
    load_state = []
    for w in range(4):
        load_state.append('\tADD $%d, %s, %s' % (w * 16, iv_reg, ivaddr_reg))
        for c in range(n):
            base = pool[c*6:(c+1)*6]
            r = base[w]
            load_state.append('\tVLD1 (%s), [V%d.S4]' % (ivaddr_reg, r))

    header = HEADER % {
        'funcname': funcname,
        'outlist': ', '.join('out%d' % i for i in range(n)),
        'msglist': ', '.join('msg%d' % i for i in range(n)),
        'argsz': argsz,
        'prologue': '\n'.join(prologue),
        'load_state': '\n'.join(load_state),
    }

    # Footer: add the initial MD4 state back into each chain's final state.
    # K's shared register is free again once the 48-step loop is done, so
    # it is reused (as md5neon_gen.py reuses its own K-temp) to reload the
    # IV one word at a time rather than reserving a dedicated register for
    # it across the whole run.
    footer_lines = []
    for w in range(4):
        footer_lines.append('\tADD $%d, %s, %s' % (w * 16, iv_reg, ivaddr_reg))
        footer_lines.append('\tVLD1 (%s), [%s.S4]' % (ivaddr_reg, kR))
        for c in range(n):
            base = pool[c*6:(c+1)*6]
            r = base[w]
            footer_lines.append('\tVADD V%d.S4, %s.S4, V%d.S4' % (r, kR, r))
    for c in range(n):
        base = pool[c*6:(c+1)*6]
        for w in range(4):
            r = base[w]
            footer_lines.append('\tADD $%d, %s, %s' % (w * 16, out_regs[c], ivaddr_reg))
            footer_lines.append('\tVST1 [V%d.S4], (%s)' % (r, ivaddr_reg))
    footer_lines.append('\tRET')

    with open(outpath, 'w') as f:
        f.write(header)
        f.write(body)
        f.write('\n'.join(footer_lines))
        f.write('\n')
    print('generated', outpath, 'n=', n, 'vregs/chain=6 total=', 6*n+1)


if __name__ == '__main__':
    outdir = os.path.dirname(os.path.abspath(__file__))
    generate(5, 'md4g20NEON', os.path.join(outdir, 'md4neon_arm64.s'))
