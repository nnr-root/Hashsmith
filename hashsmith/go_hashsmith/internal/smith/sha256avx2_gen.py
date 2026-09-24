"""Generator for sha256avx2_amd64.s — an 8-lane AVX2 SHA-256 compression
core, N=1 chain. Modelled on md5avx2_gen.py's generator pattern (same
HEADER/prologue/footer shape, same "generate assembly, don't hand-write it"
discipline) but for a materially different round function and register
budget — read that file's docstring first for the shared conventions this
one does not repeat.

=== Register budget ===

8 state registers (a..h — SHA-256 has twice MD5's 4) plus 4 scratch
(T0-T3, derived below) = 12 YMM/chain. N*12 <= 16 caps this at N=1 — unlike
MD5's N=3, there is no room for a second chain even with aggressive scratch
reduction (2 chains at even a tight 8 scratch total would need 2*10=20).
This generator does not take N as a parameter for that reason: N=1 is not a
starting point to search from, it is the only value that fits.

=== Round function, derived from scratch (why 4 temps, not fewer) ===

Standard formulation:
    T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
    T2 = Sigma0(a) + Maj(a,b,c)
    h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2

Ch(e,f,g) = g ^ (e & (f^g)) — the same bit-select-without-a-mask-instruction
identity md5avx2_gen.py uses for F/G, so it costs the same 3 ops / 1 temp:
    T = f^g; T = e&T; T = g^T.

Maj(a,b,c) has no equivalent 2-op reduction. Using the identity
Maj(a,b,c) = (a&b) ^ (c&(a^b)) (verified by truth table below) needs 2 temps
simultaneously, since a^b and a&b must both be live before combining:
    U = a^b; V = a&b; U = c&U; U = U^V.       (4 ops, 2 temps: U, V)
Truth table check, all 8 inputs of (a,b,c):
  000->0/0  001->0/0  010->0/0  011->1/1  100->0/0  101->1/1  110->1/1  111->1/1
  (left = Maj(a,b,c), right = (a&b)^(c&(a^b))) — they agree on all 8, so the
  identity is exact, not an approximation.

Sigma1(e) = ROTR(e,6)^ROTR(e,11)^ROTR(e,25). AVX2 has no rotate instruction
for 32-bit lanes, so each ROTR(x,n) is VPSRLD+VPSLLD+VPOR — 2 temps (one
for each shifted half) before the OR, and a third register to accumulate
across the three XORed terms without those two builder temps colliding with
the running total:
    ACC = x>>n0; B = x<<(32-n0); ACC = ACC|B            (first term direct)
    B = x>>n1; C = x<<(32-n1); B = B|C; ACC = ACC^B      (second term)
    B = x>>n2; C = x<<(32-n2); B = B|C; ACC = ACC^B      (third term)
That is 3 registers (ACC, B, C) for one Sigma. Sigma0(a) needs the same
shape and, since Sigma1's result must survive into T1's sum (read after
Sigma0/Maj are computed for T2), it is computed with a **separate**
accumulator from Sigma1's, but the two builder registers ARE reused between
Sigma1 and Sigma0 (they hold no state that needs to survive across the
switch). So: 2 accumulators (Sigma1-result, Sigma0-or-Maj-result — Ch and
Maj also reuse the builder pair rather than adding a fifth register) +
2 builders = 4 scratch registers total, named T0-T3 below:
    T0 = Sigma1(e), then accumulates Ch(e,f,g), h, K[t], W[t] in place
         (becomes "T1round")
    T1 = Sigma0(a), then Maj(a,b,c) is computed into it and added
         (becomes "T2round")
    T2, T3 = builders, reused throughout for whichever rotation/Ch/Maj
         term is currently being assembled

=== State update: relabeling, not copying ===

Only e and a get NEW values each round (e_new = d+T1round, a_new =
T1round+T2round); every other new_X is a pure rename of an old register
(new_h=old_g, new_g=old_f, new_f=old_e, new_d=old_c, new_c=old_b,
new_b=old_a) — old_h's value is fully consumed into T1round and never
carried forward. Exactly like md5avx2_gen.py's chain_block return value
reorders which physical register plays which role for the next step with
zero copy instructions, this generator writes e_new IN PLACE into the
register that held d (d is not read for anything else this round) and
a_new IN PLACE into the register that held h (h is fully dead after being
read into T1round) — so the whole state update is two VPADDD writes plus a
Python-side rotation of the 8-element register-role list, no MOV/copy
instructions at all.

=== Message schedule: precomputed in Go, not expanded here ===

Unlike MD5's fixed 16-word permutation (a lookup, no computation),
SHA-256's schedule needs a real expansion (w[16..63] from earlier words via
sigma0/sigma1) that would materially complicate this generator's hot loop.
The Go side expands the full 64-word schedule once per block into a
[64][8]uint32 array (mirroring K's own [64][8]uint32 layout, each word
pre-broadcast to all 8 lanes) and this core reads it via a memory operand
exactly like K — see sha256_schedule.go's scalarSHA256Schedule, which this
core's Go-side caller must use to fill the buffer this reads.

Regenerate with: `python3 sha256avx2_gen.py` from this directory. Do not
hand-edit sha256avx2_amd64.s — edit this file and regenerate instead.
"""

import os

LANES = 8  # AVX2: one YMM = 8x uint32

# (Sigma1 rotate amounts, Sigma0 rotate amounts) per FIPS 180-4 Sec 4.1.2.
SIGMA1_ROTS = (6, 11, 25)
SIGMA0_ROTS = (2, 13, 22)

STATE_NAMES = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']


def sigma(dst, x, rots, t2, t3, first_op):
    """Emit ACC=dst := ROTR(x,rots[0]) ^ ROTR(x,rots[1]) ^ ROTR(x,rots[2]),
    using t2/t3 as builder scratch. first_op is 'set' (dst := first term,
    used when dst has no prior live value) — always 'set' here since both
    Sigma call sites start a fresh accumulator."""
    assert first_op == 'set'
    lines = []
    n0, n1, n2 = rots
    lines.append('\tVPSRLD $%d, %s, %s' % (n0, x, dst))
    lines.append('\tVPSLLD $%d, %s, %s' % (32 - n0, x, t2))
    lines.append('\tVPOR %s, %s, %s' % (t2, dst, dst))
    for n in (n1, n2):
        lines.append('\tVPSRLD $%d, %s, %s' % (n, x, t2))
        lines.append('\tVPSLLD $%d, %s, %s' % (32 - n, x, t3))
        lines.append('\tVPOR %s, %s, %s' % (t3, t2, t2))
        lines.append('\tVPXOR %s, %s, %s' % (t2, dst, dst))
    return lines


def round_block(step, regs, T, msg_reg, kvec_reg):
    """regs is the current [a,b,c,d,e,f,g,h] register-role list (8 YMM
    names). T is [T0,T1,T2,T3]. Returns (asm_lines, new_regs) where
    new_regs is regs rotated by one position with e's and a's slots holding
    freshly written registers — the relabeling described in the module
    docstring."""
    a, b, c, d, e, f, g, h = regs
    T0, T1, T2, T3 = T
    woff = step * LANES * 4
    koff = step * LANES * 4
    lines = ['\t// round %d  a=%s b=%s c=%s d=%s e=%s f=%s g=%s h=%s' %
             (step, a, b, c, d, e, f, g, h)]

    # T0 = Sigma1(e)
    lines += sigma(T0, e, SIGMA1_ROTS, T2, T3, 'set')
    # T2 = Ch(e,f,g) = g ^ (e & (f^g))
    lines.append('\tVPXOR %s, %s, %s' % (g, f, T2))   # T2 = f^g
    lines.append('\tVPAND %s, %s, %s' % (e, T2, T2))  # T2 = e&(f^g)
    lines.append('\tVPXOR %s, %s, %s' % (g, T2, T2))  # T2 = Ch(e,f,g)
    # T0 = Sigma1(e) + Ch(e,f,g) + h + K[t] + W[t]  ("T1round")
    lines.append('\tVPADDD %s, %s, %s' % (T2, T0, T0))
    lines.append('\tVPADDD %s, %s, %s' % (h, T0, T0))
    lines.append('\tVPADDD %d(%s), %s, %s' % (koff, kvec_reg, T0, T0))
    lines.append('\tVPADDD %d(%s), %s, %s' % (woff, msg_reg, T0, T0))

    # T1 = Sigma0(a)
    lines += sigma(T1, a, SIGMA0_ROTS, T2, T3, 'set')
    # T2 = Maj(a,b,c) = (a&b) ^ (c&(a^b))
    lines.append('\tVPXOR %s, %s, %s' % (b, a, T2))   # T2 = a^b
    lines.append('\tVPAND %s, %s, %s' % (b, a, T3))   # T3 = a&b
    lines.append('\tVPAND %s, %s, %s' % (T2, c, T2))  # T2 = c&(a^b)
    lines.append('\tVPXOR %s, %s, %s' % (T3, T2, T2))  # T2 = Maj(a,b,c)
    # T1 = Sigma0(a) + Maj(a,b,c)  ("T2round")
    lines.append('\tVPADDD %s, %s, %s' % (T2, T1, T1))

    # new_e := d + T1round, written in place into d's register (d is not
    # read for anything else this round).
    lines.append('\tVPADDD %s, %s, %s' % (T0, d, d))
    # new_a := T1round + T2round, written in place into h's register (h is
    # fully dead after being consumed into T0 above).
    lines.append('\tVPADDD %s, %s, %s' % (T1, T0, h))
    lines.append('')

    new_regs = [h, a, b, c, d, e, f, g]  # rotate: new a is old h's reg (now
    # holding a_new), new b..d are old a..c unchanged, new e is old d's reg
    # (now holding e_new), new f..h are old e..g unchanged.
    return lines, new_regs


HEADER = '''// Code generated by sha256avx2_gen.py. DO NOT EDIT BY HAND — edit
// sha256avx2_gen.py and regenerate with `python3 sha256avx2_gen.py` from
// this directory.
//
// AVX2 8-lane SHA-256 compression core, one chain (%(group)d candidates in
// flight per call) — see sha256avx2_gen.py's module docstring for the full
// register-budget derivation (8 state + 4 scratch = 12 YMM, N=1 is the only
// chain count that fits in 16 YMM for this round function).
//
// Message layout: word-major, lane-minor [64][8]uint32 — the FULLY EXPANDED
// 64-word schedule (see sha256_schedule.go), word t at byte offset t*32.
// K layout: [64][8]uint32, step t at byte offset t*32, each K value
// pre-broadcast to all 8 lanes by the Go side, exactly like MD5's kvec.
// State in/out layout: [8][8]uint32, word w (a..h, index 0..7) at byte
// offset w*32.
#include "textflag.h"

// func %(funcname)s(out *[8][8]uint32, msg *[64][8]uint32, kvec *[64][8]uint32, ivvec *[8][8]uint32)
TEXT ·%(funcname)s(SB), NOSPLIT, $0-32
	MOVQ out+0(FP), AX
	MOVQ msg+8(FP), BX
	MOVQ kvec+16(FP), CX
	MOVQ ivvec+24(FP), DX

%(load_state)s
'''

STATE_REGS = ['Y0', 'Y1', 'Y2', 'Y3', 'Y4', 'Y5', 'Y6', 'Y7']
SCRATCH_REGS = ['Y8', 'Y9', 'Y10', 'Y11']


def generate(funcname, outpath):
    regs = list(STATE_REGS)
    T = list(SCRATCH_REGS)

    load_state = []
    for w in range(8):
        load_state.append('\tVMOVDQU %d(DX), %s' % (w * LANES * 4, regs[w]))

    lines = []
    for step in range(64):
        blk, regs = round_block(step, regs, T, 'BX', 'CX')
        lines += blk
    body = '\n'.join(lines)

    # regs now holds the final [a,b,c,d,e,f,g,h] register-role list — add
    # the chaining value back (straight from ivvec memory, matching MD5's
    # footer) and store to out, in STATE order (index 0=a .. 7=h), not
    # physical-register order.
    footer_lines = []
    for w in range(8):
        footer_lines.append('\tVPADDD %d(DX), %s, %s' % (w * LANES * 4, regs[w], regs[w]))
    for w in range(8):
        footer_lines.append('\tVMOVDQU %s, %d(AX)' % (regs[w], w * LANES * 4))
    footer_lines.append('\tVZEROUPPER')
    footer_lines.append('\tRET')

    header = HEADER % {
        'funcname': funcname,
        'group': LANES,
        'load_state': '\n'.join(load_state),
    }

    with open(outpath, 'w') as f:
        f.write(header)
        f.write('\n')
        f.write(body)
        f.write('\n'.join(footer_lines))
        f.write('\n')
    print('generated', outpath, 'group=', LANES, 'yregs= 12 (8 state + 4 scratch)')


if __name__ == '__main__':
    outdir = os.path.dirname(os.path.abspath(__file__))
    outpath = os.path.join(outdir, 'sha256avx2_amd64.s')
    generate('sha256g8AVX2', outpath)
