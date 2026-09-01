"""Generator for md5avx2_amd64.s — a pipelined N-chain x 8-lane AVX2 MD5
core. Spike deliverable: answers "can AVX2 beat crypto/md5 by >=3x on
x86-64", modelled on the NEON generator at
hashsmith/go_hashsmith/cmd/hashsmith/md5neon_gen.py (read that file's
register-budget commentary first — this port follows the same shape:
N independent chains, each processing 8 lanes of one MD5 message in
parallel via a single YMM register per state word, software-pipelined so
the out-of-order core overlaps the 64-step serial dependency chain across
chains rather than within one).

=== Register budget (the whole point of this generator's parameter) ===

Per chain: state A,B,C,D (4 YMM) + one scratch register T (1 YMM) = 5.
That 5th register is the true minimum, not merely convenient: MD5's step
function relabels registers each step (new A = old D unchanged, new D =
old C unchanged, new C = old B unchanged, new B = computed) — so B, C, D's
*physical* register contents must survive the step untouched for reuse as
next step's C, D, A. Only the current A's slot is ever overwritten with a
freshly computed value. That leaves one register "free" to use as scratch
(T), but no fewer: the function-round value (F/G/H/I) and the
rotate-left intermediate both need a temporary, and since the function
value is fully consumed (added into A) before the rotate needs a
temporary, T is reused sequentially for both — never simultaneously — so
one scratch register suffices and no second is needed.

Unlike the NEON core, this generator needs **no shared registers at all**
across chains:
  - The message word M[g] and round constant K[step] are both added
    straight from memory via AVX2's memory-operand VPADDD form (proven:
    `VPADDD (BX), Y0, Y1` assembles) — x86's flat base+disp32 addressing
    means no address-computation instruction and no register is spent
    holding the loaded value, unlike NEON's VLD1-then-VADD two-step which
    needed a dedicated load register per chain.
  - The all-ones constant the I round needs (I(b,c,d) = c ^ (b | ~d), and
    x86 has no single-instruction NOT, only VPANDN which computes
    ~src1 & src2 — not the ~d alone this round needs) is also referenced
    straight from memory (`VPXOR (allonesReg), D, T` = ~D) rather than
    held in a shared register the way NEON's V25 held it.
  - The IV is loaded once at entry and stored once at exit via a Go-side
    broadcast array pointer (ivvec), exactly like NEON's ivvec — no
    register is reserved for it across the 64-step loop.

So the budget is exactly 5 YMM/chain, 0 shared: N*5 <= 16. That puts the
ceiling at N=3 (15/16, one register to spare) — N=4 would need 20. This
generator takes N as a parameter specifically to let the spike probe that
ceiling rather than assume it.

=== F/G round function: an XOR identity, not VPANDN ===

VPANDN *is* proven to assemble and does give ~b&d in one instruction (see
the spike's proven-facts list) — but wiring F = (b&c)|(~b&d) up via
AND/ANDN/OR directly costs 2 scratch registers (one holds the ANDN result,
another the AND result, before they can be ORed together), which blows the
5-register-per-chain budget the ceiling above depends on. Using the
standard bit-select identity instead —
    F(b,c,d) = d ^ (b & (c^d))
    G(b,c,d) = c ^ (d & (b^c))     (same identity, mask swapped to d)
— computes F/G in 3 VPXOR/VPAND ops using only the single T register,
matching H's natural 2-op VPXOR/VPXOR shape and I's 3-op shape above. This
is the same bit-select-without-a-mask-instruction trick NEON's VBSL
implements as one hardware op; x86 has no bit-select instruction (VPBLENDVB
is byte-granularity, not bit-granularity, so it cannot implement it), so
this identity is the register-minimal substitute. VPANDN goes unused in
the final core — not because it doesn't work, but because the identity
above wins on the metric that actually gates the chain count.

Regenerate with: `python3 md5avx2_gen.py` from this directory. Do not
hand-edit md5avx2_amd64.s — edit this file and regenerate instead.
"""

import os

S = [7,12,17,22]*4 + [5,9,14,20]*4 + [4,11,16,23]*4 + [6,10,15,21]*4

LANES = 8  # AVX2: one YMM = 8x uint32


def msgidx(step):
    i = step % 16
    if step < 16:
        return i
    elif step < 32:
        return (5 * i + 1) % 16
    elif step < 48:
        return (3 * i + 5) % 16
    else:
        return (7 * i) % 16


def func_kind(step):
    if step < 16: return 'F'
    if step < 32: return 'G'
    if step < 48: return 'H'
    return 'I'


def chain_block(step, regs, T, msg_reg, kvec_reg, allones_reg):
    A, B, C, D = regs
    kind = func_kind(step)
    mi = msgidx(step)
    s = S[step]
    moff = mi * LANES * 4
    koff = step * LANES * 4
    lines = []
    lines.append('\t// step %d %s msg=%d(%s) K=%d(%s) s=%d A=%s' %
                  (step, kind, moff, msg_reg, koff, kvec_reg, s, A))
    if kind == 'F':
        lines.append('\tVPXOR %s, %s, %s' % (D, C, T))     # T = C^D
        lines.append('\tVPAND %s, %s, %s' % (B, T, T))     # T = B&(C^D)
        lines.append('\tVPXOR %s, %s, %s' % (D, T, T))     # T = D^(B&(C^D)) = F
    elif kind == 'G':
        lines.append('\tVPXOR %s, %s, %s' % (C, B, T))     # T = B^C
        lines.append('\tVPAND %s, %s, %s' % (D, T, T))     # T = D&(B^C)
        lines.append('\tVPXOR %s, %s, %s' % (C, T, T))     # T = C^(D&(B^C)) = G
    elif kind == 'H':
        lines.append('\tVPXOR %s, %s, %s' % (C, B, T))     # T = B^C
        lines.append('\tVPXOR %s, %s, %s' % (D, T, T))     # T = B^C^D = H
    else:  # I: T = ~D (from memory), T = B|T, T = T^C
        lines.append('\tVPXOR (%s), %s, %s' % (allones_reg, D, T))  # T = ~D
        lines.append('\tVPOR %s, %s, %s' % (B, T, T))               # T = B|~D
        lines.append('\tVPXOR %s, %s, %s' % (C, T, T))              # T = C^(B|~D) = I
    # A = A + f(B,C,D)   (old A is dead after this read)
    lines.append('\tVPADDD %s, %s, %s' % (T, A, A))
    # A += K[step], streamed straight from memory — costs no register
    lines.append('\tVPADDD %d(%s), %s, %s' % (koff, kvec_reg, A, A))
    # A += M[g], streamed straight from memory — costs no register
    lines.append('\tVPADDD %d(%s), %s, %s' % (moff, msg_reg, A, A))
    # rotate left by s: T = A<<s (A untouched), then A >>= (32-s) in place
    # (A's sum value is dead once T holds A<<s), then T |= A.
    lines.append('\tVPSLLD $%d, %s, %s' % (s, A, T))
    lines.append('\tVPSRLD $%d, %s, %s' % (32 - s, A, A))
    lines.append('\tVPOR %s, %s, %s' % (A, T, T))
    # newB = B + rotated, written into A's register (this step's retiree)
    lines.append('\tVPADDD %s, %s, %s' % (T, B, A))
    lines.append('')
    return lines, [D, A, B, C]


HEADER = '''// Code generated by md5avx2_gen.py. DO NOT EDIT BY HAND — edit
// md5avx2_gen.py and regenerate with `python3 md5avx2_gen.py` from this
// directory.
//
// AVX2 spike core: %(n)d independent 8-lane MD5 chains (%(group)d candidates
// in flight per call), software-pipelined so the out-of-order core overlaps
// each chain's 64-step serial dependency latency with the others' — see
// md5avx2_gen.py's module docstring for the full register-budget
// derivation (5 YMM/chain, 0 shared, ceiling N=3 in 16 YMM).
//
// Message layout per chain: word-major, lane-minor [16][8]uint32 — word g
// at byte offset g*32. K layout: [64][8]uint32, step s at byte offset
// s*32, each K value pre-broadcast to all 8 lanes by the Go side. State
// in/out layout: [4][8]uint32, word w at byte offset w*32. allones is a
// single broadcast [8]uint32 of 0xffffffff, referenced by the I round only.
#include "textflag.h"

// func %(funcname)s(%(outlist)s *[4][8]uint32, %(msglist)s *[16][8]uint32, kvec *[64][8]uint32, ivvec *[4][8]uint32, allones *[8]uint32)
TEXT ·%(funcname)s(SB), NOSPLIT, $0-%(argsz)d
%(prologue)s

%(load_state)s
'''

GPR_POOL = ['AX', 'BX', 'CX', 'DX', 'SI', 'DI',
            'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']


def generate(n, funcname, outpath):
    assert n * 5 <= 16, 'too many chains for the 16-YMM budget'
    assert 2 * n + 3 <= len(GPR_POOL), 'too many chains for available GPRs'

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
    allones_reg = GPR_POOL[2 * n + 2]

    # --- prologue: load args ---
    argsz = 8 * (n + n + 1 + 1 + 1)  # out ptrs + msg ptrs + kvec + ivvec + allones
    prologue = []
    off = 0
    for i in range(n):
        prologue.append('\tMOVQ out%d+%d(FP), %s' % (i, off, out_regs[i])); off += 8
    for i in range(n):
        prologue.append('\tMOVQ msg%d+%d(FP), %s' % (i, off, msg_regs[i])); off += 8
    prologue.append('\tMOVQ kvec+%d(FP), %s' % (off, kvec_reg)); off += 8
    prologue.append('\tMOVQ ivvec+%d(FP), %s' % (off, ivvec_reg)); off += 8
    prologue.append('\tMOVQ allones+%d(FP), %s' % (off, allones_reg)); off += 8

    # --- load IV into every chain's state registers ---
    # x86's flat base+disp32 addressing lets every chain load word w
    # straight from ivvec+w*32 with no address-computation instruction
    # (unlike NEON, which needed a separate ADD before each VLD1).
    load_state = []
    for c in range(n):
        state, _T = chain_regs[c]
        for w in range(4):
            load_state.append('\tVMOVDQU %d(%s), %s' % (w * LANES * 4, ivvec_reg, state[w]))

    # --- 64-step body ---
    lines = []
    for step in range(64):
        for c in range(n):
            state, T = chain_regs[c]
            blk, newstate = chain_block(step, state, T, msg_regs[c], kvec_reg, allones_reg)
            lines += blk
            chain_regs[c][0] = newstate
    body = '\n'.join(lines)

    # --- footer: add chaining value back (straight from ivvec memory, no
    # temp register needed) and store final state to each chain's out ---
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
          'yregs/chain=5 total=', 5 * n, 'gprs=', 2 * n + 3)


if __name__ == '__main__':
    outdir = os.path.dirname(os.path.abspath(__file__))
    outpath = os.path.join(outdir, 'md5avx2_amd64.s')
    with open(outpath, 'w') as f:
        pass  # truncate; generate() appends per-function below via manual concat

    n2 = generate(2, 'md5g16AVX2', os.path.join(outdir, '_n2.s.tmp'))
    n3 = generate(3, 'md5g24AVX2', os.path.join(outdir, '_n3.s.tmp'))

    with open(outpath, 'w') as out:
        with open(os.path.join(outdir, '_n2.s.tmp')) as f2:
            out.write(f2.read())
        out.write('\n')
        with open(os.path.join(outdir, '_n3.s.tmp')) as f3:
            # Both chunks carry their own HEADER (including
            # #include "textflag.h"), since each is independently
            # regeneratable/readable on its own. Concatenated into one
            # file that would redefine the header's NOPROF etc. macros a
            # second time, which the assembler's C-style preprocessor
            # rejects — so strip the second chunk's include line only.
            out.write(f3.read().replace('#include "textflag.h"\n', '', 1))
    os.remove(os.path.join(outdir, '_n2.s.tmp'))
    os.remove(os.path.join(outdir, '_n3.s.tmp'))
    print('combined into', outpath)
