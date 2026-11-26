// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! x86-64 instruction decode: legacy and REX prefixes, ModRM/SIB and
//! address-size handling, immediates, and the routing of an opcode to an
//! `Op` (plus, for SSE, its sub-op). The decoder reads exactly the bytes the
//! instruction needs, byte by byte through the MMU, so a fetch fault is
//! reported on the byte that faults and never ahead of the instruction.
//!
//! The decoded form (`Insn`) keeps the architectural operands as ModRM
//! fields; exec.zig reads them (all faulting reads before any
//! architectural write, so a faulting instruction has no effect). An
//! encoding this file does not know sets `op = .invalid` and exec.zig
//! raises KW_EV_ILLEGAL with the raw bytes.

const std = @import("std");
const common = @import("common.zig");
const state = @import("state.zig");

pub const Op = enum(u8) {
    invalid,
    // integer ALU and data movement
    add,
    or_,
    adc,
    sbb,
    and_,
    sub,
    xor_,
    cmp,
    test_,
    mov,
    movzx,
    movsx,
    movsxd,
    lea,
    xchg,
    push,
    pop,
    inc,
    dec,
    neg,
    not,
    mul,
    imul,
    div,
    idiv,
    shl,
    shr,
    sar,
    rol,
    ror,
    rcl,
    rcr,
    shld,
    shrd,
    bt,
    bts,
    btr,
    btc,
    bsf,
    bsr,
    tzcnt,
    lzcnt,
    popcnt,
    jmp,
    jcc,
    call,
    ret,
    loopne,
    loope,
    loop,
    jrcxz,
    cmovcc,
    setcc,
    movs,
    stos,
    lods,
    scas,
    cmps,
    cmpxchg,
    xadd,
    cmpxchg8b,
    cmpxchg16b,
    cbw,
    cwd,
    pushf,
    popf,
    sahf,
    lahf,
    leave,
    enter,
    int3,
    int_n,
    hlt,
    ud2,
    endbr,
    syscall,
    cpuid,
    rdtsc,
    rdtscp,
    xgetbv,
    clc,
    stc,
    cmc,
    cld,
    std,
    cli,
    sti,
    nop,
    bswap,
    mfence,
    lfence,
    sfence,
    fxsave,
    fxrstor,
    xsave,
    xrstor,
    pause,
    xlat,
    movnti,
    rdssp,
    sse,
    fpu,
};

/// SSE/SSE2 sub-ops. `sse` instructions use the ModRM fields of `Insn` too.
pub const Sse = enum(u8) {
    movups,
    movupd,
    movss,
    movsd,
    movaps,
    movapd,
    movdqa,
    movdqu,
    movd,
    movq,
    movlps,
    movhps,
    movhlps,
    movlhps,
    movmskps,
    movmskpd,
    movntps,
    movntpd,
    movntdq,
    movnti,
    movntq,
    maskmovdqu,
    movsldup,
    movshdup,
    movddup,
    lddqu,
    unpcklps,
    unpcklpd,
    unpckhps,
    unpckhpd,
    shufps,
    shufpd,
    pshufd,
    pshufhw,
    pshuflw,
    pshufw,
    addps,
    addpd,
    addss,
    addsd,
    addsubps,
    addsubpd,
    subps,
    subpd,
    subss,
    subsd,
    mulps,
    mulpd,
    mulss,
    mulsd,
    divps,
    divpd,
    divss,
    divsd,
    minps,
    minpd,
    minss,
    minsd,
    maxps,
    maxpd,
    maxss,
    maxsd,
    sqrtps,
    sqrtpd,
    sqrtss,
    sqrtsd,
    rsqrtps,
    rsqrtss,
    rcpps,
    rcpss,
    andps,
    andpd,
    andnps,
    andnpd,
    orps,
    orpd,
    xorps,
    xorpd,
    cmpps,
    cmppd,
    cmpss,
    cmpsd,
    comiss,
    comisd,
    ucomiss,
    ucomisd,
    cvtsi2ss,
    cvtsi2sd,
    cvttss2si,
    cvttsd2si,
    cvtss2si,
    cvtsd2si,
    cvtss2sd,
    cvtsd2ss,
    cvtdq2ps,
    cvtps2dq,
    cvttps2dq,
    cvtps2pd,
    cvtpd2ps,
    cvtdq2pd,
    cvtpd2dq,
    cvttpd2dq,
    ldmxcsr,
    stmxcsr,
    // packed integer (0x66 forms; the MMX forms are not implemented)
    paddb,
    paddw,
    paddd,
    paddq,
    paddsb,
    paddsw,
    paddusb,
    paddusw,
    psubb,
    psubw,
    psubd,
    psubq,
    psubsb,
    psubsw,
    psubusb,
    psubusw,
    pcmpeqb,
    pcmpeqw,
    pcmpeqd,
    pcmpgtb,
    pcmpgtw,
    pcmpgtd,
    pmullw,
    pmulhw,
    pmulhuw,
    pmuludq,
    pmaddwd,
    pand,
    pandn,
    por,
    pxor,
    pavgb,
    pavgw,
    pminub,
    pminsw,
    pmaxub,
    pmaxsw,
    psadbw,
    psllw,
    pslld,
    psllq,
    psrlw,
    psrld,
    psrlq,
    psraw,
    psrad,
    packsswb,
    packssdw,
    packuswb,
    punpcklbw,
    punpcklwd,
    punpckldq,
    punpcklqdq,
    punpckhbw,
    punpckhwd,
    punpckhdq,
    punpckhqdq,
    pmovmskb,
    pinsrw,
    pextrw,
    pslldq,
    psrldq,
};

/// x87 sub-ops (the small set long double needs; the rest is #UD).
pub const Fpu = enum(u8) {
    fld,
    fst,
    fstp,
    fild,
    fist,
    fistp,
    fadd,
    fsub,
    fmul,
    fdiv,
    fsubr,
    fdivr,
    fiadd,
    fisub,
    fimul,
    fidiv,
    fisubr,
    fidivr,
    faddp,
    fmulp,
    fsubp,
    fsubrp,
    fdivp,
    fdivrp,
    fcom,
    fcomp,
    fcompp,
    fucom,
    fucomp,
    fucomi,
    fucomip,
    fcomi,
    fcomip,
    fldcw,
    fnstcw,
    fnstsw,
    fninit,
    fchs,
    fabs,
    fsqrt,
    fxch,
    ftst,
    fxam,
    fld1,
    fldz,
    fldpi,
    fldl2e,
    fldl2t,
    fldln2,
    fldlg2,
    frndint,
    fscale,
    fprem,
    fucompp,
};

/// Prefixes that change how the rest of the instruction decodes.
pub const Prefix = struct {
    opsz16: bool = false,
    addr32: bool = false,
    lock: bool = false,
    /// 0, 0xF2 (repne) or 0xF3 (rep/repe).
    rep: u8 = 0,
    /// Segment override prefix byte, 0 if none.
    seg: u8 = 0,
    rex: u8 = 0,

    pub inline fn w(p: Prefix) bool {
        return p.rex & 8 != 0;
    }
    pub inline fn rexR(p: Prefix) u4 {
        return @intCast((p.rex >> 2) & 1);
    }
    pub inline fn rexX(p: Prefix) u4 {
        return @intCast((p.rex >> 1) & 1);
    }
    pub inline fn rexB(p: Prefix) u4 {
        return @intCast(p.rex & 1);
    }
};

pub const Insn = struct {
    op: Op = .invalid,
    sse: Sse = .movups,
    fpu: Fpu = .fld,
    len: u8 = 0,
    pfx: Prefix = .{},
    /// 1, 2, 4, 8 (operand size; 8 with REX.W, 2 with 0x66, else 4).
    opsz: u8 = 4,
    /// Operand size of a movzx/movsx source.
    src_sz: u8 = 0,
    /// 0x66 was present (SSE packed-integer forms).
    pfx66: bool = false,
    has_modrm: bool = false,
    md: u2 = 0,
    /// The ModRM.reg field, extended with REX.R (a register operand).
    reg: u4 = 0,
    /// The raw ModRM.reg field (an opcode extension in the group opcodes).
    opx: u3 = 0,
    /// The ModRM.rm field, extended with REX.B.
    rm: u4 = 0,
    mem: bool = false,
    addr32: bool = false,
    rip_rel: bool = false,
    has_base: bool = false,
    base: u4 = 0,
    has_index: bool = false,
    index: u4 = 0,
    scale: u3 = 0,
    disp: i64 = 0,
    /// Effective address, filled in at the end of decode.
    ea: u64 = 0,
    imm: u64 = 0,
    imm2: u64 = 0,
    /// Condition code (jcc/cmovcc/setcc) or an SSE comparison predicate.
    cc: u8 = 0,
    /// Encoding-form discriminator for the shared handlers (the low opcode
    /// bits of an ALU/mov/test form, or 0x80 for the group-1 form).
    form: u8 = 0,
    /// A few encodings need one more discriminator (fence byte, xgetbv, a
    /// movd/movq direction, ...).
    aux: u8 = 0,
    /// First eight bytes of the instruction, little-endian.
    raw: u64 = 0,
};

const max_insn = 15;

const Dec = struct {
    s: common.St,
    p: u64,
    n: u8 = 0,
    raw: u64 = 0,
    ins: *Insn,

    fn byte(d: *Dec) common.DecodeError!u8 {
        if (d.n >= max_insn) return common.invalid(d.s, d.raw);
        const b = try d.s.m.load(u8, d.p);
        if (d.n < 8) d.raw |= @as(u64, b) << @intCast(8 * @as(u6, @intCast(d.n)));
        d.p +%= 1;
        d.n += 1;
        return b;
    }

    fn immN(d: *Dec, n: u8) common.DecodeError!u64 {
        var v: u64 = 0;
        var i: u8 = 0;
        while (i < n) : (i += 1) v |= @as(u64, try d.byte()) << @intCast(8 * i);
        return v;
    }

    fn imm32(d: *Dec) common.DecodeError!u64 {
        return @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(try d.immN(4)))))));
    }

    fn imm8(d: *Dec) common.DecodeError!u64 {
        return @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(try d.immN(1)))))));
    }

    fn modrm(d: *Dec) common.DecodeError!void {
        const b = try d.byte();
        const ins = d.ins;
        ins.has_modrm = true;
        ins.md = @intCast(b >> 6);
        ins.opx = @intCast((b >> 3) & 7);
        ins.reg = @as(u4, ins.opx) | (ins.pfx.rexR() << 3);
        ins.rm = @as(u4, @intCast(b & 7)) | (ins.pfx.rexB() << 3);
        if (ins.md == 3) return;
        ins.mem = true;
        ins.addr32 = ins.pfx.addr32;
        if (b & 7 == 4) {
            const sib = try d.byte();
            ins.scale = @intCast(sib >> 6);
            const idx: u4 = @as(u4, @intCast((sib >> 3) & 7)) | (ins.pfx.rexX() << 3);
            if (idx != 4) {
                ins.has_index = true;
                ins.index = idx;
            }
            const bs: u4 = @as(u4, @intCast(sib & 7)) | (ins.pfx.rexB() << 3);
            if (bs == 5 and ins.md == 0) {
                ins.disp = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(try d.immN(4)))))));
            } else {
                ins.has_base = true;
                ins.base = bs;
            }
        } else if (b & 7 == 5 and ins.md == 0) {
            ins.rip_rel = true;
            ins.disp = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(try d.immN(4)))))));
        } else {
            ins.has_base = true;
            ins.base = ins.rm;
        }
        switch (ins.md) {
            1 => ins.disp += @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(try d.immN(1))))))),
            2 => ins.disp += @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(try d.immN(4))))))),
            else => {},
        }
    }

    /// Effective address. `r.rip` is the next instruction's address by then
    /// (run.zig advances it before exec; decode is called after).
    fn finalizeEA(d: *Dec) void {
        const ins = d.ins;
        if (!ins.mem) return;
        var ea: u64 = @bitCast(ins.disp);
        if (ins.rip_rel) {
            ea = d.s.r.rip +% d.n +% ea;
        } else {
            if (ins.has_base) ea +%= common.gpr(d.s.r, ins.base).*;
            if (ins.has_index) ea +%= common.gpr(d.s.r, ins.index).* << ins.scale;
        }
        if (ins.addr32) ea &= 0xffff_ffff;
        ins.ea = ea;
    }

    fn finish(d: *Dec) void {
        d.ins.raw = d.raw;
        d.ins.len = d.n;
        d.finalizeEA();
    }
};

/// Zero an Insn word by word: a `= .{}` of this size becomes a memset call
/// on wasm, which the kernel does not link.
inline fn zeroInsn(out: *Insn) void {
    comptime std.debug.assert(@sizeOf(Insn) % 8 == 0);
    const p: [*]volatile u64 = @ptrCast(out);
    for (0..@sizeOf(Insn) / 8) |i| p[i] = 0;
}

/// Decode the instruction at `s.r.rip` into `out`. `r.rip` is not
/// modified.
pub fn one(s: common.St, out: *Insn) common.DecodeError!void {
    zeroInsn(out);
    var d: Dec = .{ .s = s, .p = s.r.rip, .ins = out };
    const pfx = &out.pfx;
    while (true) {
        if (d.n >= max_insn) return common.invalid(s, d.raw);
        const b = try d.s.m.load(u8, d.p);
        switch (b) {
            0x66 => pfx.opsz16 = true,
            0x67 => pfx.addr32 = true,
            0xf0 => pfx.lock = true,
            0xf2, 0xf3 => pfx.rep = b,
            0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65 => pfx.seg = b,
            0x40...0x4f => pfx.rex = b,
            else => break,
        }
        if (d.n < 8) d.raw |= @as(u64, b) << @intCast(8 * @as(u6, @intCast(d.n)));
        d.p +%= 1;
        d.n += 1;
    }
    const ins = d.ins;
    ins.pfx66 = pfx.opsz16;
    ins.opsz = if (pfx.w()) 8 else if (pfx.opsz16) 2 else 4;

    const op = try d.byte();
    switch (op) {
        0x00...0x0e, 0x10...0x3d => {
            const grp: u3 = @intCast((op >> 3) & 7);
            switch (op & 7) {
                0, 1, 2, 3 => {
                    try d.modrm();
                    ins.opsz = if (op & 1 == 0) 1 else ins.opsz;
                    ins.op = aluOp(grp);
                    ins.form = op & 7;
                },
                4 => {
                    ins.op = aluOp(grp);
                    ins.opsz = if (op & 1 == 0) 1 else ins.opsz;
                    ins.form = 0x10;
                    ins.imm = if (ins.opsz == 1) (try d.imm8() & 0xff) else if (ins.opsz == 2) @as(u16, @truncate(try d.immN(2))) else (try d.imm32());
                },
                5 => {
                    ins.op = aluOp(grp);
                    ins.form = 0x11;
                    ins.imm = if (ins.opsz == 1 or ins.opsz == 2) @as(u16, @truncate(try d.immN(2))) else (try d.imm32());
                },
                else => {},
            }
        },
        0x50...0x57 => {
            ins.op = .push;
            ins.form = 0x50;
            ins.opsz = if (pfx.opsz16) 2 else 8;
            ins.rm = @as(u4, @intCast(op & 7)) | (pfx.rexB() << 3);
        },
        0x58...0x5f => {
            ins.op = .pop;
            ins.form = 0x58;
            ins.opsz = if (pfx.opsz16) 2 else 8;
            ins.rm = @as(u4, @intCast(op & 7)) | (pfx.rexB() << 3);
        },
        0x63 => {
            try d.modrm();
            ins.op = .movsxd;
            ins.opsz = if (pfx.w()) 8 else 4;
            ins.src_sz = 4;
        },
        0x68 => {
            ins.op = .push;
            ins.form = 0x68;
            ins.opsz = if (pfx.opsz16) 2 else 8;
            if (ins.opsz == 2) {
                ins.imm = try d.immN(2);
            } else {
                ins.imm = try d.imm32();
            }
        },
        0x69 => {
            try d.modrm();
            ins.op = .imul;
            ins.form = 3;
            ins.imm = if (ins.opsz == 2) @as(u16, @truncate(try d.immN(2))) else (try d.imm32());
        },
        0x6a => {
            ins.op = .push;
            ins.form = 0x68;
            ins.opsz = if (pfx.opsz16) 2 else 8;
            ins.imm = try d.imm8();
        },
        0x6b => {
            try d.modrm();
            ins.op = .imul;
            ins.form = 3;
            ins.imm = try d.imm8();
        },
        0x70...0x7f => {
            ins.op = .jcc;
            ins.cc = @intCast(op & 0xf);
            ins.imm = try d.imm8();
        },
        0x80...0x83 => {
            try d.modrm();
            ins.opsz = if (op == 0x80) 1 else ins.opsz;
            ins.op = switch (ins.opx) {
                0 => .add,
                1 => .or_,
                2 => .adc,
                3 => .sbb,
                4 => .and_,
                5 => .sub,
                6 => .xor_,
                7 => .cmp,
            };
            ins.form = 0x10;
            ins.imm = if (op == 0x83) try d.imm8() else if (ins.opsz == 1) (try d.imm8() & 0xff) else if (ins.opsz == 2) @as(u16, @truncate(try d.immN(2))) else (try d.imm32());
        },
        0x84, 0x85 => {
            try d.modrm();
            ins.op = .test_;
            ins.opsz = if (op == 0x84) 1 else ins.opsz;
            ins.form = 0x84;
        },
        0x86, 0x87 => {
            try d.modrm();
            ins.op = .xchg;
            ins.opsz = if (op == 0x86) 1 else ins.opsz;
        },
        0x88...0x8b => {
            try d.modrm();
            ins.op = .mov;
            ins.opsz = if (op & 1 == 0) 1 else ins.opsz;
            ins.form = op & 7;
        },
        0x8c => {
            try d.modrm();
            ins.op = .mov;
            ins.opsz = 2;
            ins.cc = 1; // r/m16 <- selector
        },
        0x8d => {
            try d.modrm();
            ins.op = .lea;
            if (!ins.mem) return common.invalid(s, d.raw);
        },
        0x8e => {
            try d.modrm();
            ins.op = .mov;
            ins.opsz = 2;
            ins.cc = 2; // selector <- r/m16 (ignored)
        },
        0x8f => {
            try d.modrm();
            ins.op = .pop;
            ins.form = 0x8f;
            ins.opsz = if (pfx.opsz16) 2 else 8;
        },
        0x90...0x97 => {
            // 0x90 is NOP only without REX.B; with it the encoding is
            // xchg %rax,%r8 (compilers emit 49 90 for that).
            if (op == 0x90 and pfx.rexB() == 0) {
                ins.op = .nop;
            } else {
                ins.op = .xchg;
                ins.form = 0x90;
                ins.rm = @as(u4, @intCast(op & 7)) | (pfx.rexB() << 3);
            }
        },
        0x98 => ins.op = .cbw,
        0x99 => ins.op = .cwd,
        0x9b => ins.op = .nop,
        0x9c => ins.op = .pushf,
        0x9d => ins.op = .popf,
        0x9e => ins.op = .sahf,
        0x9f => ins.op = .lahf,
        0xa0...0xa3 => {
            ins.op = .mov;
            ins.opsz = if (op & 1 == 0) 1 else ins.opsz;
            ins.form = op & 3;
            ins.cc = 3;
            ins.imm = try d.immN(if (pfx.addr32) 4 else 8);
        },
        0xa4, 0xa5 => {
            ins.op = .movs;
            ins.opsz = if (op == 0xa4) 1 else ins.opsz;
        },
        0xa6, 0xa7 => {
            ins.op = .cmps;
            ins.opsz = if (op == 0xa6) 1 else ins.opsz;
        },
        0xa8, 0xa9 => {
            ins.op = .test_;
            ins.opsz = if (op == 0xa8) 1 else ins.opsz;
            ins.form = 0xa8;
            ins.imm = if (ins.opsz == 1) (try d.imm8() & 0xff) else if (ins.opsz == 2) @as(u16, @truncate(try d.immN(2))) else (try d.imm32());
        },
        0xaa, 0xab => {
            ins.op = .stos;
            ins.opsz = if (op == 0xaa) 1 else ins.opsz;
        },
        0xac, 0xad => {
            ins.op = .lods;
            ins.opsz = if (op == 0xac) 1 else ins.opsz;
        },
        0xae, 0xaf => {
            ins.op = .scas;
            ins.opsz = if (op == 0xae) 1 else ins.opsz;
        },
        0xb0...0xb7 => {
            ins.op = .mov;
            ins.form = 0xb0;
            ins.opsz = 1;
            ins.rm = @as(u4, @intCast(op & 7)) | (pfx.rexB() << 3);
            ins.imm = try d.immN(1);
        },
        0xb8...0xbf => {
            ins.op = .mov;
            ins.form = 0xb8;
            ins.rm = @as(u4, @intCast(op & 7)) | (pfx.rexB() << 3);
            ins.imm = switch (ins.opsz) {
                2 => try d.immN(2),
                4 => try d.immN(4),
                else => try d.immN(8),
            };
        },
        0xc0, 0xc1 => {
            try d.modrm();
            ins.opsz = if (op == 0xc0) 1 else ins.opsz;
            ins.op = shiftOp(ins.opx);
            ins.form = 0;
            ins.imm = (try d.immN(1)) & 0xff;
        },
        0xc2 => {
            ins.op = .ret;
            ins.imm = try d.immN(2);
        },
        0xc3 => ins.op = .ret,
        0xc6, 0xc7 => {
            try d.modrm();
            ins.opsz = if (op == 0xc6) 1 else ins.opsz;
            if (ins.opx != 0) return common.invalid(s, d.raw);
            ins.op = .mov;
            ins.form = 0xc6;
            ins.imm = if (ins.opsz == 1) (try d.imm8() & 0xff) else if (ins.opsz == 2) @as(u16, @truncate(try d.immN(2))) else (try d.imm32());
        },
        0xc8 => {
            ins.op = .enter;
            ins.imm = try d.immN(2);
            ins.imm2 = (try d.immN(1)) & 0x1f;
        },
        0xc9 => ins.op = .leave,
        0xcc => ins.op = .int3,
        0xcd => {
            ins.op = .int_n;
            ins.imm = try d.immN(1);
        },
        0xd0...0xd3 => {
            try d.modrm();
            ins.opsz = if (op & 1 == 0) 1 else ins.opsz;
            ins.op = shiftOp(ins.opx);
            ins.form = if (op == 0xd0 or op == 0xd1) 0 else 1;
            ins.imm = switch (op) {
                0xd0, 0xd1 => 1,
                else => 0x100,
            };
        },
        0xd7 => ins.op = .xlat,
        0xd8...0xdf => try fpuOp(&d, op),
        0xe0...0xe3 => {
            ins.op = switch (op) {
                0xe0 => .loopne,
                0xe1 => .loope,
                0xe2 => .loop,
                else => .jrcxz,
            };
            ins.imm = try d.imm8();
        },
        0xe8 => {
            ins.op = .call;
            ins.imm = try d.imm32();
        },
        0xe9 => {
            ins.op = .jmp;
            ins.imm = try d.imm32();
        },
        0xeb => {
            ins.op = .jmp;
            ins.imm = try d.imm8();
        },
        0xf5 => ins.op = .cmc,
        0xf6, 0xf7 => {
            try d.modrm();
            ins.opsz = if (op == 0xf6) 1 else ins.opsz;
            ins.op = switch (ins.opx) {
                0, 1 => .test_,
                2 => .not,
                3 => .neg,
                4 => .mul,
                5 => .imul,
                6 => .div,
                7 => .idiv,
            };
            ins.form = 1;
            if (ins.opx <= 1) ins.imm = if (ins.opsz == 1) (try d.imm8() & 0xff) else if (ins.opsz == 2) @as(u16, @truncate(try d.immN(2))) else (try d.imm32());
        },
        0xf8 => ins.op = .clc,
        0xf9 => ins.op = .stc,
        0xfa => ins.op = .cli,
        0xfb => ins.op = .sti,
        0xfc => ins.op = .cld,
        0xfd => ins.op = .std,
        0xfe => {
            try d.modrm();
            ins.opsz = 1;
            ins.op = if (ins.opx == 0) .inc else if (ins.opx == 1) .dec else .invalid;
        },
        0xff => {
            try d.modrm();
            ins.op = switch (ins.opx) {
                0 => .inc,
                1 => .dec,
                2 => .call,
                4 => .jmp,
                6 => .push,
                else => .invalid,
            };
            if (ins.op == .push) {
                ins.form = 0xff;
                ins.opsz = if (pfx.opsz16) 2 else 8;
            }
        },
        0x0f => try twoByte(&d),
        else => {},
    }
    d.finish();
}

fn aluOp(grp: u3) Op {
    return switch (grp) {
        0 => .add,
        1 => .or_,
        2 => .adc,
        3 => .sbb,
        4 => .and_,
        5 => .sub,
        6 => .xor_,
        else => .cmp,
    };
}

fn shiftOp(grp: u3) Op {
    return switch (grp) {
        0 => .rol,
        1 => .ror,
        2 => .rcl,
        3 => .rcr,
        4 => .shl,
        5 => .shr,
        6 => .shl,
        else => .sar,
    };
}

fn twoByte(d: *Dec) common.DecodeError!void {
    const ins = d.ins;
    const op = try d.byte();
    switch (op) {
        0x05 => ins.op = .syscall,
        0x0b => ins.op = .ud2,
        0x0d, 0x18, 0x19, 0x1f => {
            try d.modrm();
            ins.op = .nop;
        },
        0x01 => {
            // ModRM: XGETBV (D0), RDTSCP (F9) and the like; the rest is
            // privileged or unsupported.
            const b = try d.byte();
            ins.aux = b;
            switch (b) {
                0xd0 => ins.op = .xgetbv,
                0xf9 => ins.op = .rdtscp,
                else => return common.invalid(d.s, d.raw),
            }
        },
        0x1e => {
            const b = try d.byte();
            if (ins.pfx.rep == 0xf3 and (b == 0xfa or b == 0xfb)) {
                ins.op = .endbr;
                return;
            }
            // RDSSPD/RDSSPQ (CET): there is no shadow stack, so it reads 0.
            if (ins.pfx.rep == 0xf3 and b & 0xf8 == 0xc8) {
                ins.op = .rdssp;
                ins.rm = @as(u4, @intCast(b & 7)) | (ins.pfx.rexB() << 3);
                ins.opsz = if (ins.pfx.w()) 8 else 4;
                return;
            }
            return common.invalid(d.s, d.raw);
        },
        0x31 => ins.op = .rdtsc,
        0x0e, 0x77 => ins.op = .nop,
        0x40...0x4f => {
            try d.modrm();
            ins.op = .cmovcc;
            ins.cc = @intCast(op & 0xf);
        },
        0x80...0x8f => {
            ins.op = .jcc;
            ins.cc = @intCast(op & 0xf);
            ins.imm = try d.imm32();
        },
        0x90...0x9f => {
            try d.modrm();
            ins.op = .setcc;
            ins.opsz = 1;
            ins.cc = @intCast(op & 0xf);
        },
        0xa0 => {
            ins.op = .push;
            ins.opsz = if (ins.pfx.opsz16) 2 else 8;
            ins.cc = 0xf4;
        },
        0xa1 => {
            ins.op = .pop;
            ins.opsz = if (ins.pfx.opsz16) 2 else 8;
            ins.cc = 0xf4;
        },
        0xa8 => {
            ins.op = .push;
            ins.opsz = if (ins.pfx.opsz16) 2 else 8;
            ins.cc = 0xf5;
        },
        0xa9 => {
            ins.op = .pop;
            ins.opsz = if (ins.pfx.opsz16) 2 else 8;
            ins.cc = 0xf5;
        },
        0xa2 => ins.op = .cpuid,
        0xa3 => {
            try d.modrm();
            ins.op = .bt;
            ins.imm = 0x100; // bit index in ModRM.reg
        },
        0xa4 => {
            try d.modrm();
            ins.op = .shld;
            ins.imm = (try d.immN(1)) & 0x3f;
        },
        0xa5 => {
            try d.modrm();
            ins.op = .shld;
            ins.imm = 0x100;
        },
        0xab => {
            try d.modrm();
            ins.op = .bts;
            ins.imm = 0x100; // bit index in ModRM.reg
        },
        0xac => {
            try d.modrm();
            ins.op = .shrd;
            ins.imm = (try d.immN(1)) & 0x3f;
        },
        0xad => {
            try d.modrm();
            ins.op = .shrd;
            ins.imm = 0x100;
        },
        0xae => {
            // LFENCE/MFENCE/SFENCE are the register forms E8/F0/F8;
            // FXSAVE and friends are not implemented. CLFLUSH (memory,
            // /7) is a no-op here: the decoded-code tracking already sees
            // every store, and there is no cache to flush.
            try d.modrm();
            if (ins.md == 3) {
                ins.op = switch (ins.opx) {
                    5 => .lfence,
                    6 => .mfence,
                    7 => .sfence,
                    else => return common.invalid(d.s, d.raw),
                };
            } else if (ins.opx == 7) {
                ins.op = .nop; // clflush
            } else ins.op = switch (ins.opx) {
                0 => .fxsave,
                1 => .fxrstor,
                4 => .xsave,
                5 => .xrstor,
                else => return common.invalid(d.s, d.raw),
            };
        },
        0xaf => {
            try d.modrm();
            ins.op = .imul;
            ins.form = 2;
        },
        0xb0, 0xb1 => {
            try d.modrm();
            ins.op = .cmpxchg;
            ins.opsz = if (op == 0xb0) 1 else ins.opsz;
        },
        0xb3 => {
            try d.modrm();
            ins.op = .btr;
            ins.imm = 0x100; // bit index in ModRM.reg
        },
        0xb6, 0xb7 => {
            try d.modrm();
            ins.op = .movzx;
            ins.src_sz = if (op == 0xb6) 1 else 2;
            ins.opsz = if (ins.pfx.w()) 8 else if (ins.pfx.opsz16) 2 else 4;
        },
        0xba => {
            try d.modrm();
            ins.op = switch (ins.opx) {
                4 => .bt,
                5 => .bts,
                6 => .btr,
                7 => .btc,
                else => .invalid,
            };
            ins.imm = (try d.immN(1)) & 0x3f;
            ins.aux = 1; // immediate bit offset (no address adjustment)
        },
        0xbb => {
            try d.modrm();
            ins.op = .btc;
            ins.imm = 0x100; // bit index in ModRM.reg
        },
        0xbc => {
            try d.modrm();
            ins.op = if (ins.pfx.rep == 0xf3) .tzcnt else .bsf;
        },
        0xbd => {
            try d.modrm();
            ins.op = if (ins.pfx.rep == 0xf3) .lzcnt else .bsr;
        },
        0xb8 => {
            try d.modrm();
            ins.op = if (ins.pfx.rep == 0xf3) .popcnt else .invalid;
        },
        0xbe, 0xbf => {
            try d.modrm();
            ins.op = .movsx;
            ins.src_sz = if (op == 0xbe) 1 else 2;
            ins.opsz = if (ins.pfx.w()) 8 else if (ins.pfx.opsz16) 2 else 4;
        },
        0xc0, 0xc1 => {
            try d.modrm();
            ins.op = .xadd;
            ins.opsz = if (op == 0xc0) 1 else ins.opsz;
        },
        0xc3 => {
            try d.modrm();
            ins.op = .movnti;
        },
        0xc7 => {
            try d.modrm();
            ins.aux = @intCast(ins.opx);
            if (ins.opx != 1) return common.invalid(d.s, d.raw);
            ins.op = if (ins.pfx.w()) .cmpxchg16b else .cmpxchg8b;
        },
        0xc8...0xcf => {
            ins.op = .bswap;
            ins.rm = @as(u4, @intCast(op & 7)) | (ins.pfx.rexB() << 3);
        },
        0x38, 0x3a => return common.invalid(d.s, d.raw),
        0x10...0x17, 0x28...0x2f, 0x50...0x76, 0x7e, 0x7f, 0xc2, 0xc4...0xc6, 0xd0...0xff => try sseOp(d, op),
        else => {},
    }
}

fn sseOp(d: *Dec, op: u8) common.DecodeError!void {
    const ins = d.ins;
    const p66 = ins.pfx.opsz16;
    const rep = ins.pfx.rep;
    ins.op = .sse;
    ins.opsz = 0;
    try d.modrm();
    switch (op) {
        0x10, 0x11 => {
            if (rep == 0xf3) {
                ins.sse = .movss;
            } else if (rep == 0xf2) {
                ins.sse = .movsd;
            } else if (p66) ins.sse = .movupd else ins.sse = .movups;
        },
        0x12 => ins.sse = if (rep == 0xf3) .movsldup else if (rep == 0xf2) .movddup else .movlps,
        0x13 => {
            ins.sse = .movlps;
            ins.aux = 1;
        },
        0x14 => ins.sse = if (p66) .unpcklpd else .unpcklps,
        0x15 => ins.sse = if (p66) .unpckhpd else .unpckhps,
        0x16 => ins.sse = if (rep == 0xf3) .movshdup else .movhps,
        0x17 => {
            ins.sse = .movhps;
            ins.aux = 1;
        },
        0x28 => ins.sse = if (p66) .movapd else .movaps,
        0x29 => {
            ins.sse = if (p66) .movapd else .movaps;
            ins.aux = 1;
        },
        0x2a => {
            if (rep == 0xf3) {
                ins.sse = .cvtsi2ss;
            } else if (rep == 0xf2) {
                ins.sse = .cvtsi2sd;
            } else return common.invalid(d.s, d.raw);
            ins.opsz = if (ins.pfx.w()) 8 else 4;
        },
        0x2b => {
            ins.sse = if (p66) .movntpd else .movntps;
            ins.aux = 1;
        },
        0x2c => {
            if (rep == 0xf3) {
                ins.sse = .cvttss2si;
            } else if (rep == 0xf2) {
                ins.sse = .cvttsd2si;
            } else return common.invalid(d.s, d.raw);
            ins.opsz = if (ins.pfx.w()) 8 else 4;
        },
        0x2d => {
            if (rep == 0xf3) {
                ins.sse = .cvtss2si;
            } else if (rep == 0xf2) {
                ins.sse = .cvtsd2si;
            } else return common.invalid(d.s, d.raw);
            ins.opsz = if (ins.pfx.w()) 8 else 4;
        },
        0x2e => ins.sse = if (p66) .ucomisd else .ucomiss,
        0x2f => ins.sse = if (p66) .comisd else .comiss,
        0x50 => ins.sse = if (p66) .movmskpd else .movmskps,
        0x51 => ins.sse = if (rep == 0xf3) .sqrtss else if (rep == 0xf2) .sqrtsd else if (p66) .sqrtpd else .sqrtps,
        0x52 => ins.sse = if (rep == 0xf3) .rsqrtss else .rsqrtps,
        0x53 => ins.sse = if (rep == 0xf3) .rcpss else .rcpps,
        0x54 => ins.sse = if (p66) .andpd else .andps,
        0x55 => ins.sse = if (p66) .andnpd else .andnps,
        0x56 => ins.sse = if (p66) .orpd else .orps,
        0x57 => ins.sse = if (p66) .xorpd else .xorps,
        0x58 => ins.sse = if (rep == 0xf3) .addss else if (rep == 0xf2) .addsd else if (p66) .addpd else .addps,
        0x59 => ins.sse = if (rep == 0xf3) .mulss else if (rep == 0xf2) .mulsd else if (p66) .mulpd else .mulps,
        0x5a => ins.sse = if (rep == 0xf3) .cvtss2sd else if (rep == 0xf2) .cvtsd2ss else if (p66) .cvtpd2ps else .cvtps2pd,
        0x5b => ins.sse = if (p66) .cvtps2dq else if (rep == 0xf3) .cvttps2dq else .cvtdq2ps,
        0x5c => ins.sse = if (rep == 0xf3) .subss else if (rep == 0xf2) .subsd else if (p66) .subpd else .subps,
        0x5d => ins.sse = if (rep == 0xf3) .minss else if (rep == 0xf2) .minsd else if (p66) .minpd else .minps,
        0x5e => ins.sse = if (rep == 0xf3) .divss else if (rep == 0xf2) .divsd else if (p66) .divpd else .divps,
        0x5f => ins.sse = if (rep == 0xf3) .maxss else if (rep == 0xf2) .maxsd else if (p66) .maxpd else .maxps,
        0x6e => {
            if (!p66) return common.invalid(d.s, d.raw);
            ins.sse = .movd;
            ins.opsz = if (ins.pfx.w()) 8 else 4;
            ins.aux = 0;
        },
        0x6f => {
            if (p66) {
                ins.sse = .movdqa;
            } else if (rep == 0xf3) {
                ins.sse = .movdqu;
            } else return common.invalid(d.s, d.raw);
        },
        0x7e => {
            if (p66) {
                ins.sse = .movd;
                ins.opsz = if (ins.pfx.w()) 8 else 4;
                ins.aux = 1;
            } else if (rep == 0xf3) {
                ins.sse = .movq;
                ins.aux = 0;
            } else return common.invalid(d.s, d.raw);
        },
        0x7f => {
            if (p66) {
                ins.sse = .movdqa;
            } else if (rep == 0xf3) {
                ins.sse = .movdqu;
            } else return common.invalid(d.s, d.raw);
            ins.aux = 1;
        },
        0x70 => {
            if (p66) {
                ins.sse = .pshufd;
            } else if (rep == 0xf2) {
                ins.sse = .pshuflw;
            } else if (rep == 0xf3) {
                ins.sse = .pshufhw;
            } else return common.invalid(d.s, d.raw); // MMX pshufw
            ins.imm = try d.immN(1);
        },
        0x60...0x6d, 0x71...0x76 => {
            if (!p66) return common.invalid(d.s, d.raw); // MMX forms
            ins.sse = switch (op) {
                0x60 => .punpcklbw,
                0x61 => .punpcklwd,
                0x62 => .punpckldq,
                0x63 => .packsswb,
                0x64 => .pcmpgtb,
                0x65 => .pcmpgtw,
                0x66 => .pcmpgtd,
                0x67 => .packuswb,
                0x68 => .punpckhbw,
                0x69 => .punpckhwd,
                0x6a => .punpckhdq,
                0x6b => .packssdw,
                0x6c => .punpcklqdq,
                0x6d => .punpckhqdq,
                0x71 => .psrlw,
                0x72 => .psrld,
                0x73 => .psrlq,
                0x74 => .pcmpeqb,
                0x75 => .pcmpeqw,
                0x76 => .pcmpeqd,
                else => unreachable,
            };
            if (op == 0x71 or op == 0x72 or op == 0x73) {
                if (ins.md != 3) return common.invalid(d.s, d.raw);
                ins.sse = switch (ins.opx) {
                    2 => if (op == 0x71) .psrlw else if (op == 0x72) .psrld else .psrlq,
                    3 => if (op == 0x73) .psrldq else return common.invalid(d.s, d.raw),
                    4 => if (op == 0x71) .psraw else .psrad,
                    6 => if (op == 0x71) .psllw else if (op == 0x72) .pslld else .psllq,
                    7 => if (op == 0x73) .pslldq else return common.invalid(d.s, d.raw),
                    else => return common.invalid(d.s, d.raw),
                };
                ins.aux = 2;
                ins.imm = (try d.immN(1)) & 0x7f;
                return;
            }
            if (op == 0x70) ins.imm = try d.immN(1);
        },
        0xc2 => {
            ins.sse = if (rep == 0xf3) .cmpss else if (rep == 0xf2) .cmpsd else if (p66) .cmppd else .cmpps;
            ins.imm = (try d.immN(1)) & 0x7;
        },
        0xc4 => {
            if (!p66) return common.invalid(d.s, d.raw);
            ins.sse = .pinsrw;
            ins.imm = try d.immN(1);
        },
        0xc5 => {
            if (!p66) return common.invalid(d.s, d.raw);
            ins.sse = .pextrw;
            ins.imm = try d.immN(1);
        },
        0xc6 => {
            ins.sse = if (p66) .shufpd else .shufps;
            ins.imm = try d.immN(1);
        },
        0xd0 => ins.sse = if (p66) .addsubpd else .addsubps,
        0xd1 => ins.sse = .psrlw,
        0xd2 => ins.sse = .psrld,
        0xd3 => ins.sse = .psrlq,
        0xd4 => ins.sse = .paddq,
        0xd5 => ins.sse = .pmullw,
        0xd6 => {
            ins.sse = .movq;
            ins.aux = 1;
        },
        0xd7 => ins.sse = .pmovmskb,
        0xd8 => ins.sse = .psubusb,
        0xd9 => ins.sse = .psubusw,
        0xda => ins.sse = .pminub,
        0xdb => ins.sse = .pand,
        0xdc => ins.sse = .paddusb,
        0xdd => ins.sse = .paddusw,
        0xde => ins.sse = .pmaxub,
        0xdf => ins.sse = .pandn,
        0xe0 => ins.sse = .pavgb,
        0xe1 => ins.sse = .psraw,
        0xe2 => ins.sse = .psrad,
        0xe3 => ins.sse = .pavgw,
        0xe4 => ins.sse = .pmulhuw,
        0xe5 => ins.sse = .pmulhw,
        0xe6 => ins.sse = if (rep == 0xf2) .cvtpd2dq else if (rep == 0xf3) .cvtdq2pd else .cvttpd2dq,
        0xe7 => {
            if (!p66) return common.invalid(d.s, d.raw);
            ins.sse = .movntdq;
            ins.aux = 1;
        },
        0xe8 => ins.sse = .psubsb,
        0xe9 => ins.sse = .psubsw,
        0xea => ins.sse = .pminsw,
        0xeb => ins.sse = .por,
        0xec => ins.sse = .paddsb,
        0xed => ins.sse = .paddsw,
        0xee => ins.sse = .pmaxsw,
        0xef => ins.sse = .pxor,
        0xf0 => {
            if (rep != 0xf2) return common.invalid(d.s, d.raw);
            ins.sse = .lddqu;
        },
        0xf1 => ins.sse = .psllw,
        0xf2 => ins.sse = .pslld,
        0xf3 => ins.sse = .psllq,
        0xf4 => ins.sse = .pmuludq,
        0xf5 => ins.sse = .pmaddwd,
        0xf6 => ins.sse = .psadbw,
        0xf7 => {
            if (!p66) return common.invalid(d.s, d.raw);
            ins.sse = .maskmovdqu;
            ins.aux = 1;
        },
        0xf8 => ins.sse = .psubb,
        0xf9 => ins.sse = .psubw,
        0xfa => ins.sse = .psubd,
        0xfb => ins.sse = .psubq,
        0xfc => ins.sse = .paddb,
        0xfd => ins.sse = .paddw,
        0xfe => ins.sse = .paddd,
        else => {},
    }
    if (!p66 and rep == 0 and op >= 0xd0 and op != 0xf0) return common.invalid(d.s, d.raw);
    if (op == 0x10 or op == 0x11) {
        ins.aux = if (op == 0x11) 1 else 0;
    }
}

fn fpuOp(d: *Dec, op: u8) common.DecodeError!void {
    const ins = d.ins;
    ins.op = .fpu;
    try d.modrm();
    const m = ins.md != 3;
    // Memory operand classes and register-form direction live in ins.aux:
    // 0 = st(0) = st(0) op st(i), 1 = st(i) = st(i) op st(0),
    // 2 = the pop forms (DE C0..), 3.. = memory operand classes.
    switch (op) {
        0xd8 => {
            const float: Fpu = switch (ins.opx) {
                0 => .fadd,
                1 => .fmul,
                2 => .fcom,
                3 => .fcomp,
                4 => .fsub,
                5 => .fsubr,
                6 => .fdiv,
                7 => .fdivr,
            };
            ins.fpu = float;
            if (m) {
                ins.opsz = 4;
                ins.aux = 3; // m32fp
            } else {
                ins.aux = 0;
            }
        },
        0xd9 => {
            if (m) {
                ins.fpu = switch (ins.opx) {
                    0 => .fld,
                    2 => .fst,
                    3 => .fstp,
                    5 => .fldcw,
                    7 => .fnstcw,
                    else => return common.invalid(d.s, d.raw),
                };
                ins.opsz = if (ins.opx == 0 or ins.opx == 2 or ins.opx == 3) 4 else 2;
                ins.aux = if (ins.opx == 0 or ins.opx == 2 or ins.opx == 3) 3 else 6;
            } else {
                ins.aux = 0;
                if (ins.opx == 0) {
                    ins.fpu = .fld;
                } else if (ins.opx == 1) {
                    ins.fpu = .fxch;
                } else if (ins.opx == 4) {
                    ins.fpu = switch (ins.rm) {
                        0 => .fchs,
                        1 => .fabs,
                        4 => .ftst,
                        5 => .fxam,
                        else => return common.invalid(d.s, d.raw),
                    };
                } else if (ins.opx == 5) {
                    ins.fpu = switch (ins.rm) {
                        0 => .fld1,
                        1 => .fldl2t,
                        2 => .fldl2e,
                        3 => .fldpi,
                        4 => .fldlg2,
                        5 => .fldln2,
                        6 => .fldz,
                        else => return common.invalid(d.s, d.raw),
                    };
                } else if (ins.opx == 7) {
                    ins.fpu = switch (ins.rm) {
                        2 => .fsqrt,
                        4 => .frndint,
                        5 => .fscale,
                        0 => .fprem,
                        else => return common.invalid(d.s, d.raw),
                    };
                } else return common.invalid(d.s, d.raw);
            }
        },
        0xda => {
            if (m) {
                ins.fpu = switch (ins.opx) {
                    0 => .fiadd,
                    1 => .fimul,
                    2 => .fcom,
                    3 => .fcomp,
                    4 => .fisub,
                    5 => .fisubr,
                    6 => .fidiv,
                    7 => .fidivr,
                };
                ins.opsz = 4;
                ins.aux = 4; // m32int
            } else return common.invalid(d.s, d.raw);
        },
        0xdb => {
            if (m) {
                ins.fpu = switch (ins.opx) {
                    0 => .fild,
                    2 => .fist,
                    3 => .fistp,
                    5 => .fld,
                    7 => .fstp,
                    else => return common.invalid(d.s, d.raw),
                };
                ins.opsz = if (ins.opx == 5 or ins.opx == 7) 10 else 4;
                ins.aux = if (ins.opx == 5 or ins.opx == 7) 7 else 5; // m80fp / m32int
            } else {
                ins.aux = 0;
                ins.fpu = switch (ins.opx) {
                    5 => .fucomi,
                    6 => .fcomi,
                    else => return common.invalid(d.s, d.raw),
                };
            }
        },
        0xdc => {
            if (m) {
                ins.fpu = switch (ins.opx) {
                    0 => .fadd,
                    1 => .fmul,
                    2 => .fcom,
                    3 => .fcomp,
                    4 => .fsub,
                    5 => .fsubr,
                    6 => .fdiv,
                    7 => .fdivr,
                };
                ins.opsz = 8;
                ins.aux = 3; // m64fp
            } else {
                ins.aux = 1;
                ins.fpu = switch (ins.opx) {
                    0 => .fadd,
                    1 => .fmul,
                    2 => .fcom,
                    3 => .fcomp,
                    4 => .fsub,
                    5 => .fsubr,
                    6 => .fdiv,
                    7 => .fdivr,
                };
            }
        },
        0xdd => {
            if (m) {
                ins.fpu = switch (ins.opx) {
                    0 => .fld,
                    2 => .fst,
                    3 => .fstp,
                    7 => .fnstsw,
                    else => return common.invalid(d.s, d.raw),
                };
                ins.opsz = if (ins.opx == 7) 2 else 8;
                ins.aux = if (ins.opx == 7) 6 else 3;
            } else {
                ins.aux = 0;
                ins.fpu = switch (ins.opx) {
                    0 => .fld,
                    2 => .fst,
                    3 => .fstp,
                    4 => .fucom,
                    5 => .fucomp,
                    else => return common.invalid(d.s, d.raw),
                };
            }
        },
        0xde => {
            if (m) {
                ins.fpu = switch (ins.opx) {
                    0 => .fiadd,
                    1 => .fimul,
                    2 => .fcom,
                    3 => .fcomp,
                    4 => .fisub,
                    5 => .fisubr,
                    6 => .fidiv,
                    7 => .fidivr,
                };
                ins.opsz = 2;
                ins.aux = 4; // m16int
            } else {
                ins.aux = 2;
                if (ins.opx == 3 and ins.rm == 1) {
                    ins.fpu = .fcompp;
                } else {
                    ins.fpu = switch (ins.opx) {
                        0 => .faddp,
                        1 => .fmulp,
                        4 => .fsubrp,
                        5 => .fsubp,
                        6 => .fdivrp,
                        7 => .fdivp,
                        else => return common.invalid(d.s, d.raw),
                    };
                }
            }
        },
        0xdf => {
            if (m) {
                ins.fpu = switch (ins.opx) {
                    0 => .fild,
                    2 => .fist,
                    3 => .fistp,
                    5 => .fild,
                    7 => .fistp,
                    else => return common.invalid(d.s, d.raw),
                };
                ins.opsz = if (ins.opx == 5 or ins.opx == 7) 8 else 2;
                ins.aux = 5; // integer
            } else {
                ins.aux = 0;
                ins.fpu = switch (ins.opx) {
                    4 => .fnstsw,
                    5 => .fucomip,
                    6 => .fcomip,
                    else => return common.invalid(d.s, d.raw),
                };
            }
        },
        else => return common.invalid(d.s, d.raw),
    }
}
