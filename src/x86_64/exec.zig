// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! x86-64 instruction semantics: the integer baseline a static Linux
//! userland needs, SSE2 (and the x87 operations long double uses), the
//! system instructions user mode may run (SYSCALL, CPUID, RDTSC), and
//! precise traps. The decoded form is decode.Insn; run.zig advances rip
//! past the instruction before calling `one`, so branches and RIP-relative
//! operands use the next-instruction address.

const std = @import("std");
const common = @import("common.zig");
const decode = @import("decode.zig");
comptime {
    _ = @import("x87rt.zig");
}
const state = @import("state.zig");

const Insn = decode.Insn;
const Op = decode.Op;
const Sse = decode.Sse;
const St = common.St;
const Error = common.Error;
const Exit = common.Exit;
const Regs = common.Regs;

pub fn one(s: St, ins: *const Insn) Error!Exit {
    return switch (ins.op) {
        .invalid => common.ill(s, ins.raw),
        .nop, .endbr, .pause, .mfence, .lfence, .sfence => .next,
        .add, .or_, .adc, .sbb, .and_, .sub, .xor_, .cmp => try alu(s, ins),
        .test_ => try testOp(s, ins),
        .mov => try movOp(s, ins),
        .movzx, .movsx, .movsxd => try movx(s, ins),
        .lea => blk: {
            common.regWrite(s.r, ins.reg, ins.opsz, ins.pfx.rex != 0, ins.ea);
            break :blk .next;
        },
        .xchg => try xchg(s, ins),
        .push => try push(s, ins),
        .pop => try pop(s, ins),
        .inc, .dec => try incDec(s, ins),
        .neg, .not => try negNot(s, ins),
        .mul, .imul, .div, .idiv => try mulDiv(s, ins),
        .shl, .shr, .sar, .rol, .ror, .rcl, .rcr => try shift(s, ins),
        .shld, .shrd => try shldShrd(s, ins),
        .bt, .bts, .btr, .btc => try bitTest(s, ins),
        .bsf, .bsr, .tzcnt, .lzcnt, .popcnt => try bitScan(s, ins),
        .jmp => try jmpOp(s, ins),
        .jcc => {
            if (common.cond(s.r, ins.cc)) return common.jump(s, s.r.rip +% ins.imm);
            return .next;
        },
        .call => try callOp(s, ins),
        .ret => try retOp(s, ins),
        .loopne, .loope, .loop, .jrcxz => try loopOp(s, ins),
        .cmovcc => try cmov(s, ins),
        .setcc => blk: {
            try rmWrite(s, ins, 1, @intFromBool(common.cond(s.r, ins.cc)));
            break :blk .next;
        },
        .movs, .stos, .lods, .scas, .cmps => try stringOp(s, ins),
        .cmpxchg => try cmpxchg(s, ins),
        .xadd => try xadd(s, ins),
        .cmpxchg8b, .cmpxchg16b => try cmpxchgxb(s, ins),
        .cbw => try cbw(s, ins),
        .cwd => try cwd(s, ins),
        .pushf => try pushf(s, ins),
        .popf => try popf(s, ins),
        .sahf => {
            const ah = (s.r.rax >> 8) & 0xff;
            var f = s.r.eflags & ~(state.CF | state.PF | state.AF | state.ZF | state.SF);
            if (ah & 0x01 != 0) f |= state.CF;
            if (ah & 0x04 != 0) f |= state.PF;
            if (ah & 0x10 != 0) f |= state.AF;
            if (ah & 0x40 != 0) f |= state.ZF;
            if (ah & 0x80 != 0) f |= state.SF;
            s.r.eflags = f;
            return .next;
        },
        .lahf => {
            const f = s.r.eflags;
            var ah: u64 = 0x02;
            if (f & state.CF != 0) ah |= 0x01;
            if (f & state.PF != 0) ah |= 0x04;
            if (f & state.AF != 0) ah |= 0x10;
            if (f & state.ZF != 0) ah |= 0x40;
            if (f & state.SF != 0) ah |= 0x80;
            s.r.rax = (s.r.rax & ~@as(u64, 0xff00)) | (ah << 8);
            return .next;
        },
        .leave => {
            s.r.rsp = s.r.rbp;
            const v = try s.m.load(u64, s.r.rsp);
            s.r.rsp +%= 8;
            s.r.rbp = v;
            return .next;
        },
        .enter => try enter(s, ins),
        .int3 => common.breakpoint(s, ins.raw),
        .int_n => common.ill(s, ins.raw),
        .hlt, .ud2 => common.ill(s, ins.raw),
        .syscall => {
            s.r.rcx = s.r.rip;
            s.r.r11 = s.r.eflags | state.FLAGS_RESERVED;
            return common.syscall(s);
        },
        .cpuid => try cpuid(s),
        .rdtsc => try rdtsc(s, false),
        .rdtscp => try rdtsc(s, true),
        .xgetbv => {
            const xcr = s.r.rcx;
            const v: u64 = if (xcr == 0) 3 else 0;
            s.r.rax = @truncate(v);
            s.r.rdx = v >> 32;
            return .next;
        },
        .clc => {
            s.r.eflags &= ~state.CF;
            return .next;
        },
        .stc => {
            s.r.eflags |= state.CF;
            return .next;
        },
        .cmc => {
            s.r.eflags ^= state.CF;
            return .next;
        },
        .cld => {
            s.r.eflags &= ~state.DF;
            return .next;
        },
        .std => {
            s.r.eflags |= state.DF;
            return .next;
        },
        .cli, .sti => .next, // user mode cannot change IF; the kernel owns it
        .bswap => {
            const sz = ins.opsz;
            const v = common.regRead(s.r, ins.rm, sz, ins.pfx.rex != 0);
            const r = switch (sz) {
                4 => @byteSwap(@as(u32, @truncate(v))),
                8 => @byteSwap(v),
                else => unreachable,
            };
            common.regWrite(s.r, ins.rm, sz, ins.pfx.rex != 0, r);
            return .next;
        },
        .movnti => {
            const v = common.regRead(s.r, ins.reg, ins.opsz, ins.pfx.rex != 0);
            try rmWrite(s, ins, ins.opsz, v);
            return .next;
        },
        .rdssp => {
            // No CET shadow stack: the shadow stack pointer reads 0.
            common.regWrite(s.r, ins.rm, ins.opsz, ins.pfx.rex != 0, 0);
            return .next;
        },
        .xlat => {
            const addr = s.r.rbx +% (s.r.rax & 0xff);
            const b = try s.m.load(u8, addr);
            s.r.rax = (s.r.rax & ~@as(u64, 0xff)) | b;
            return .next;
        },
        .fxsave, .xsave => try fxsave(s, ins),
        .fxrstor, .xrstor => try fxrstor(s, ins),
        .sse => try sseOp(s, ins),
        .fpu => try fpuOp(s, ins),
    };
}

// ---- operand helpers -------------------------------------------------------------

fn rmRead(s: St, ins: *const Insn, sz: u8) Error!u64 {
    if (ins.mem) return common.readMem(s, ins.ea, sz, ins.pfx.seg);
    return common.regRead(s.r, ins.rm, sz, ins.pfx.rex != 0);
}

fn rmWrite(s: St, ins: *const Insn, sz: u8, v: u64) Error!void {
    if (ins.mem) return common.writeMem(s, ins.ea, sz, ins.pfx.seg, v);
    common.regWrite(s.r, ins.rm, sz, ins.pfx.rex != 0, v);
}

// ---- ALU / test ------------------------------------------------------------------

fn alu(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    var a: u64 = undefined;
    var b: u64 = undefined;
    var dst_rm = false;
    switch (ins.form) {
        0, 1 => {
            dst_rm = true;
            a = try rmRead(s, ins, sz);
            b = common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0);
        },
        2, 3 => {
            a = common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0);
            b = try rmRead(s, ins, sz);
        },
        0x10 => {
            dst_rm = true;
            a = try rmRead(s, ins, sz);
            b = ins.imm;
        },
        0x11 => {
            a = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
            b = ins.imm;
        },
        else => unreachable,
    }
    const m = common.mask(sz);
    const res: u64 = switch (ins.op) {
        .add, .or_, .adc, .sbb, .and_, .sub, .xor_, .cmp => blk: {
            const carry: u1 = @intCast(@intFromBool(s.r.eflags & state.CF != 0));
            switch (ins.op) {
                .add => {
                    common.flagsAdd(s.r, sz, a, b, 0);
                    break :blk (a +% b) & m;
                },
                .adc => {
                    common.flagsAdd(s.r, sz, a, b, carry);
                    break :blk (a +% b +% carry) & m;
                },
                .sub => {
                    common.flagsSub(s.r, sz, a, b, 0);
                    break :blk (a -% b) & m;
                },
                .sbb => {
                    common.flagsSub(s.r, sz, a, b, carry);
                    break :blk (a -% b -% carry) & m;
                },
                .cmp => {
                    common.flagsSub(s.r, sz, a, b, 0);
                    break :blk (a -% b) & m;
                },
                .or_ => {
                    const r = (a | b) & m;
                    common.flagsLogic(s.r, sz, r);
                    break :blk r;
                },
                .and_ => {
                    const r = (a & b) & m;
                    common.flagsLogic(s.r, sz, r);
                    break :blk r;
                },
                else => {
                    const r = (a ^ b) & m;
                    common.flagsLogic(s.r, sz, r);
                    break :blk r;
                },
            }
        },
        else => unreachable,
    };
    if (ins.op == .cmp) return .next;
    if (dst_rm) try rmWrite(s, ins, sz, res) else common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, res);
    return .next;
}

fn testOp(s: St, ins: *const Insn) Error!Exit {
    var a: u64 = undefined;
    var b: u64 = undefined;
    if (ins.form == 0x84) {
        a = try rmRead(s, ins, ins.opsz);
        b = common.regRead(s.r, ins.reg, ins.opsz, ins.pfx.rex != 0);
    } else if (ins.form == 0xa8) {
        a = common.regRead(s.r, 0, ins.opsz, ins.pfx.rex != 0);
        b = ins.imm;
    } else {
        // F6/F7 /0: r/m with an immediate (the decoder stores it in imm).
        a = try rmRead(s, ins, ins.opsz);
        b = ins.imm;
    }
    common.flagsLogic(s.r, ins.opsz, a & b);
    return .next;
}

// ---- mov -------------------------------------------------------------------------

fn movOp(s: St, ins: *const Insn) Error!Exit {
    if (ins.cc == 1) { // MOV r/m16, Sreg
        try rmWrite(s, ins, 2, 0);
        return .next;
    }
    if (ins.cc == 2) return .next; // MOV Sreg, r/m16: flat, ignored
    if (ins.cc == 3) { // moffs
        const sz = ins.opsz;
        const va = ins.imm;
        if (ins.form == 0 or ins.form == 1) {
            const v = try common.readMem(s, va, sz, 0);
            common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, v);
        } else {
            const v = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
            try common.writeMem(s, va, sz, 0, v);
        }
        return .next;
    }
    switch (ins.form) {
        0, 1 => { // r/m <- reg
            const v = common.regRead(s.r, ins.reg, ins.opsz, ins.pfx.rex != 0);
            try rmWrite(s, ins, ins.opsz, v);
        },
        2, 3 => { // reg <- r/m
            const v = try rmRead(s, ins, ins.opsz);
            common.regWrite(s.r, ins.reg, ins.opsz, ins.pfx.rex != 0, v);
        },
        0xb0, 0xb8 => { // reg <- imm
            common.regWrite(s.r, ins.rm, ins.opsz, ins.pfx.rex != 0, ins.imm);
        },
        0xc6 => { // r/m <- imm
            try rmWrite(s, ins, ins.opsz, ins.imm);
        },
        else => unreachable,
    }
    return .next;
}

fn movx(s: St, ins: *const Insn) Error!Exit {
    const src_sz: u8 = if (ins.op == .movsxd) 4 else ins.src_sz;
    const v = if (ins.mem) try common.readMem(s, ins.ea, src_sz, ins.pfx.seg) else common.regRead(s.r, ins.rm, src_sz, ins.pfx.rex != 0);
    const r: u64 = switch (ins.op) {
        .movzx => v,
        .movsx, .movsxd => common.sextR(v, src_sz * 8),
        else => unreachable,
    };
    common.regWrite(s.r, ins.reg, ins.opsz, ins.pfx.rex != 0, r);
    return .next;
}

fn xchg(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    if (ins.form == 0x90) {
        const a = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
        const b = common.regRead(s.r, ins.rm, sz, ins.pfx.rex != 0);
        common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, b);
        common.regWrite(s.r, ins.rm, sz, ins.pfx.rex != 0, a);
        return .next;
    }
    const a = try rmRead(s, ins, sz);
    const b = common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0);
    try rmWrite(s, ins, sz, b); // a faulting store leaves the register as it was
    common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, a);
    return .next;
}

// ---- stack -----------------------------------------------------------------------

fn pushValue(s: St, sz: u8, v: u64) Error!void {
    // Store first: a faulting push must leave rsp as it was.
    const sp = s.r.rsp -% sz;
    try common.writeMem(s, sp, sz, 0, v);
    s.r.rsp = sp;
}

fn popValue(s: St, sz: u8) Error!u64 {
    const v = try common.readMem(s, s.r.rsp, sz, 0);
    s.r.rsp +%= sz;
    return v;
}

fn push(s: St, ins: *const Insn) Error!Exit {
    const sz: u8 = if (ins.opsz == 2) 2 else 8;
    const v: u64 = switch (ins.cc) {
        0xf4, 0xf5 => 0,
        else => switch (ins.form) {
            0x50 => common.regRead(s.r, ins.rm, sz, ins.pfx.rex != 0),
            0x68 => ins.imm,
            0xff => try rmRead(s, ins, sz),
            else => 0,
        },
    };
    try pushValue(s, sz, v & common.mask(sz));
    return .next;
}

fn pop(s: St, ins: *const Insn) Error!Exit {
    const sz = if (ins.opsz == 2) @as(u8, 2) else 8;
    if (ins.cc == 0xf4 or ins.cc == 0xf5) { // pop fs/gs: selectors ignored
        _ = try popValue(s, sz);
        return .next;
    }
    // A faulting store to the destination must leave rsp and the
    // destination unchanged: read first, write, then commit rsp.
    const sp = s.r.rsp;
    const v = try common.readMem(s, sp, sz, 0);
    if (ins.has_modrm and ins.mem) {
        // Intel SDM: when rSP is the base of a POP's memory destination,
        // the effective address is computed after rSP is incremented.
        // SpiderMonkey's JIT saves the return address with `push [rsp];
        // mov [rsp+8], 1` and restores it with `pop [rsp]` after
        // `mov rsp, rbp; pop rbp`.
        var ea = ins.ea;
        if (ins.has_base and ins.base == 4) ea +%= sz;
        if (ins.addr32) ea &= 0xffff_ffff;
        try common.writeMem(s, ea, sz, ins.pfx.seg, v);
    } else {
        common.regWrite(s.r, ins.rm, sz, ins.pfx.rex != 0, v);
        // POP rSP: the loaded value is the new stack pointer, not rSP + size.
        if (ins.rm == 4) return .next;
    }
    s.r.rsp = sp +% sz;
    return .next;
}

// ---- inc/dec/neg/not -------------------------------------------------------------

fn incDec(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const a = try rmRead(s, ins, sz);
    common.flagsIncDec(s.r, sz, a, ins.op == .dec);
    try rmWrite(s, ins, sz, (if (ins.op == .dec) a -% 1 else a +% 1) & common.mask(sz));
    return .next;
}

fn negNot(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const a = try rmRead(s, ins, sz);
    if (ins.op == .not) {
        try rmWrite(s, ins, sz, ~a & common.mask(sz));
        return .next;
    }
    // NEG: 0 - a; CF = a != 0, OF/AF/SF/ZF/PF as SUB.
    common.flagsSub(s.r, sz, 0, a, 0);
    try rmWrite(s, ins, sz, (0 -% a) & common.mask(sz));
    return .next;
}

// ---- multiply / divide -----------------------------------------------------------

fn mulDiv(s: St, ins: *const Insn) Error!Exit {
    switch (ins.form) {
        2 => return imulTwo(s, ins),
        3 => return imulThree(s, ins),
        else => {},
    }
    const sz = ins.opsz;
    const bits: u8 = sz * 8;
    const m = common.mask(sz);
    const src = try rmRead(s, ins, sz);
    switch (ins.op) {
        .mul => {
            const a = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
            const p = mulU64(a & m, src & m);
            if (sz == 1) {
                s.r.rax = (s.r.rax & ~@as(u64, 0xffff)) | (p.lo & 0xffff);
            } else {
                common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, p.lo);
                common.regWrite(s.r, 2, sz, ins.pfx.rex != 0, p.hi);
            }
            const overflow = if (sz == 8) p.hi != 0 else (p.lo >> @intCast(bits)) != 0;
            s.r.eflags = (s.r.eflags & ~(state.CF | state.OF)) | (if (overflow) state.CF | state.OF else 0);
        },
        .imul => {
            const a: i64 = @bitCast(common.sextR(common.regRead(s.r, 0, sz, ins.pfx.rex != 0), bits));
            const b: i64 = @bitCast(common.sextR(src, bits));
            const p = mulI64(a, b);
            if (sz == 1) {
                s.r.rax = (s.r.rax & ~@as(u64, 0xffff)) | (p.lo & 0xffff);
            } else {
                common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, p.lo);
                common.regWrite(s.r, 2, sz, ins.pfx.rex != 0, p.hi);
            }
            const overflow = mulOverflowsI(p, bits);
            s.r.eflags = (s.r.eflags & ~(state.CF | state.OF)) | (if (overflow) state.CF | state.OF else 0);
        },
        .div, .idiv => {
            if (src == 0) return common.ill(s, ins.raw); // #DE
            const a = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
            const d = common.regRead(s.r, 2, sz, ins.pfx.rex != 0);
            if (sz == 1 and ins.op == .div) {
                const dividend: u16 = (@as(u16, @intCast(d & 0xff)) << 8) | @as(u8, @truncate(a));
                const divisor: u16 = @intCast(src & 0xff);
                const q = dividend / divisor;
                const r = dividend % divisor;
                if (q > 0xff) return common.ill(s, ins.raw);
                s.r.rax = (s.r.rax & ~@as(u64, 0xffff)) | (@as(u64, q) << 8) | r;
            } else if (sz == 1) {
                const dividend: i16 = @bitCast((@as(u16, @intCast(d & 0xff)) << 8) | @as(u8, @truncate(a)));
                const divisor: i16 = @bitCast(@as(u16, @intCast(src & 0xff)));
                const q = @divTrunc(dividend, divisor);
                const r = @rem(dividend, divisor);
                if (q < -128 or q > 127) return common.ill(s, ins.raw);
                s.r.rax = (s.r.rax & ~@as(u64, 0xffff)) | (@as(u64, @bitCast(@as(i64, q))) << 8) | (@as(u64, @bitCast(@as(i64, r))) & 0xff);
            } else if (sz == 2 or sz == 4) {
                if (ins.op == .div) {
                    const dividend: u64 = ((d & m) << @intCast(bits)) | (a & m);
                    const divisor: u64 = src & m;
                    const q = dividend / divisor;
                    const r = dividend % divisor;
                    if (q > m) return common.ill(s, ins.raw);
                    common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, q);
                    common.regWrite(s.r, 2, sz, ins.pfx.rex != 0, r);
                } else {
                    // The 2*sz-bit dividend fits in i64 for sz 2 and 4.
                    const hi: i64 = @bitCast(common.sextR(d & m, bits));
                    const lo: i64 = @bitCast(common.sextR(a & m, bits));
                    const wide: i64 = (hi << @intCast(bits)) | (lo & @as(i64, @bitCast(m)));
                    const divisor: i64 = @bitCast(common.sextR(src, bits));
                    const q = @divTrunc(wide, divisor);
                    const r = @rem(wide, divisor);
                    const qm: i64 = (@as(i64, 1) << @intCast(bits - 1)) - 1;
                    if (q > qm or q < -qm - 1) return common.ill(s, ins.raw);
                    common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, @bitCast(q));
                    common.regWrite(s.r, 2, sz, ins.pfx.rex != 0, @bitCast(r));
                }
            } else {
                // 64-bit: a 128-bit dividend over a 64-bit divisor.
                if (ins.op == .div) {
                    if (d >= src) return common.ill(s, ins.raw);
                    const qr = udiv128(d, a, src);
                    common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, qr.q);
                    common.regWrite(s.r, 2, sz, ins.pfx.rex != 0, qr.r);
                } else {
                    const neg_a = d >> 63 != 0;
                    const neg_b = @as(i64, @bitCast(src)) < 0;
                    const dneg: u64 = if (neg_b) 0 -% src else src;
                    var hi = d;
                    var lo = a;
                    if (neg_a) {
                        lo = ~lo +% 1;
                        hi = ~hi +% @intFromBool(lo == 0);
                    }
                    if (hi >= dneg) return common.ill(s, ins.raw);
                    const u = udiv128(hi, lo, dneg);
                    const q: u64 = if (neg_a != neg_b) 0 -% u.q else u.q;
                    const r: u64 = if (neg_a) 0 -% u.r else u.r;
                    if (neg_a != neg_b and q == (@as(u64, 1) << 63) and dneg == 1 and false) return common.ill(s, ins.raw);
                    common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, q);
                    common.regWrite(s.r, 2, sz, ins.pfx.rex != 0, r);
                }
            }
        },
        else => unreachable,
    }
    return .next;
}

/// Unsigned 128-by-64 division (hi < d), shift and subtract: no
/// compiler-rt __udivti3 in the wasm object.
fn udiv128(hi: u64, lo: u64, d: u64) struct { q: u64, r: u64 } {
    var rem = hi;
    var q: u64 = 0;
    var i: u8 = 64;
    while (i > 0) {
        i -= 1;
        const top = rem >> 63;
        rem = (rem << 1) | ((lo >> @intCast(i)) & 1);
        q <<= 1;
        if (top != 0 or rem >= d) {
            rem -%= d;
            q |= 1;
        }
    }
    return .{ .q = q, .r = rem };
}

fn imulThree(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const bits: u8 = sz * 8;
    const a: i64 = @bitCast(common.sextR(try rmRead(s, ins, sz), bits));
    const b: i64 = @bitCast(common.sextR(ins.imm, bits));
    const p = mulI64(a, b);
    common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, p.lo);
    const overflow = mulOverflowsI(p, bits);
    s.r.eflags = (s.r.eflags & ~(state.CF | state.OF)) | (if (overflow) state.CF | state.OF else 0);
    return .next;
}

fn imulTwo(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const bits: u8 = sz * 8;
    const x: i64 = @bitCast(common.sextR(common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0), bits));
    const y: i64 = @bitCast(common.sextR(try rmRead(s, ins, sz), bits));
    const p = mulI64(x, y);
    common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, p.lo);
    const overflow = mulOverflowsI(p, bits);
    s.r.eflags = (s.r.eflags & ~(state.CF | state.OF)) | (if (overflow) state.CF | state.OF else 0);
    return .next;
}

const MulWide = struct { lo: u64, hi: u64 };

/// 64x64 -> 128 unsigned product from 32-bit halves (no __multi3).
fn mulU64(a: u64, b: u64) MulWide {
    const a0: u64 = a & 0xffff_ffff;
    const a1: u64 = a >> 32;
    const b0: u64 = b & 0xffff_ffff;
    const b1: u64 = b >> 32;
    const p00 = a0 * b0;
    const p01 = a0 * b1;
    const p10 = a1 * b0;
    const p11 = a1 * b1;
    const mid = (p00 >> 32) + (p01 & 0xffff_ffff) + (p10 & 0xffff_ffff);
    return .{ .lo = (p00 & 0xffff_ffff) | (mid << 32), .hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32) };
}

fn mulI64(a: i64, b: i64) MulWide {
    const neg = (a < 0) != (b < 0);
    const ua: u64 = if (a < 0) 0 -% @as(u64, @bitCast(a)) else @as(u64, @bitCast(a));
    const ub: u64 = if (b < 0) 0 -% @as(u64, @bitCast(b)) else @as(u64, @bitCast(b));
    var p = mulU64(ua, ub);
    if (neg) {
        p.lo = ~p.lo +% 1;
        p.hi = ~p.hi +% @intFromBool(p.lo == 0);
    }
    return p;
}

fn mulOverflowsI(p: MulWide, bits: u8) bool {
    if (bits == 64) {
        const sign = p.lo >> 63;
        return p.hi != (if (sign != 0) std.math.maxInt(u64) else @as(u64, 0));
    }
    return common.sextR(p.lo, bits) != p.lo;
}

// ---- shifts ----------------------------------------------------------------------

fn shift(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const bits: u8 = sz * 8;
    const m = common.mask(sz);
    const raw: u64 = if (ins.form == 1) common.regRead(s.r, 1, 1, false) & 0xff else ins.imm & 0xff;
    const count: u8 = if (ins.op == .rcl or ins.op == .rcr)
        @intCast(raw % (@as(u64, bits) + 1))
    else
        @intCast(raw & @as(u64, if (bits == 64) 63 else 31));
    const v = try rmRead(s, ins, sz);
    if (count == 0) return .next;
    const cf_in: u1 = @intCast(@intFromBool(s.r.eflags & state.CF != 0));
    var cf: u1 = cf_in;
    var of: bool = false;
    const res: u64 = switch (ins.op) {
        .shl => blk: {
            if (count >= bits) {
                cf = 0;
                break :blk 0;
            }
            const r = ((v & m) << @intCast(count)) & m;
            cf = @intCast(((v & m) >> @intCast(bits - count)) & 1);
            if (count == 1) of = ((r & common.signbit(sz)) != 0) != (cf != 0);
            break :blk r;
        },
        .shr => blk: {
            if (count >= bits) {
                cf = 0;
                break :blk 0;
            }
            cf = @intCast(((v & m) >> @intCast(count - 1)) & 1);
            const r = (v & m) >> @intCast(count);
            if (count == 1) of = (v & common.signbit(sz)) != 0;
            break :blk r;
        },
        .sar => blk: {
            const sv: i64 = @bitCast(common.sextR(v & m, bits));
            const shifted = sv >> @intCast(@min(count, bits - 1));
            cf = @intCast((@as(u64, @bitCast(sv)) >> @intCast(count - 1)) & 1);
            if (count == 1) of = false;
            break :blk @as(u64, @bitCast(shifted)) & m;
        },
        .rol => blk: {
            const c: u8 = @intCast(count % bits);
            const r = ((v & m) << @intCast(c) | (v & m) >> @intCast(bits - c)) & m;
            cf = @intCast((r & 1));
            if (count == 1) of = ((r & common.signbit(sz)) != 0) != (cf != 0);
            break :blk r;
        },
        .ror => blk: {
            const c: u8 = @intCast(count % bits);
            const r = ((v & m) >> @intCast(c) | (v & m) << @intCast(bits - c)) & m;
            cf = @intCast((r & common.signbit(sz)) >> @intCast(bits - 1));
            if (count == 1) of = ((r & common.signbit(sz)) != 0) != (((r << 1) & common.signbit(sz)) != 0);
            break :blk r;
        },
        .rcl => blk: {
            var val: u64 = v & m;
            var carry: u1 = cf_in;
            var i: u8 = 0;
            while (i < count) : (i += 1) {
                const msb: u1 = @intCast((val >> @intCast(bits - 1)) & 1);
                val = ((val << 1) | carry) & m;
                carry = msb;
            }
            cf = carry;
            break :blk val;
        },
        .rcr => blk: {
            var val: u64 = v & m;
            var carry: u1 = cf_in;
            var i: u8 = 0;
            while (i < count) : (i += 1) {
                const lsb: u1 = @intCast(val & 1);
                val = (val >> 1) | (@as(u64, carry) << @intCast(bits - 1));
                carry = lsb;
            }
            cf = carry;
            break :blk val;
        },
        else => unreachable,
    };
    // CF/OF, then SZP from the result.
    s.r.eflags &= ~(state.CF | state.OF | state.SF | state.ZF | state.PF | state.AF);
    if (cf != 0) s.r.eflags |= state.CF;
    if (of) s.r.eflags |= state.OF;
    if (res == 0) s.r.eflags |= state.ZF;
    if (res & common.signbit(sz) != 0) s.r.eflags |= state.SF;
    if (@popCount(@as(u8, @truncate(res))) & 1 == 0) s.r.eflags |= state.PF;
    try rmWrite(s, ins, sz, res);
    return .next;
}

fn shldShrd(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const bits: u8 = sz * 8;
    const m = common.mask(sz);
    const raw: u64 = if (ins.imm == 0x100) common.regRead(s.r, 1, 1, false) & 0xff else ins.imm;
    const count: u8 = @intCast(raw & @as(u64, if (bits == 64) 63 else 31));
    if (count == 0) return .next;
    const dst = try rmRead(s, ins, sz);
    const src = common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0);
    var res: u64 = undefined;
    var cf: u1 = 0;
    var of: bool = false;
    if (ins.op == .shld) {
        cf = @intCast((dst >> @intCast(bits - count)) & 1);
        res = ((dst << @intCast(count)) | (src >> @intCast(bits - count))) & m;
        if (count == 1) of = ((res & common.signbit(sz)) != 0) != (cf != 0);
    } else {
        cf = @intCast((dst >> @intCast(count - 1)) & 1);
        res = ((dst >> @intCast(count)) | (src << @intCast(bits - count))) & m;
        if (count == 1) of = (dst & common.signbit(sz)) != 0;
    }
    s.r.eflags &= ~(state.CF | state.OF | state.SF | state.ZF | state.PF | state.AF);
    if (cf != 0) s.r.eflags |= state.CF;
    if (of) s.r.eflags |= state.OF;
    if (res == 0) s.r.eflags |= state.ZF;
    if (res & common.signbit(sz) != 0) s.r.eflags |= state.SF;
    if (@popCount(@as(u8, @truncate(res))) & 1 == 0) s.r.eflags |= state.PF;
    try rmWrite(s, ins, sz, res);
    return .next;
}

// ---- bit tests and scans ---------------------------------------------------------

fn bitTest(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const bits: u8 = sz * 8;
    // 0x100 marks the register forms, whose bit index is ModRM.reg (the
    // same sentinel shld/shrd use for CL).
    const idx: u64 = if (ins.imm == 0x100)
        common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0)
    else
        ins.imm;
    var addr = ins.ea;
    var width: u8 = sz;
    var v: u64 = undefined;
    var bit: u6 = undefined;
    if (ins.mem) {
        if (ins.aux == 1) {
            // An immediate offset is taken modulo the operand width; the
            // address does not move.
            v = try common.readMem(s, ins.ea, sz, ins.pfx.seg);
            bit = @intCast(idx % bits);
        } else {
            // A register offset is signed and moves the bit base by bytes.
            const signed: i64 = @bitCast(idx);
            addr +%= @bitCast(@as(i64, @divFloor(signed, 8)));
            bit = @intCast(@mod(signed, 8));
            width = 1;
            v = try common.readMem(s, addr, 1, ins.pfx.seg);
        }
    } else {
        v = try rmRead(s, ins, sz);
        bit = @intCast(idx % bits);
    }
    const on = (v >> bit) & 1 != 0;
    s.r.eflags = (s.r.eflags & ~state.CF) | (if (on) state.CF else 0);
    if (ins.op != .bt) {
        const nv = switch (ins.op) {
            .bts => v | (@as(u64, 1) << bit),
            .btr => v & ~(@as(u64, 1) << bit),
            else => v ^ (@as(u64, 1) << bit),
        };
        if (ins.mem) {
            try common.writeMem(s, addr, width, ins.pfx.seg, nv);
        } else {
            common.regWrite(s.r, ins.rm, sz, ins.pfx.rex != 0, nv & common.mask(sz));
        }
    }
    return .next;
}

fn bitScan(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const v = try rmRead(s, ins, sz);
    switch (ins.op) {
        .bsf, .bsr => {
            if (v == 0) {
                s.r.eflags |= state.ZF;
                return .next;
            }
            s.r.eflags &= ~state.ZF;
            const r: u64 = if (ins.op == .bsf) @ctz(v) else 63 - @clz(v);
            common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, r);
        },
        .tzcnt, .lzcnt => {
            const width: u64 = sz * 8;
            const r: u64 = if (v == 0) width else if (ins.op == .tzcnt) @ctz(v) else width - 1 - @clz(v);
            common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, r);
            s.r.eflags = (s.r.eflags & ~(state.CF | state.ZF)) | (if (v == 0) state.CF else 0) | (if (r == 0) state.ZF else 0);
        },
        .popcnt => {
            const r: u64 = @popCount(v);
            common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, r);
            s.r.eflags = (s.r.eflags & ~(state.CF | state.ZF)) | (if (r == 0) state.ZF else 0);
        },
        else => unreachable,
    }
    return .next;
}

// ---- control flow ----------------------------------------------------------------

fn jmpOp(s: St, ins: *const Insn) Error!Exit {
    if (ins.has_modrm) {
        const t = try rmRead(s, ins, 8);
        return common.jump(s, t);
    }
    return common.jump(s, s.r.rip +% ins.imm);
}

fn callOp(s: St, ins: *const Insn) Error!Exit {
    var target: u64 = undefined;
    if (ins.has_modrm) {
        target = try rmRead(s, ins, 8);
    } else {
        target = s.r.rip +% ins.imm;
    }
    try pushValue(s, 8, s.r.rip);
    return common.jump(s, target);
}

fn retOp(s: St, ins: *const Insn) Error!Exit {
    const target = try popValue(s, 8);
    if (ins.imm != 0) s.r.rsp +%= ins.imm;
    return common.jump(s, target);
}

fn loopOp(s: St, ins: *const Insn) Error!Exit {
    const addr32 = ins.pfx.addr32;
    const sz: u8 = if (addr32) 4 else 8;
    const c = common.regRead(s.r, 1, sz, false);
    if (ins.op == .jrcxz) {
        if (c == 0) return common.jump(s, s.r.rip +% ins.imm);
        return .next;
    }
    const n = (c -% 1) & common.mask(sz);
    common.regWrite(s.r, 1, sz, false, n);
    const taken = switch (ins.op) {
        .loop => n != 0,
        .loope => n != 0 and s.r.eflags & state.ZF != 0,
        .loopne => n != 0 and s.r.eflags & state.ZF == 0,
        else => false,
    };
    if (taken) return common.jump(s, s.r.rip +% ins.imm);
    return .next;
}

fn cmov(s: St, ins: *const Insn) Error!Exit {
    const v = try rmRead(s, ins, ins.opsz);
    if (common.cond(s.r, ins.cc)) common.regWrite(s.r, ins.reg, ins.opsz, ins.pfx.rex != 0, v);
    return .next;
}

// ---- string instructions ---------------------------------------------------------

fn stringOp(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const addr32 = ins.pfx.addr32;
    // The subtraction has to be 64-bit: `0 -% sz` with sz: u8 would wrap
    // in 8 bits and make the backward step 0xff instead of -1.
    const step: u64 = if (s.r.eflags & state.DF != 0) 0 -% @as(u64, sz) else sz;
    const rep = ins.pfx.rep;
    const have_rep = (ins.op == .movs and rep == 0xf3) or (ins.op == .stos and rep == 0xf3) or
        (ins.op == .lods and rep == 0xf3) or (ins.op == .scas and rep != 0) or (ins.op == .cmps and rep != 0);
    const count: u64 = if (have_rep) common.regRead(s.r, 1, if (addr32) 4 else 8, false) else 1;
    if (have_rep and count == 0) return .next;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const si = common.regRead(s.r, 6, if (addr32) 4 else 8, false);
        const di = common.regRead(s.r, 7, if (addr32) 4 else 8, false);
        switch (ins.op) {
            .movs => {
                const v = try common.readMem(s, si, sz, ins.pfx.seg);
                try common.writeMem(s, di, sz, 0, v);
            },
            .stos => {
                const v = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
                try common.writeMem(s, di, sz, 0, v);
            },
            .lods => {
                const v = try common.readMem(s, si, sz, ins.pfx.seg);
                common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, v);
            },
            .scas => {
                const a = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
                const v = try common.readMem(s, di, sz, 0);
                common.flagsSub(s.r, sz, a, v, 0);
            },
            .cmps => {
                const a = try common.readMem(s, si, sz, ins.pfx.seg);
                const b = try common.readMem(s, di, sz, 0);
                common.flagsSub(s.r, sz, a, b, 0);
            },
            else => unreachable,
        }
        if (ins.op == .movs or ins.op == .lods or ins.op == .cmps) common.regWrite(s.r, 6, if (addr32) 4 else 8, false, si +% step);
        if (ins.op == .movs or ins.op == .stos or ins.op == .cmps or ins.op == .scas) common.regWrite(s.r, 7, if (addr32) 4 else 8, false, di +% step);
        if (have_rep) {
            const n = (common.regRead(s.r, 1, if (addr32) 4 else 8, false) -% 1) & common.mask(if (addr32) 4 else 8);
            common.regWrite(s.r, 1, if (addr32) 4 else 8, false, n);
            if (ins.op == .scas or ins.op == .cmps) {
                const zf = s.r.eflags & state.ZF != 0;
                if ((rep == 0xf3 and !zf) or (rep == 0xf2 and zf)) break;
            }
            if (n == 0) break;
        }
    }
    return .next;
}

// ---- compare-exchange / exchange-add --------------------------------------------

fn cmpxchg(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const acc = common.regRead(s.r, 0, sz, ins.pfx.rex != 0);
    const dst = try rmRead(s, ins, sz);
    if (acc == dst) {
        const src = common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0);
        try rmWrite(s, ins, sz, src);
        s.r.eflags |= state.ZF;
    } else {
        s.r.eflags &= ~state.ZF;
        common.regWrite(s.r, 0, sz, ins.pfx.rex != 0, dst);
    }
    return .next;
}

fn xadd(s: St, ins: *const Insn) Error!Exit {
    const sz = ins.opsz;
    const dst = try rmRead(s, ins, sz);
    const src = common.regRead(s.r, ins.reg, sz, ins.pfx.rex != 0);
    const sum = (dst +% src) & common.mask(sz);
    // Store first: a faulting store must leave flags and the register as
    // they were.
    try rmWrite(s, ins, sz, sum);
    common.flagsAdd(s.r, sz, dst, src, 0);
    common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, dst);
    return .next;
}

fn cmpxchgxb(s: St, ins: *const Insn) Error!Exit {
    if (ins.op == .cmpxchg16b and ins.ea & 15 != 0) return common.misaligned(s, ins.ea);
    if (ins.op == .cmpxchg8b) {
        const mem = try common.readMem(s, ins.ea, 8, ins.pfx.seg);
        const expected: u64 = ((s.r.rdx & 0xffff_ffff) << 32) | (s.r.rax & 0xffff_ffff);
        if (mem == expected) {
            s.r.eflags |= state.ZF;
            const nv: u64 = ((s.r.rcx & 0xffff_ffff) << 32) | (s.r.rbx & 0xffff_ffff);
            try common.writeMem(s, ins.ea, 8, ins.pfx.seg, nv);
        } else {
            s.r.eflags &= ~state.ZF;
            s.r.rax = (s.r.rax & ~@as(u64, 0xffff_ffff)) | (mem & 0xffff_ffff);
            s.r.rdx = (s.r.rdx & ~@as(u64, 0xffff_ffff)) | (mem >> 32);
        }
    } else {
        const lo = try common.readMem(s, ins.ea, 8, ins.pfx.seg);
        const hi = try common.readMem(s, ins.ea + 8, 8, ins.pfx.seg);
        if (lo == s.r.rax and hi == s.r.rdx) {
            s.r.eflags |= state.ZF;
            try common.writeMem(s, ins.ea, 8, ins.pfx.seg, s.r.rbx);
            try common.writeMem(s, ins.ea + 8, 8, ins.pfx.seg, s.r.rcx);
        } else {
            s.r.eflags &= ~state.ZF;
            s.r.rax = lo;
            s.r.rdx = hi;
        }
    }
    return .next;
}

// ---- conversions / flags ---------------------------------------------------------

fn cbw(s: St, ins: *const Insn) Error!Exit {
    switch (ins.opsz) {
        2 => {
            const al = s.r.rax & 0xff;
            s.r.rax = (s.r.rax & ~@as(u64, 0xffff)) | (common.sextR(al, 8) & 0xffff);
        },
        4 => {
            const ax = s.r.rax & 0xffff;
            s.r.rax = (s.r.rax & ~@as(u64, 0xffff_ffff)) | (common.sextR(ax, 16) & 0xffff_ffff);
        },
        else => {
            const eax = s.r.rax & 0xffff_ffff;
            s.r.rax = common.sextR(eax, 32);
        },
    }
    return .next;
}

fn cwd(s: St, ins: *const Insn) Error!Exit {
    switch (ins.opsz) {
        2 => {
            const ax = s.r.rax & 0xffff;
            const hi: u64 = if (ax & 0x8000 != 0) 0xffff else 0;
            s.r.rdx = (s.r.rdx & ~@as(u64, 0xffff)) | hi;
        },
        4 => {
            const eax = s.r.rax & 0xffff_ffff;
            const hi: u64 = if (eax & 0x8000_0000 != 0) 0xffff_ffff else 0;
            s.r.rdx = (s.r.rdx & ~@as(u64, 0xffff_ffff)) | hi;
        },
        else => {
            s.r.rdx = if (s.r.rax & 0x8000_0000_0000_0000 != 0) std.math.maxInt(u64) else 0;
        },
    }
    return .next;
}

fn pushf(s: St, ins: *const Insn) Error!Exit {
    const sz: u8 = if (ins.opsz == 2 or ins.pfx.opsz16) 2 else 8;
    var f = s.r.eflags | state.FLAGS_RESERVED;
    if (sz == 2) f &= 0xffff;
    try pushValue(s, sz, f);
    return .next;
}

fn popf(s: St, ins: *const Insn) Error!Exit {
    const sz: u8 = if (ins.pfx.opsz16) 2 else 8;
    const f = try popValue(s, sz);
    const keep = s.r.eflags & ~@as(u64, 0xffff);
    const set = f & 0xffff;
    s.r.eflags = if (sz == 2) (keep | set) else f;
    s.r.eflags |= state.FLAGS_RESERVED;
    return .next;
}

fn enter(s: St, ins: *const Insn) Error!Exit {
    const size: u64 = ins.imm & 0xffff;
    try pushValue(s, 8, s.r.rbp);
    const frame = s.r.rsp;
    s.r.rbp = frame;
    s.r.rsp -%= size;
    return .next;
}

// ---- system ----------------------------------------------------------------------

fn cpuid(s: St) Error!Exit {
    const leaf: u32 = @truncate(s.r.rax);
    var a: u32 = 0;
    var b: u32 = 0;
    var c: u32 = 0;
    var d: u32 = 0;
    switch (leaf) {
        0 => {
            a = 0x0d;
            b = 0x756e_6547; // "Genu"
            d = 0x4965_6e69; // "ineI"
            c = 0x6c65_746e; // "ntel"
        },
        1 => {
            a = 0x0006_06a3; // family 6, model 6, stepping 3
            b = 0;
            c = 0; // baseline only: no SSE3+/SSSE3/SSE4/POPCNT/CX16
            d = (1 << 0) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 11) |
                (1 << 13) | (1 << 15) | (1 << 19) | (1 << 23) | (1 << 24) |
                (1 << 25) | (1 << 26);
            // FPU, TSC, MSR, PAE, CX8, SEP, PGE, CMOV, CLFSH, MMX, FXSR,
            // SSE, SSE2.
        },
        7 => {
            a = 0;
            b = 0;
            c = 0;
            d = 0;
        },
        0x8000_0000 => a = 0x8000_0008,
        0x8000_0001 => {
            a = 0x0006_06a3;
            c = 1; // LAHF/SAHF in long mode
            d = (1 << 11) | (1 << 20) | (1 << 27) | (1 << 29);
            // SYSCALL, NX, RDTSCP, LM.
        },
        0x8000_0008 => {
            a = 0x3030; // 48-bit physical and virtual addresses
            b = 0;
            c = 0;
            d = 0;
        },
        else => {},
    }
    s.r.rax = a;
    s.r.rbx = b;
    s.r.rcx = c;
    s.r.rdx = d;
    return .next;
}

fn rdtsc(s: St, aux: bool) Error!Exit {
    const t = s.m.icount *% 3;
    s.r.rax = @truncate(t);
    s.r.rdx = t >> 32;
    if (aux) s.r.rcx = 0;
    return .next;
}

// ---- SSE -------------------------------------------------------------------------
//
// An XMM register is two 64-bit little-endian halves (`Vec`), the same
// memory image as the C header's `uint64_t xmm[16][2]`. Lanes are taken
// with u64 shifts only: a 128-bit shift becomes __lshrti3 on wasm, which
// the kernel does not link (a64/common.zig has the same rule).

pub const Vec = [2]u64;

inline fn u8s(v: Vec) [16]u8 {
    var r: [16]u8 = undefined;
    inline for (0..8) |i| {
        r[i] = @truncate(v[0] >> (8 * i));
        r[8 + i] = @truncate(v[1] >> (8 * i));
    }
    return r;
}
inline fn fromU8s(a: [16]u8) Vec {
    var lo: u64 = 0;
    var hi: u64 = 0;
    inline for (0..8) |i| {
        lo |= @as(u64, a[i]) << (8 * i);
        hi |= @as(u64, a[8 + i]) << (8 * i);
    }
    return .{ lo, hi };
}
inline fn u16s(v: Vec) [8]u16 {
    var r: [8]u16 = undefined;
    inline for (0..4) |i| {
        r[i] = @truncate(v[0] >> (16 * i));
        r[4 + i] = @truncate(v[1] >> (16 * i));
    }
    return r;
}
inline fn fromU16s(a: [8]u16) Vec {
    var lo: u64 = 0;
    var hi: u64 = 0;
    inline for (0..4) |i| {
        lo |= @as(u64, a[i]) << (16 * i);
        hi |= @as(u64, a[4 + i]) << (16 * i);
    }
    return .{ lo, hi };
}
inline fn u32s(v: Vec) [4]u32 {
    return .{ @truncate(v[0]), @truncate(v[0] >> 32), @truncate(v[1]), @truncate(v[1] >> 32) };
}
inline fn fromU32s(a: [4]u32) Vec {
    return .{ @as(u64, a[0]) | (@as(u64, a[1]) << 32), @as(u64, a[2]) | (@as(u64, a[3]) << 32) };
}
inline fn f32s(v: Vec) [4]f32 {
    const a = u32s(v);
    return .{ @bitCast(a[0]), @bitCast(a[1]), @bitCast(a[2]), @bitCast(a[3]) };
}
inline fn fromF32s(a: [4]f32) Vec {
    return fromU32s(.{ @bitCast(a[0]), @bitCast(a[1]), @bitCast(a[2]), @bitCast(a[3]) });
}
inline fn f64s(v: Vec) [2]f64 {
    return .{ @bitCast(v[0]), @bitCast(v[1]) };
}
inline fn fromF64s(a: [2]f64) Vec {
    return .{ @bitCast(a[0]), @bitCast(a[1]) };
}

fn sseSrc(s: St, ins: *const Insn) Error!Vec {
    if (ins.mem) return common.readMem128(s, ins.ea, ins.pfx.seg);
    return s.r.xmm[ins.rm];
}

fn sseStore(s: St, ins: *const Insn, v: Vec) Error!void {
    if (ins.mem) return common.writeMem128(s, ins.ea, ins.pfx.seg, v);
    s.r.xmm[ins.rm] = v;
}

fn cmpF32(pred: u8, a: f32, b: f32) bool {
    return switch (pred & 7) {
        0 => a == b,
        1 => a < b,
        2 => a <= b,
        3 => std.math.isNan(a) or std.math.isNan(b),
        4 => a != b,
        5 => !(a < b),
        6 => !(a <= b),
        else => !std.math.isNan(a) and !std.math.isNan(b),
    };
}

fn minx(a: f32, b: f32) f32 {
    if (std.math.isNan(a) or std.math.isNan(b)) return b;
    if (a == 0 and b == 0) return b;
    return if (a < b) a else b;
}
fn maxx(a: f32, b: f32) f32 {
    if (std.math.isNan(a) or std.math.isNan(b)) return b;
    if (a == 0 and b == 0) return b;
    return if (a > b) a else b;
}
fn minxD(a: f64, b: f64) f64 {
    if (std.math.isNan(a) or std.math.isNan(b)) return b;
    if (a == 0 and b == 0) return b;
    return if (a < b) a else b;
}
fn maxxD(a: f64, b: f64) f64 {
    if (std.math.isNan(a) or std.math.isNan(b)) return b;
    if (a == 0 and b == 0) return b;
    return if (a > b) a else b;
}

fn roundEven(x: f64) f64 {
    const fl = @floor(x);
    const d = x - fl;
    if (d < 0.5) return fl;
    if (d > 0.5) return fl + 1;
    return if (@mod(fl, 2) == 0) fl else fl + 1;
}

fn sseOp(s: St, ins: *const Insn) Error!Exit {
    const dst = &s.r.xmm[ins.reg];
    const imm = @as(u8, @truncate(ins.imm));
    switch (ins.sse) {
        .movups, .movupd, .movdqu, .lddqu => {
            if (ins.aux == 1) {
                const v = dst.*;
                try sseStore(s, ins, v);
            } else {
                dst.* = try sseSrc(s, ins);
            }
        },
        .movaps, .movapd, .movdqa => {
            if (ins.mem and ins.ea & 15 != 0) return common.misaligned(s, ins.ea);
            if (ins.aux == 1) {
                const v = dst.*;
                try sseStore(s, ins, v);
            } else {
                dst.* = try sseSrc(s, ins);
            }
        },
        .movss => {
            if (ins.aux == 1) {
                const v = dst[0];
                if (ins.mem) {
                    try common.writeMem(s, ins.ea, 4, ins.pfx.seg, @truncate(v));
                } else {
                    var cur = s.r.xmm[ins.rm];
                    cur[0] = (cur[0] & ~@as(u64, 0xffff_ffff)) | (v & 0xffff_ffff);
                    s.r.xmm[ins.rm] = cur;
                }
            } else {
                const x: u64 = if (ins.mem) try common.readMem(s, ins.ea, 4, ins.pfx.seg) else s.r.xmm[ins.rm][0];
                if (ins.mem) {
                    dst.* = .{ x & 0xffff_ffff, 0 };
                } else {
                    dst[0] = (dst[0] & ~@as(u64, 0xffff_ffff)) | (x & 0xffff_ffff);
                }
            }
        },
        .movsd => {
            if (ins.aux == 1) {
                const v = dst[0];
                if (ins.mem) {
                    try common.writeMem(s, ins.ea, 8, ins.pfx.seg, v);
                } else {
                    s.r.xmm[ins.rm][0] = v;
                }
            } else {
                const x: u64 = if (ins.mem) try common.readMem(s, ins.ea, 8, ins.pfx.seg) else s.r.xmm[ins.rm][0];
                if (ins.mem) {
                    dst.* = .{ x, 0 };
                } else {
                    dst[0] = x;
                }
            }
        },
        .movd => {
            if (ins.aux == 1) {
                const v = dst[0];
                if (ins.mem) {
                    try common.writeMem(s, ins.ea, ins.opsz, ins.pfx.seg, v);
                } else common.regWrite(s.r, ins.rm, ins.opsz, ins.pfx.rex != 0, v);
            } else {
                const v = try rmRead(s, ins, ins.opsz);
                dst.* = .{ v, 0 };
            }
        },
        .movq => {
            if (ins.aux == 1) { // 66 0F D6: m64/xmm <- xmm low
                const v = dst[0];
                if (ins.mem) {
                    try common.writeMem(s, ins.ea, 8, ins.pfx.seg, v);
                } else s.r.xmm[ins.rm] = .{ v, 0 };
            } else { // F3 0F 7E: xmm <- m64/xmm low
                const v: u64 = if (ins.mem) try common.readMem(s, ins.ea, 8, ins.pfx.seg) else s.r.xmm[ins.rm][0];
                dst.* = .{ v, 0 };
            }
        },
        .movlps => {
            if (ins.aux == 1) {
                if (!ins.mem) return common.ill(s, ins.raw);
                try common.writeMem(s, ins.ea, 8, ins.pfx.seg, dst[0]);
            } else if (ins.md == 3) { // MOVHLPS
                dst[0] = s.r.xmm[ins.rm][1];
            } else {
                dst[0] = try common.readMem(s, ins.ea, 8, ins.pfx.seg);
            }
        },
        .movhps => {
            if (ins.aux == 1) {
                if (!ins.mem) return common.ill(s, ins.raw);
                try common.writeMem(s, ins.ea, 8, ins.pfx.seg, dst[1]);
            } else if (ins.md == 3) { // MOVLHPS
                dst[1] = s.r.xmm[ins.rm][0];
            } else {
                dst[1] = try common.readMem(s, ins.ea, 8, ins.pfx.seg);
            }
        },
        .movsldup => {
            const a = u32s(s.r.xmm[ins.rm]);
            dst.* = fromU32s(.{ a[0], a[0], a[2], a[2] });
        },
        .movshdup => {
            const a = u32s(s.r.xmm[ins.rm]);
            dst.* = fromU32s(.{ a[1], a[1], a[3], a[3] });
        },
        .movddup => {
            const a = s.r.xmm[ins.rm][0];
            dst.* = .{ a, a };
        },
        .movmskps => {
            const a = u32s(s.r.xmm[ins.rm]);
            var r: u64 = 0;
            inline for (0..4) |i| r |= @as(u64, a[i] >> 31) << i;
            common.regWrite(s.r, ins.reg, 4, ins.pfx.rex != 0, r);
        },
        .movmskpd => {
            const a = s.r.xmm[ins.rm];
            var r: u64 = 0;
            inline for (0..2) |i| r |= (a[i] >> 63) << i;
            common.regWrite(s.r, ins.reg, 4, ins.pfx.rex != 0, r);
        },
        .movntps, .movntpd, .movntdq => try sseStore(s, ins, dst.*),
        .maskmovdqu => {
            const mask = u8s(s.r.xmm[ins.reg]);
            const data = u8s(s.r.xmm[ins.rm]);
            var i: usize = 0;
            while (i < 16) : (i += 1) {
                if (mask[i] & 0x80 != 0) try common.writeMem(s, s.r.rdi +% i, 1, 0, data[i]);
            }
        },
        .unpcklps => {
            const a = u32s(dst.*);
            const b = u32s(try sseSrc(s, ins));
            dst.* = fromU32s(.{ a[0], b[0], a[1], b[1] });
        },
        .unpckhps => {
            const a = u32s(dst.*);
            const b = u32s(try sseSrc(s, ins));
            dst.* = fromU32s(.{ a[2], b[2], a[3], b[3] });
        },
        .unpcklpd => {
            dst.* = .{ dst[0], (try sseSrc(s, ins))[0] };
        },
        .unpckhpd => {
            dst.* = .{ dst[1], (try sseSrc(s, ins))[1] };
        },
        .shufps => {
            const a = u32s(dst.*);
            const b = u32s(try sseSrc(s, ins));
            dst.* = fromU32s(.{ a[imm & 3], a[(imm >> 2) & 3], b[(imm >> 4) & 3], b[(imm >> 6) & 3] });
        },
        .shufpd => {
            const a = dst.*;
            const b = try sseSrc(s, ins);
            dst.* = .{ a[imm & 1], b[(imm >> 1) & 1] };
        },
        .pshufd => {
            const a = u32s(try sseSrc(s, ins));
            dst.* = fromU32s(.{ a[imm & 3], a[(imm >> 2) & 3], a[(imm >> 4) & 3], a[(imm >> 6) & 3] });
        },
        .pshufhw => {
            const a = u16s(try sseSrc(s, ins));
            dst.* = fromU16s(.{ a[0], a[1], a[2], a[3], a[4 + (imm & 3)], a[4 + ((imm >> 2) & 3)], a[4 + ((imm >> 4) & 3)], a[4 + ((imm >> 6) & 3)] });
        },
        .pshuflw => {
            const a = u16s(try sseSrc(s, ins));
            dst.* = fromU16s(.{ a[imm & 3], a[(imm >> 2) & 3], a[(imm >> 4) & 3], a[(imm >> 6) & 3], a[4], a[5], a[6], a[7] });
        },
        .pshufw => {
            const a = u16s(try sseSrc(s, ins));
            dst.* = fromU16s(.{ a[imm & 3], a[(imm >> 2) & 3], a[(imm >> 4) & 3], a[(imm >> 6) & 3], 0, 0, 0, 0 });
        },
        .addps, .subps, .mulps, .divps, .minps, .maxps, .sqrtps, .cmpps => {
            const a = f32s(dst.*);
            const b = f32s(try sseSrc(s, ins));
            if (ins.sse == .cmpps) {
                var rb: [4]u32 = undefined;
                inline for (0..4) |i| rb[i] = if (cmpF32(imm, a[i], b[i])) 0xffff_ffff else 0;
                dst.* = fromU32s(rb);
                return .next;
            }
            var r: [4]f32 = undefined;
            inline for (0..4) |i| {
                r[i] = switch (ins.sse) {
                    .addps => a[i] + b[i],
                    .subps => a[i] - b[i],
                    .mulps => a[i] * b[i],
                    .divps => a[i] / b[i],
                    .minps => minx(a[i], b[i]),
                    .maxps => maxx(a[i], b[i]),
                    else => @sqrt(b[i]),
                };
            }
            dst.* = fromF32s(r);
        },
        .addpd, .subpd, .mulpd, .divpd, .minpd, .maxpd, .sqrtpd, .cmppd => {
            const a = f64s(dst.*);
            const b = f64s(try sseSrc(s, ins));
            if (ins.sse == .cmppd) {
                var rb: [2]u64 = undefined;
                inline for (0..2) |i| rb[i] = if (cmpF64(imm, a[i], b[i]) != 0) 0xffff_ffff_ffff_ffff else 0;
                dst.* = rb;
                return .next;
            }
            var r: [2]f64 = undefined;
            inline for (0..2) |i| {
                r[i] = switch (ins.sse) {
                    .addpd => a[i] + b[i],
                    .subpd => a[i] - b[i],
                    .mulpd => a[i] * b[i],
                    .divpd => a[i] / b[i],
                    .minpd => minxD(a[i], b[i]),
                    .maxpd => maxxD(a[i], b[i]),
                    else => @sqrt(b[i]),
                };
            }
            dst.* = fromF64s(r);
        },
        .addss, .subss, .mulss, .divss, .minss, .maxss, .sqrtss, .cmpss => {
            const a = f32s(dst.*);
            const b = f32s(try sseSrc(s, ins));
            if (ins.sse == .cmpss) {
                const cur = u32s(dst.*);
                var r = cur;
                r[0] = if (cmpF32(imm, a[0], b[0])) 0xffff_ffff else 0;
                dst.* = fromU32s(r);
                return .next;
            }
            var r = a;
            r[0] = switch (ins.sse) {
                .addss => a[0] + b[0],
                .subss => a[0] - b[0],
                .mulss => a[0] * b[0],
                .divss => a[0] / b[0],
                .minss => minx(a[0], b[0]),
                .maxss => maxx(a[0], b[0]),
                else => @sqrt(b[0]),
            };
            dst.* = fromF32s(r);
        },
        .addsd, .subsd, .mulsd, .divsd, .minsd, .maxsd, .sqrtsd, .cmpsd => {
            var a = f64s(dst.*);
            const b = f64s(try sseSrc(s, ins));
            if (ins.sse == .cmpsd) {
                const cur = dst.*;
                dst.* = .{ if (cmpF64(imm, a[0], b[0]) != 0) 0xffff_ffff_ffff_ffff else 0, cur[1] };
                return .next;
            }
            a[0] = switch (ins.sse) {
                .addsd => a[0] + b[0],
                .subsd => a[0] - b[0],
                .mulsd => a[0] * b[0],
                .divsd => a[0] / b[0],
                .minsd => minxD(a[0], b[0]),
                .maxsd => maxxD(a[0], b[0]),
                else => @sqrt(b[0]),
            };
            dst.* = fromF64s(a);
        },
        .andps, .andpd => {
            const v = try sseSrc(s, ins);
            dst[0] &= v[0];
            dst[1] &= v[1];
        },
        .andnps, .andnpd => {
            const v = try sseSrc(s, ins);
            dst.* = .{ ~dst[0] & v[0], ~dst[1] & v[1] };
        },
        .orps, .orpd => {
            const v = try sseSrc(s, ins);
            dst[0] |= v[0];
            dst[1] |= v[1];
        },
        .xorps, .xorpd => {
            const v = try sseSrc(s, ins);
            dst[0] ^= v[0];
            dst[1] ^= v[1];
        },
        .comiss, .ucomiss, .comisd, .ucomisd => {
            const is_d = ins.sse == .comisd or ins.sse == .ucomisd;
            var a: f64 = undefined;
            var b: f64 = undefined;
            if (is_d) {
                a = f64s(dst.*)[0];
                b = f64s(try sseSrc(s, ins))[0];
            } else {
                a = f32s(dst.*)[0];
                b = f32s(try sseSrc(s, ins))[0];
            }
            s.r.eflags &= ~(state.ZF | state.PF | state.CF | state.OF | state.AF | state.SF);
            if (std.math.isNan(a) or std.math.isNan(b)) {
                s.r.eflags |= state.ZF | state.PF | state.CF;
            } else if (a < b) {
                s.r.eflags |= state.CF;
            } else if (a == b) {
                s.r.eflags |= state.ZF;
            }
        },
        .cvtsi2ss => {
            const iv = try rmRead(s, ins, ins.opsz);
            const x: f32 = @floatFromInt(@as(i64, @bitCast(common.sextR(iv, ins.opsz * 8))));
            var r = f32s(dst.*);
            r[0] = x;
            dst.* = fromF32s(r);
        },
        .cvtsi2sd => {
            const iv = try rmRead(s, ins, ins.opsz);
            const x: f64 = @floatFromInt(@as(i64, @bitCast(common.sextR(iv, ins.opsz * 8))));
            var r = f64s(dst.*);
            r[0] = x;
            dst.* = fromF64s(r);
        },
        .cvttss2si, .cvtss2si, .cvttsd2si, .cvtsd2si => {
            const is_d = ins.sse == .cvttsd2si or ins.sse == .cvtsd2si;
            const trunc = ins.sse == .cvttss2si or ins.sse == .cvttsd2si;
            const sz: u8 = if (ins.pfx.w()) 8 else 4;
            const f: f64 = if (is_d) f64s(try sseSrc(s, ins))[0] else f32s(try sseSrc(s, ins))[0];
            var iv: i64 = undefined;
            if (std.math.isNan(f)) {
                iv = if (sz == 8) std.math.minInt(i64) else std.math.minInt(i32);
            } else {
                const r = if (trunc) @trunc(f) else roundEven(f);
                const limit: f64 = if (sz == 8) 9.2233720368547758e18 else 2147483648.0;
                if (r >= limit or r < -limit) {
                    iv = if (sz == 8) std.math.minInt(i64) else std.math.minInt(i32);
                } else iv = @intFromFloat(r);
            }
            common.regWrite(s.r, ins.reg, sz, ins.pfx.rex != 0, @bitCast(iv));
        },
        .cvtss2sd => {
            const f = f32s(try sseSrc(s, ins))[0];
            var r = f64s(dst.*);
            r[0] = f;
            dst.* = fromF64s(r);
        },
        .cvtsd2ss => {
            const f = f64s(try sseSrc(s, ins))[0];
            var r = f32s(dst.*);
            r[0] = @floatCast(f);
            dst.* = fromF32s(r);
        },
        .cvtdq2ps => {
            const a = u32s(try sseSrc(s, ins));
            var r: [4]f32 = undefined;
            inline for (0..4) |i| r[i] = @floatFromInt(@as(i32, @bitCast(a[i])));
            dst.* = fromF32s(r);
        },
        .cvtps2dq, .cvttps2dq => {
            const a = f32s(try sseSrc(s, ins));
            var r: [4]u32 = undefined;
            inline for (0..4) |i| {
                const v = if (ins.sse == .cvttps2dq) @trunc(a[i]) else roundEven(a[i]);
                r[i] = @bitCast(@as(i32, if (std.math.isNan(a[i]) or v >= 2147483648.0 or v < -2147483648.0) std.math.minInt(i32) else @intFromFloat(v)));
            }
            dst.* = fromU32s(r);
        },
        .cvtps2pd => {
            const a = f32s(try sseSrc(s, ins));
            dst.* = fromF64s(.{ a[0], a[1] });
        },
        .cvtpd2ps => {
            const a = f64s(try sseSrc(s, ins));
            dst.* = fromF32s(.{ @floatCast(a[0]), @floatCast(a[1]), 0, 0 });
        },
        .cvtdq2pd => {
            const a = u32s(try sseSrc(s, ins));
            dst.* = fromF64s(.{ @floatFromInt(@as(i32, @bitCast(a[0]))), @floatFromInt(@as(i32, @bitCast(a[1]))) });
        },
        .cvtpd2dq, .cvttpd2dq => {
            const a = f64s(try sseSrc(s, ins));
            var r: [4]u32 = .{ 0, 0, 0, 0 };
            inline for (0..2) |i| {
                const v = if (ins.sse == .cvttpd2dq) @trunc(a[i]) else roundEven(a[i]);
                r[i] = @bitCast(@as(i32, if (std.math.isNan(a[i]) or v >= 2147483648.0 or v < -2147483648.0) std.math.minInt(i32) else @intFromFloat(v)));
            }
            dst.* = fromU32s(r);
        },
        .ldmxcsr => {
            const v = try common.readMem(s, ins.ea, 4, ins.pfx.seg);
            s.r.mxcsr = @truncate(v);
        },
        .stmxcsr => try common.writeMem(s, ins.ea, 4, ins.pfx.seg, s.r.mxcsr),
        .paddb, .paddw, .paddd, .paddq, .paddsb, .paddsw, .paddusb, .paddusw, .psubb, .psubw, .psubd, .psubq, .psubsb, .psubsw, .psubusb, .psubusw => {
            dst.* = packAddSub(ins.sse, dst.*, try sseSrc(s, ins));
        },
        .pcmpeqb, .pcmpeqw, .pcmpeqd => {
            dst.* = packCompare(ins.sse, dst.*, try sseSrc(s, ins), false);
        },
        .pcmpgtb, .pcmpgtw, .pcmpgtd => {
            dst.* = packCompare(ins.sse, dst.*, try sseSrc(s, ins), true);
        },
        .pmullw, .pmulhw, .pmulhuw, .pmuludq, .pmaddwd, .psadbw, .pavgb, .pavgw, .pminub, .pminsw, .pmaxub, .pmaxsw, .packsswb, .packssdw, .packuswb, .punpcklbw, .punpcklwd, .punpckldq, .punpcklqdq, .punpckhbw, .punpckhwd, .punpckhdq, .punpckhqdq, .psllw, .pslld, .psllq, .psrlw, .psrld, .psrlq, .psraw, .psrad => {
            const v = try packMisc(s, ins, dst.*);
            // The shift-by-immediate forms (0x71..0x73) name their register
            // in ModRM.rm and use reg as the opcode extension: packMisc has
            // written it already, and writing reg here would clobber it.
            if (ins.aux != 2) dst.* = v;
        },
        .pand => {
            const b = try sseSrc(s, ins);
            dst.* = .{ dst[0] & b[0], dst[1] & b[1] };
        },
        .pandn => {
            const b = try sseSrc(s, ins);
            dst.* = .{ ~dst[0] & b[0], ~dst[1] & b[1] };
        },
        .por => {
            const b = try sseSrc(s, ins);
            dst.* = .{ dst[0] | b[0], dst[1] | b[1] };
        },
        .pxor => {
            const b = try sseSrc(s, ins);
            dst.* = .{ dst[0] ^ b[0], dst[1] ^ b[1] };
        },
        .pmovmskb => {
            const a = u8s(s.r.xmm[ins.rm]);
            var r: u64 = 0;
            inline for (0..16) |i| r |= @as(u64, a[i] >> 7) << i;
            common.regWrite(s.r, ins.reg, 4, ins.pfx.rex != 0, r);
        },
        .pslldq, .psrldq => {
            // Byte shifts on the two halves: an array shift here becomes a
            // memcpy call, which the kernel does not link. These forms name
            // their register in ModRM.rm (ModRM.reg is the opcode
            // extension), so `dst` (xmm[reg]) is not the operand.
            const d = &s.r.xmm[ins.rm];
            const n: u32 = imm & 0xff;
            const b: u32 = n * 8;
            const v = d.*;
            if (n >= 16) {
                d.* = .{ 0, 0 };
            } else if (b == 0) {
                // unchanged
            } else if (ins.sse == .pslldq) {
                d.* = if (b < 64)
                    .{ v[0] << @intCast(b), (v[1] << @intCast(b)) | (v[0] >> @intCast(64 - b)) }
                else
                    .{ 0, v[0] << @intCast(b - 64) };
            } else {
                d.* = if (b < 64)
                    .{ (v[0] >> @intCast(b)) | (v[1] << @intCast(64 - b)), v[1] >> @intCast(b) }
                else
                    .{ v[1] >> @intCast(b - 64), 0 };
            }
        },
        .pinsrw => {
            const src = try rmRead(s, ins, 2);
            const i = imm & 7;
            dst[i] = (dst[i] & ~@as(u64, 0xffff)) | (src & 0xffff);
        },
        .pextrw => {
            if (ins.md != 3) return common.ill(s, ins.raw);
            const w = u16s(s.r.xmm[ins.rm])[imm & 7];
            common.regWrite(s.r, ins.reg, 4, ins.pfx.rex != 0, w);
        },
        else => unreachable,
    }
    return .next;
}

fn cmpF64(pred: u8, a: f64, b: f64) f64 {
    const on = switch (pred & 7) {
        0 => a == b,
        1 => a < b,
        2 => a <= b,
        3 => std.math.isNan(a) or std.math.isNan(b),
        4 => a != b,
        5 => !(a < b),
        6 => !(a <= b),
        else => !std.math.isNan(a) and !std.math.isNan(b),
    };
    return if (on) 1.0 else 0.0;
}

fn packAddSub(op: Sse, a: Vec, b: Vec) Vec {
    switch (op) {
        .paddb, .psubb => {
            const x = u8s(a);
            const y = u8s(b);
            var r: [16]u8 = undefined;
            inline for (0..16) |i| r[i] = if (op == .paddb) x[i] +% y[i] else x[i] -% y[i];
            return fromU8s(r);
        },
        .paddw, .psubw => {
            const x = u16s(a);
            const y = u16s(b);
            var r: [8]u16 = undefined;
            inline for (0..8) |i| r[i] = if (op == .paddw) x[i] +% y[i] else x[i] -% y[i];
            return fromU16s(r);
        },
        .paddd, .psubd => {
            const x = u32s(a);
            const y = u32s(b);
            var r: [4]u32 = undefined;
            inline for (0..4) |i| r[i] = if (op == .paddd) x[i] +% y[i] else x[i] -% y[i];
            return fromU32s(r);
        },
        .paddq, .psubq => {
            return .{ if (op == .paddq) a[0] +% b[0] else a[0] -% b[0], if (op == .paddq) a[1] +% b[1] else a[1] -% b[1] };
        },
        .paddsb, .psubsb => {
            const x: [16]i8 = @bitCast(a);
            const y: [16]i8 = @bitCast(b);
            var r: [16]i8 = undefined;
            inline for (0..16) |i| r[i] = if (op == .paddsb) satI8(@as(i16, x[i]) + y[i]) else satI8(@as(i16, x[i]) - y[i]);
            return @bitCast(r);
        },
        .paddsw, .psubsw => {
            const x: [8]i16 = @bitCast(a);
            const y: [8]i16 = @bitCast(b);
            var r: [8]i16 = undefined;
            inline for (0..8) |i| r[i] = if (op == .paddsw) satI16(@as(i32, x[i]) + y[i]) else satI16(@as(i32, x[i]) - y[i]);
            return @bitCast(r);
        },
        .paddusb, .psubusb => {
            const x = u8s(a);
            const y = u8s(b);
            var r: [16]u8 = undefined;
            inline for (0..16) |i| r[i] = if (op == .paddusb) @intCast(@min(@as(u16, x[i]) + y[i], 255)) else (if (x[i] > y[i]) x[i] - y[i] else 0);
            return fromU8s(r);
        },
        .paddusw, .psubusw => {
            const x = u16s(a);
            const y = u16s(b);
            var r: [8]u16 = undefined;
            inline for (0..8) |i| r[i] = if (op == .paddusw) @intCast(@min(@as(u32, x[i]) + y[i], 65535)) else (if (x[i] > y[i]) x[i] - y[i] else 0);
            return fromU16s(r);
        },
        else => unreachable,
    }
}

fn satI8(v: i16) i8 {
    return @intCast(std.math.clamp(v, -128, 127));
}
fn satI16(v: i32) i16 {
    return @intCast(std.math.clamp(v, -32768, 32767));
}

fn packCompare(op: Sse, a: Vec, b: Vec, gt: bool) Vec {
    switch (op) {
        .pcmpeqb, .pcmpgtb => {
            const x: [16]i8 = @bitCast(a);
            const y: [16]i8 = @bitCast(b);
            var r: [16]u8 = undefined;
            inline for (0..16) |i| r[i] = if (if (gt) x[i] > y[i] else x[i] == y[i]) 0xff else 0;
            return fromU8s(r);
        },
        .pcmpeqw, .pcmpgtw => {
            const x: [8]i16 = @bitCast(a);
            const y: [8]i16 = @bitCast(b);
            var r: [8]u16 = undefined;
            inline for (0..8) |i| r[i] = if (if (gt) x[i] > y[i] else x[i] == y[i]) 0xffff else 0;
            return fromU16s(r);
        },
        else => {
            const x: [4]i32 = @bitCast(a);
            const y: [4]i32 = @bitCast(b);
            var r: [4]u32 = undefined;
            inline for (0..4) |i| r[i] = if (if (gt) x[i] > y[i] else x[i] == y[i]) 0xffff_ffff else 0;
            return fromU32s(r);
        },
    }
}

fn packMisc(s: St, ins: *const Insn, a: Vec) Error!Vec {
    if (ins.sse == .psllw or ins.sse == .pslld or ins.sse == .psllq or
        ins.sse == .psrlw or ins.sse == .psrld or ins.sse == .psrlq or
        ins.sse == .psraw or ins.sse == .psrad)
    {
        if (ins.aux == 2) {
            const dst = &s.r.xmm[ins.rm];
            dst.* = packShift(ins.sse, dst.*, @truncate(ins.imm));
            return dst.*;
        }
        const b = try sseSrc(s, ins);
        return packShift(ins.sse, a, @truncate(b[0]));
    }
    const b = try sseSrc(s, ins);
    switch (ins.sse) {
        .pmullw => {
            const x = u16s(a);
            const y = u16s(b);
            var r: [8]u16 = undefined;
            inline for (0..8) |i| r[i] = x[i] *% y[i];
            return fromU16s(r);
        },
        .pmulhw => {
            const x: [8]i16 = @bitCast(a);
            const y: [8]i16 = @bitCast(b);
            var r: [8]i16 = undefined;
            inline for (0..8) |i| r[i] = @truncate((@as(i32, x[i]) * y[i]) >> 16);
            return @bitCast(r);
        },
        .pmulhuw => {
            const x = u16s(a);
            const y = u16s(b);
            var r: [8]u16 = undefined;
            inline for (0..8) |i| r[i] = @truncate((@as(u32, x[i]) * y[i]) >> 16);
            return fromU16s(r);
        },
        .pmuludq => {
            const x = u32s(a);
            const y = u32s(b);
            return .{ @as(u64, x[0]) * y[0], @as(u64, x[2]) * y[2] };
        },
        .pmaddwd => {
            const x: [8]i16 = @bitCast(a);
            const y: [8]i16 = @bitCast(b);
            var r: [4]i32 = undefined;
            inline for (0..4) |i| r[i] = @as(i32, x[2 * i]) * y[2 * i] + @as(i32, x[2 * i + 1]) * y[2 * i + 1];
            return @bitCast(r);
        },
        .psadbw => {
            const x = u8s(a);
            const y = u8s(b);
            var r0: u64 = 0;
            var r1: u64 = 0;
            inline for (0..8) |i| r0 += @abs(@as(i16, x[i]) - @as(i16, y[i]));
            inline for (0..8) |i| r1 += @abs(@as(i16, x[8 + i]) - @as(i16, y[8 + i]));
            return .{ r0, r1 };
        },
        .pavgb => {
            const x = u8s(a);
            const y = u8s(b);
            var r: [16]u8 = undefined;
            inline for (0..16) |i| r[i] = @intCast((@as(u16, x[i]) + y[i] + 1) >> 1);
            return fromU8s(r);
        },
        .pavgw => {
            const x = u16s(a);
            const y = u16s(b);
            var r: [8]u16 = undefined;
            inline for (0..8) |i| r[i] = @intCast((@as(u32, x[i]) + y[i] + 1) >> 1);
            return fromU16s(r);
        },
        .pminub, .pmaxub => {
            const x = u8s(a);
            const y = u8s(b);
            var r: [16]u8 = undefined;
            inline for (0..16) |i| r[i] = if (ins.sse == .pminub) @min(x[i], y[i]) else @max(x[i], y[i]);
            return fromU8s(r);
        },
        .pminsw, .pmaxsw => {
            const x: [8]i16 = @bitCast(a);
            const y: [8]i16 = @bitCast(b);
            var r: [8]i16 = undefined;
            inline for (0..8) |i| r[i] = if (ins.sse == .pminsw) @min(x[i], y[i]) else @max(x[i], y[i]);
            return @bitCast(r);
        },
        .packsswb => {
            const x: [8]i16 = @bitCast(a);
            const y: [8]i16 = @bitCast(b);
            var r: [16]i8 = undefined;
            inline for (0..8) |i| r[i] = satI8(x[i]);
            inline for (0..8) |i| r[8 + i] = satI8(y[i]);
            return @bitCast(r);
        },
        .packssdw => {
            const x: [4]i32 = @bitCast(a);
            const y: [4]i32 = @bitCast(b);
            var r: [8]i16 = undefined;
            inline for (0..4) |i| r[i] = satI16(x[i]);
            inline for (0..4) |i| r[4 + i] = satI16(y[i]);
            return @bitCast(r);
        },
        .packuswb => {
            const x: [8]i16 = @bitCast(a);
            const y: [8]i16 = @bitCast(b);
            var r: [16]u8 = undefined;
            inline for (0..8) |i| r[i] = @intCast(std.math.clamp(x[i], 0, 255));
            inline for (0..8) |i| r[8 + i] = @intCast(std.math.clamp(y[i], 0, 255));
            return fromU8s(r);
        },
        .punpcklbw, .punpckhbw => {
            const x = u8s(a);
            const y = u8s(b);
            var r: [16]u8 = undefined;
            const base: usize = if (ins.sse == .punpcklbw) 0 else 8;
            inline for (0..8) |i| {
                r[2 * i] = x[base + i];
                r[2 * i + 1] = y[base + i];
            }
            return fromU8s(r);
        },
        .punpcklwd, .punpckhwd => {
            const x = u16s(a);
            const y = u16s(b);
            var r: [8]u16 = undefined;
            const base: usize = if (ins.sse == .punpcklwd) 0 else 4;
            inline for (0..4) |i| {
                r[2 * i] = x[base + i];
                r[2 * i + 1] = y[base + i];
            }
            return fromU16s(r);
        },
        .punpckldq, .punpckhdq => {
            const x = u32s(a);
            const y = u32s(b);
            const base: usize = if (ins.sse == .punpckldq) 0 else 2;
            return fromU32s(.{ x[base], y[base], x[base + 1], y[base + 1] });
        },
        .punpcklqdq, .punpckhqdq => {
            return if (ins.sse == .punpcklqdq) .{ a[0], b[0] } else .{ a[1], b[1] };
        },
        else => return a,
    }
}

fn packShift(op: Sse, v: Vec, count: u32) Vec {
    switch (op) {
        .psllw, .psrlw, .psraw => {
            const x = u16s(v);
            var r: [8]u16 = undefined;
            inline for (0..8) |i| {
                r[i] = switch (op) {
                    .psllw => if (count >= 16) 0 else x[i] << @intCast(count),
                    .psrlw => if (count >= 16) 0 else x[i] >> @intCast(count),
                    else => blk: {
                        const sx: i16 = @bitCast(x[i]);
                        break :blk @bitCast(if (count >= 16) (if (sx < 0) @as(i16, -1) else 0) else sx >> @intCast(count));
                    },
                };
            }
            return fromU16s(r);
        },
        .pslld, .psrld, .psrad => {
            const x = u32s(v);
            var r: [4]u32 = undefined;
            inline for (0..4) |i| {
                r[i] = switch (op) {
                    .pslld => if (count >= 32) 0 else x[i] << @intCast(count),
                    .psrld => if (count >= 32) 0 else x[i] >> @intCast(count),
                    else => blk: {
                        const sx: i32 = @bitCast(x[i]);
                        break :blk @bitCast(if (count >= 32) (if (sx < 0) @as(i32, -1) else 0) else sx >> @intCast(count));
                    },
                };
            }
            return fromU32s(r);
        },
        else => {
            var r: [2]u64 = undefined;
            inline for (0..2) |i| {
                r[i] = if (op == .psllq) (if (count >= 64) 0 else v[i] << @intCast(count)) else (if (count >= 64) 0 else v[i] >> @intCast(count));
            }
            return r;
        },
    }
}

// ---- FXSAVE/FXRSTOR --------------------------------------------------------------

fn xsaveWrite(s: St, ins: *const Insn, off: u64, v: u64) Error!void {
    try common.writeMem(s, ins.ea + off, 8, ins.pfx.seg, v);
}
fn xsaveRead(s: St, ins: *const Insn, off: u64) Error!u64 {
    return common.readMem(s, ins.ea + off, 8, ins.pfx.seg);
}

fn fxsave(s: St, ins: *const Insn) Error!Exit {
    const r = s.r;
    try xsaveWrite(s, ins, 0, (@as(u64, r.fop) << 48) | (@as(u64, r.ftw) << 32) |
        (@as(u64, r.fsw) << 16) | r.fcw);
    try xsaveWrite(s, ins, 8, r.fip);
    try xsaveWrite(s, ins, 16, r.fdp);
    try xsaveWrite(s, ins, 24, (@as(u64, 0xffff) << 32) | r.mxcsr);
    for (0..8) |i| {
        try xsaveWrite(s, ins, 32 + i * 16, r.x87[i][0]);
        try xsaveWrite(s, ins, 40 + i * 16, r.x87[i][1]);
    }
    for (0..16) |i| {
        try xsaveWrite(s, ins, 160 + i * 16, r.xmm[i][0]);
        try xsaveWrite(s, ins, 168 + i * 16, r.xmm[i][1]);
    }
    return .next;
}

fn fxrstor(s: St, ins: *const Insn) Error!Exit {
    const r = s.r;
    const w = try xsaveRead(s, ins, 0);
    r.fcw = @truncate(w);
    r.fsw = @truncate(w >> 16);
    r.ftw = @truncate(w >> 32);
    r.fop = @truncate(w >> 48);
    r.fip = try xsaveRead(s, ins, 8);
    r.fdp = try xsaveRead(s, ins, 16);
    r.mxcsr = @truncate(try xsaveRead(s, ins, 24));
    for (0..8) |i| {
        r.x87[i][0] = try xsaveRead(s, ins, 32 + i * 16);
        r.x87[i][1] = try xsaveRead(s, ins, 40 + i * 16) & 0xffff;
    }
    for (0..16) |i| {
        r.xmm[i][0] = try xsaveRead(s, ins, 160 + i * 16);
        r.xmm[i][1] = try xsaveRead(s, ins, 168 + i * 16);
    }
    return .next;
}

// ---- x87 -------------------------------------------------------------------------

fn fpuOp(s: St, ins: *const Insn) Error!Exit {
    const r = s.r;
    switch (ins.fpu) {
        .fld => {
            if (ins.mem) {
                x87Push(s, try x87LoadMem(s, ins));
            } else {
                x87Push(s, x87Get(r, @intCast(ins.rm & 7)));
            }
        },
        .fst => {
            const v = x87Get(r, 0);
            if (ins.mem) try x87StoreMem(s, ins, v) else x87Set(r, @intCast(ins.rm & 7), v);
        },
        .fstp => {
            const v = x87Get(r, 0);
            if (ins.mem) try x87StoreMem(s, ins, v) else x87Set(r, @intCast(ins.rm & 7), v);
            x87Pop(r);
        },
        .fild => {
            if (!ins.mem) return common.ill(s, ins.raw);
            const v: i64 = switch (ins.opsz) {
                2 => @as(i16, @bitCast(@as(u16, @truncate(try common.readMem(s, ins.ea, 2, ins.pfx.seg))))),
                4 => @as(i32, @bitCast(@as(u32, @truncate(try common.readMem(s, ins.ea, 4, ins.pfx.seg))))),
                8 => @bitCast(try common.readMem(s, ins.ea, 8, ins.pfx.seg)),
                else => unreachable,
            };
            x87Push(s, @floatFromInt(v));
        },
        .fist, .fistp => {
            if (!ins.mem) return common.ill(s, ins.raw);
            const v: i64 = @intFromFloat(x87Round(r, x87Get(r, 0)));
            switch (ins.opsz) {
                2 => try common.writeMem(s, ins.ea, 2, ins.pfx.seg, @as(u16, @truncate(@as(u64, @bitCast(@as(i64, @as(i16, @truncate(v)))))))),
                4 => try common.writeMem(s, ins.ea, 4, ins.pfx.seg, @as(u32, @truncate(@as(u64, @bitCast(@as(i64, @as(i32, @truncate(v)))))))),
                8 => try common.writeMem(s, ins.ea, 8, ins.pfx.seg, @bitCast(v)),
                else => unreachable,
            }
            if (ins.fpu == .fistp) x87Pop(r);
        },
        .fadd, .fsub, .fsubr, .fmul, .fdiv, .fdivr => {
            const other: f80 = if (ins.mem) try x87LoadMem(s, ins) else x87Get(r, @intCast(ins.rm & 7));
            const a = x87Get(r, 0);
            if (ins.aux == 1) {
                const dst: u3 = @intCast(ins.rm & 7);
                const b = x87Get(r, dst);
                x87Set(r, dst, switch (ins.fpu) {
                    .fadd => b + a,
                    .fsub => b - a,
                    .fsubr => a - b,
                    .fmul => b * a,
                    .fdiv => b / a,
                    .fdivr => a / b,
                    else => unreachable,
                });
            } else {
                x87Set(r, 0, switch (ins.fpu) {
                    .fadd => a + other,
                    .fsub => a - other,
                    .fsubr => other - a,
                    .fmul => a * other,
                    .fdiv => a / other,
                    .fdivr => other / a,
                    else => unreachable,
                });
            }
        },
        .fiadd, .fisub, .fisubr, .fimul, .fidiv, .fidivr => {
            if (!ins.mem) return common.ill(s, ins.raw);
            const iv: i64 = switch (ins.opsz) {
                2 => @as(i16, @bitCast(@as(u16, @truncate(try common.readMem(s, ins.ea, 2, ins.pfx.seg))))),
                4 => @as(i32, @bitCast(@as(u32, @truncate(try common.readMem(s, ins.ea, 4, ins.pfx.seg))))),
                else => unreachable,
            };
            const other: f80 = @floatFromInt(iv);
            const a = x87Get(r, 0);
            x87Set(r, 0, switch (ins.fpu) {
                .fiadd => a + other,
                .fisub => a - other,
                .fisubr => other - a,
                .fimul => a * other,
                .fidiv => a / other,
                .fidivr => other / a,
                else => unreachable,
            });
        },
        .faddp, .fmulp, .fsubp, .fsubrp, .fdivp, .fdivrp => {
            const dst: u3 = @intCast(ins.rm & 7);
            const a = x87Get(r, dst);
            const b = x87Get(r, 0);
            x87Set(r, dst, switch (ins.fpu) {
                .faddp => a + b,
                .fmulp => a * b,
                .fsubp => a - b,
                .fsubrp => b - a,
                .fdivp => a / b,
                .fdivrp => b / a,
                else => unreachable,
            });
            x87Pop(r);
        },
        .fcmov => {
            if (x87Cond(r, ins.cc)) x87Set(r, 0, x87Get(r, @intCast(ins.rm & 7)));
        },
        .fcom, .fcomp, .fucom, .fucomp => {
            const other: f80 = if (ins.mem) try x87LoadMem(s, ins) else x87Get(r, @intCast(ins.rm & 7));
            x87Compare(r, x87Get(r, 0), other);
            if (ins.fpu == .fcomp or ins.fpu == .fucomp) x87Pop(r);
        },
        .fcompp, .fucompp => {
            x87Compare(r, x87Get(r, 0), x87Get(r, 1));
            x87Pop(r);
            x87Pop(r);
        },
        .fucomi, .fcomi, .fucomip, .fcomip => {
            const other: f80 = if (ins.mem) try x87LoadMem(s, ins) else x87Get(r, @intCast(ins.rm & 7));
            x87CompareFlags(r, x87Get(r, 0), other);
            if (ins.fpu == .fucomip or ins.fpu == .fcomip) x87Pop(r);
        },
        .ftst => x87Compare(r, x87Get(r, 0), 0),
        .fxam => x87Exam(r, x87Get(r, 0)),
        .fldcw => {
            if (!ins.mem) return common.ill(s, ins.raw);
            r.fcw = @truncate(try common.readMem(s, ins.ea, 2, ins.pfx.seg));
        },
        .fnstcw => {
            if (ins.mem) {
                try common.writeMem(s, ins.ea, 2, ins.pfx.seg, r.fcw);
            } else return common.ill(s, ins.raw);
        },
        .fnstsw => {
            if (ins.mem) {
                try common.writeMem(s, ins.ea, 2, ins.pfx.seg, r.fsw);
            } else {
                common.regWrite(r, 0, 2, ins.pfx.rex != 0, r.fsw);
            }
        },
        .fninit => {
            r.fcw = 0x037f;
            r.fsw = 0;
            r.ftw = 0xffff;
        },
        .fchs, .fabs => {
            var u: u80 = @bitCast(x87Get(r, 0));
            if (ins.fpu == .fchs) u ^= @as(u80, 1) << 79 else u &= ~(@as(u80, 1) << 79);
            x87Set(r, 0, @bitCast(u));
        },
        .fsqrt => x87Set(r, 0, @sqrt(x87Get(r, 0))),
        .frndint => x87Set(r, 0, x87Round(r, x87Get(r, 0))),
        .fxch => {
            const i: u3 = @intCast(ins.rm & 7);
            const a = x87Get(r, 0);
            const b = x87Get(r, i);
            x87Set(r, 0, b);
            x87Set(r, i, a);
        },
        .fld1 => x87Push(s, 1),
        .fldz => x87Push(s, 0),
        .fldpi => x87Push(s, @as(f80, 3.141592653589793238462643383279502884)),
        .fldl2e => x87Push(s, @as(f80, 1.442695040888963407359924681001892137)),
        .fldl2t => x87Push(s, @as(f80, 3.321928094887362347870319429489390176)),
        .fldln2 => x87Push(s, @as(f80, 0.693147180559945309417232121458176568)),
        .fldlg2 => x87Push(s, @as(f80, 0.301029995663981195213738894724493027)),
        .fscale => {
            const e: i32 = @intFromFloat(@trunc(x87Get(r, 1)));
            x87Set(r, 0, std.math.scalbn(x87Get(r, 0), e));
        },
        .fprem => {
            const a = x87Get(r, 0);
            const b = x87Get(r, 1);
            if (b == 0 or std.math.isNan(a) or std.math.isNan(b) or std.math.isInf(a)) {
                x87Set(r, 0, std.math.nan(f80));
            } else {
                x87Set(r, 0, @mod(a, b));
            }
        },
    }
    return .next;
}

inline fn x87Top(r: *Regs) u3 {
    return @intCast((r.fsw >> 11) & 7);
}
inline fn x87SetTop(r: *Regs, t: u3) void {
    r.fsw = (r.fsw & ~@as(u16, 7 << 11)) | (@as(u16, t) << 11);
}
inline fn x87Phys(r: *Regs, i: u3) u3 {
    return (x87Top(r) +% i) & 7;
}
inline fn x87Get(r: *Regs, i: u3) f80 {
    const p = r.x87[x87Phys(r, i)];
    const u: u80 = (@as(u80, p[1] & 0xffff) << 64) | p[0];
    return @bitCast(u);
}
inline fn x87Set(r: *Regs, i: u3, v: f80) void {
    const u: u80 = @bitCast(v);
    const p = &r.x87[x87Phys(r, i)];
    p[0] = @truncate(u);
    p[1] = @as(u64, @truncate(u >> 64)) & 0xffff;
}
fn x87Push(s: St, v: f80) void {
    x87SetTop(s.r, (x87Top(s.r) -% 1) & 7);
    x87Set(s.r, 0, v);
}
inline fn x87Pop(r: *Regs) void {
    x87SetTop(r, (x87Top(r) +% 1) & 7);
}

fn x87LoadMem(s: St, ins: *const Insn) Error!f80 {
    return switch (ins.aux) {
        3 => switch (ins.opsz) {
            4 => @floatCast(@as(f32, @bitCast(@as(u32, @truncate(try common.readMem(s, ins.ea, 4, ins.pfx.seg)))))),
            8 => @floatCast(@as(f64, @bitCast(try common.readMem(s, ins.ea, 8, ins.pfx.seg)))),
            else => unreachable,
        },
        4 => blk: {
            const iv: i64 = switch (ins.opsz) {
                2 => @as(i16, @bitCast(@as(u16, @truncate(try common.readMem(s, ins.ea, 2, ins.pfx.seg))))),
                4 => @as(i32, @bitCast(@as(u32, @truncate(try common.readMem(s, ins.ea, 4, ins.pfx.seg))))),
                else => unreachable,
            };
            break :blk @floatFromInt(iv);
        },
        5 => blk: {
            const iv: i64 = switch (ins.opsz) {
                2 => @as(i16, @bitCast(@as(u16, @truncate(try common.readMem(s, ins.ea, 2, ins.pfx.seg))))),
                4 => @as(i32, @bitCast(@as(u32, @truncate(try common.readMem(s, ins.ea, 4, ins.pfx.seg))))),
                8 => @bitCast(try common.readMem(s, ins.ea, 8, ins.pfx.seg)),
                else => unreachable,
            };
            break :blk @floatFromInt(iv);
        },
        7 => blk: {
            const lo = try common.readMem(s, ins.ea, 8, ins.pfx.seg);
            const hi = try common.readMem(s, ins.ea + 8, 2, ins.pfx.seg);
            break :blk @bitCast((@as(u80, @truncate(hi)) << 64) | lo);
        },
        else => unreachable,
    };
}

fn x87StoreMem(s: St, ins: *const Insn, v: f80) Error!void {
    switch (ins.aux) {
        3 => switch (ins.opsz) {
            4 => try common.writeMem(s, ins.ea, 4, ins.pfx.seg, @as(u32, @bitCast(@as(f32, @floatCast(v))))),
            8 => try common.writeMem(s, ins.ea, 8, ins.pfx.seg, @bitCast(@as(f64, @floatCast(v)))),
            else => unreachable,
        },
        5 => {
            const iv: i64 = @intFromFloat(x87Round(s.r, v));
            switch (ins.opsz) {
                2 => try common.writeMem(s, ins.ea, 2, ins.pfx.seg, @as(u16, @truncate(@as(u64, @bitCast(@as(i64, @as(i16, @truncate(iv)))))))),
                4 => try common.writeMem(s, ins.ea, 4, ins.pfx.seg, @as(u32, @truncate(@as(u64, @bitCast(@as(i64, @as(i32, @truncate(iv)))))))),
                8 => try common.writeMem(s, ins.ea, 8, ins.pfx.seg, @bitCast(iv)),
                else => unreachable,
            }
        },
        7 => {
            const u: u80 = @bitCast(v);
            try common.writeMem(s, ins.ea, 8, ins.pfx.seg, @truncate(u));
            try common.writeMem(s, ins.ea + 8, 2, ins.pfx.seg, @truncate(u >> 64));
        },
        else => unreachable,
    }
}

fn x87Cond(r: *Regs, cc: u8) bool {
    return switch (cc) {
        2 => r.eflags & state.CF != 0,
        3 => r.eflags & state.CF == 0,
        4 => r.eflags & state.ZF != 0,
        5 => r.eflags & state.ZF == 0,
        6 => r.eflags & (state.CF | state.ZF) != 0,
        7 => r.eflags & (state.CF | state.ZF) == 0,
        8 => r.eflags & state.PF != 0,
        9 => r.eflags & state.PF == 0,
        else => false,
    };
}

fn x87Round(r: *Regs, v: f80) f80 {
    return switch ((r.fcw >> 10) & 3) {
        0 => @round(v), // nearest (ties away; x87 uses ties to even)
        1 => @floor(v),
        2 => @ceil(v),
        else => @trunc(v),
    };
}

fn x87SetCC(r: *Regs, c0: bool, c1: bool, c2: bool, c3: bool) void {
    r.fsw = (r.fsw & ~@as(u16, (1 << 8) | (1 << 9) | (1 << 10) | (1 << 14))) |
        (if (c0) @as(u16, 1 << 8) else 0) | (if (c1) @as(u16, 1 << 9) else 0) |
        (if (c2) @as(u16, 1 << 10) else 0) | (if (c3) @as(u16, 1 << 14) else 0);
}

fn x87Compare(r: *Regs, a: f80, b: f80) void {
    if (std.math.isNan(a) or std.math.isNan(b)) {
        x87SetCC(r, true, false, true, true);
    } else if (a > b) {
        x87SetCC(r, false, false, false, false);
    } else if (a < b) {
        x87SetCC(r, true, false, false, false);
    } else {
        x87SetCC(r, false, false, false, true);
    }
}

fn x87CompareFlags(r: *Regs, a: f80, b: f80) void {
    x87Compare(r, a, b);
    var f = r.eflags & ~(state.CF | state.PF | state.ZF | state.OF | state.SF | state.AF);
    if (std.math.isNan(a) or std.math.isNan(b)) {
        f |= state.CF | state.PF | state.ZF;
    } else if (a < b) {
        f |= state.CF;
    } else if (a == b) {
        f |= state.ZF;
    }
    r.eflags = f;
}

fn x87Exam(r: *Regs, v: f80) void {
    const u: u80 = @bitCast(v);
    const sign = (u >> 79) & 1 != 0;
    const exp: u16 = @truncate(u >> 64);
    const frac = u & ((@as(u80, 1) << 63) - 1);
    var c0 = false;
    var c2 = false;
    var c3 = false;
    if (exp == 0 and frac == 0) {
        c3 = true; // +0/-0
    } else if (exp == 0) {
        c3 = true; // denormal
        c2 = true;
    } else if (exp == 0x7fff) {
        if (frac == 0) {
            c0 = true;
            c2 = true; // infinity
        } else {
            c0 = true; // NaN
        }
    } else {
        c2 = true; // normal
    }
    x87SetCC(r, c0, sign, c2, c3);
}
