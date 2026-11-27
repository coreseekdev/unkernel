// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! Helpers the x86-64 decoder and executor share: the per-instruction
//! context (`St`), traps, GPR access (including the AH/CH/DH/BH forms),
//! memory access with segment bases and precise faults, and RFLAGS.
//!
//! Rules (the same as the A64 side):
//!  - an instruction that traps or faults has no architectural effect:
//!    read every operand and do every access that can fault before writing
//!    any register (string instructions are the allowed exception: progress
//!    made by completed iterations stays);
//!  - an encoding exec does not implement returns `ill(s)`, never a no-op;
//!  - no u128 variable shifts/multiplies/divisions (compiler-rt calls on
//!    wasm): XMM lanes are handled as arrays.

const std = @import("std");
const core = @import("../cpu/core.zig");
const kwemu = @import("../emu/kwemu.zig");
pub const state = @import("state.zig");

pub const Regs = state.Regs;
pub const Cpu = kwemu.Cpu;
pub const Hart = core.Hart;
pub const Error = core.Error;
pub const Exit = core.Exit;
/// Decode can also fail on an unimplemented/invalid encoding, which is a
/// guest-visible event (KW_EV_ILLEGAL), not a Zig error the kernel sees.
pub const DecodeError = error{ PageFault, Illegal };
pub const sext = core.sext;

/// Context of one instruction: registers, hart (traps, exclusive monitor),
/// memory. r.rip is the address of the instruction being executed during
/// decode; run.zig advances it to the next instruction before exec.
pub const St = struct {
    r: *Regs,
    h: *Hart,
    m: *Cpu,

    pub inline fn priv(s: St) *state.Priv {
        return &s.m.priv.x86_64;
    }
};

// ---- traps ---------------------------------------------------------------------

/// Unimplemented or invalid encoding: KW_EV_ILLEGAL with the raw bytes.
/// Decode-time invalid encoding: sets Hart.trap and returns error.Illegal.
pub fn invalid(s: St, raw: u64) DecodeError {
    s.h.trap = .illegal;
    s.h.trap_val = raw;
    return error.Illegal;
}

pub fn ill(s: St, raw: u64) Exit {
    @branchHint(.cold);
    s.h.trap = .illegal;
    s.h.trap_val = raw;
    return .trap;
}

/// A #GP from an aligned SSE access: KW_EV_MISALIGNED with the address.
pub fn misaligned(s: St, addr: u64) Exit {
    @branchHint(.cold);
    s.h.trap = .misaligned;
    s.h.trap_val = addr;
    return .trap;
}

pub fn syscall(s: St) Exit {
    s.h.trap = .syscall;
    return .trap;
}

/// A #DE from DIV/IDIV (zero divisor or quotient overflow): SIGFPE.
pub fn divideError(s: St, raw: u64) Exit {
    @branchHint(.cold);
    s.h.trap = .divide;
    s.h.trap_val = raw;
    return .trap;
}

pub fn breakpoint(s: St, raw: u64) Exit {
    s.h.trap = .breakpoint;
    s.h.trap_val = raw;
    return .trap;
}

pub inline fn jump(s: St, target: u64) Exit {
    s.r.rip = target;
    return .jump;
}

// ---- register access -------------------------------------------------------------

/// Pointer to general register `i` (0 rax, 1 rcx, ..., 4 rsp, 5 rbp, ...).
pub inline fn gpr(r: *Regs, i: u4) *u64 {
    return switch (i) {
        0 => &r.rax,
        1 => &r.rcx,
        2 => &r.rdx,
        3 => &r.rbx,
        4 => &r.rsp,
        5 => &r.rbp,
        6 => &r.rsi,
        7 => &r.rdi,
        8 => &r.r8,
        9 => &r.r9,
        10 => &r.r10,
        11 => &r.r11,
        12 => &r.r12,
        13 => &r.r13,
        14 => &r.r14,
        else => &r.r15,
    };
}

pub inline fn mask(sz: u8) u64 {
    return switch (sz) {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        else => 0xffff_ffff_ffff_ffff,
    };
}

pub inline fn signbit(sz: u8) u64 {
    return @as(u64, 1) << @intCast(@as(u32, sz) * 8 - 1);
}

/// Register value of `sz` bytes. 8-bit register numbers 4..7 without a REX
/// prefix are AH, CH, DH, BH.
pub inline fn regRead(r: *Regs, idx: u4, sz: u8, rex: bool) u64 {
    if (sz == 1 and !rex and idx >= 4 and idx < 8) return (gpr(r, idx - 4).* >> 8) & 0xff;
    const v = gpr(r, idx).*;
    return switch (sz) {
        1 => v & 0xff,
        2 => v & 0xffff,
        4 => v & 0xffff_ffff,
        else => v,
    };
}

/// Write `sz` bytes, zero-extending into the rest (32-bit writes clear the
/// upper half; 8/16-bit writes keep it).
pub inline fn regWrite(r: *Regs, idx: u4, sz: u8, rex: bool, v: u64) void {
    if (sz == 1 and !rex and idx >= 4 and idx < 8) {
        const p = gpr(r, idx - 4);
        p.* = (p.* & ~@as(u64, 0xff00)) | ((v & 0xff) << 8);
        return;
    }
    const p = gpr(r, idx);
    p.* = switch (sz) {
        1 => (p.* & ~@as(u64, 0xff)) | (v & 0xff),
        2 => (p.* & ~@as(u64, 0xffff)) | (v & 0xffff),
        4 => v & 0xffff_ffff,
        else => v,
    };
}

// ---- memory --------------------------------------------------------------------

pub inline fn segBase(r: *Regs, seg: u8) u64 {
    return switch (seg) {
        0x64 => r.fs_base,
        0x65 => r.gs_base,
        else => 0,
    };
}

pub fn readMem(s: St, ea: u64, sz: u8, seg: u8) Error!u64 {
    const va = ea +% segBase(s.r, seg);
    return switch (sz) {
        1 => @as(u64, try s.m.load(u8, va)),
        2 => @as(u64, try s.m.load(u16, va)),
        4 => @as(u64, try s.m.load(u32, va)),
        8 => try s.m.load(u64, va),
        else => unreachable,
    };
}

pub fn writeMem(s: St, ea: u64, sz: u8, seg: u8, v: u64) Error!void {
    const va = ea +% segBase(s.r, seg);
    switch (sz) {
        1 => try s.m.store(u8, va, @truncate(v)),
        2 => try s.m.store(u16, va, @truncate(v)),
        4 => try s.m.store(u32, va, @truncate(v)),
        8 => try s.m.store(u64, va, v),
        else => unreachable,
    }
}

pub const Vec = [2]u64;

pub fn readMem128(s: St, ea: u64, seg: u8) Error!Vec {
    const va = ea +% segBase(s.r, seg);
    const lo = try s.m.load(u64, va);
    const hi = try s.m.load(u64, va + 8);
    return .{ lo, hi };
}

pub fn writeMem128(s: St, ea: u64, seg: u8, v: Vec) Error!void {
    const va = ea +% segBase(s.r, seg);
    // Probe both halves before the first store: a fault leaves memory as it
    // was.
    try s.m.probe(va, .write);
    try s.m.probe(va + 8, .write);
    try s.m.store(u64, va, v[0]);
    try s.m.store(u64, va + 8, v[1]);
}

// ---- RFLAGS ---------------------------------------------------------------------

pub inline fn hasFlag(r: *const Regs, f: u64) bool {
    return r.eflags & f != 0;
}

pub inline fn setFlag(r: *Regs, f: u64, on: bool) void {
    if (on) r.eflags |= f else r.eflags &= ~f;
}

fn parityFlag(v: u8) bool {
    return @popCount(v) & 1 == 0;
}

/// Logical results: CF = OF = 0, ZF/SF/PF from the result.
pub fn flagsLogic(r: *Regs, sz: u8, res0: u64) void {
    const res = res0 & mask(sz);
    r.eflags = (r.eflags & ~(state.CF | state.OF | state.SF | state.ZF | state.PF | state.AF)) |
        (if (res == 0) state.ZF else 0) |
        (if (res & signbit(sz) != 0) state.SF else 0) |
        (if (parityFlag(@truncate(res))) state.PF else 0);
}

pub fn flagsAdd(r: *Regs, sz: u8, a0: u64, b0: u64, carry: u1) void {
    const m = mask(sz);
    const a = a0 & m;
    const b = b0 & m;
    const s1 = @addWithOverflow(a, b);
    const s2 = @addWithOverflow(s1[0], @as(u64, carry));
    const res: u64 = s2[0] & m;
    const cf = s1[1] != 0 or s2[1] != 0;
    const of = ((a ^ res) & (b ^ res) & signbit(sz)) != 0;
    const af = ((a ^ b ^ res) & 0x10) != 0;
    r.eflags = (r.eflags & ~(state.CF | state.OF | state.AF | state.SF | state.ZF | state.PF)) |
        (if (cf) state.CF else 0) |
        (if (of) state.OF else 0) |
        (if (af) state.AF else 0) |
        (if (res == 0) state.ZF else 0) |
        (if (res & signbit(sz) != 0) state.SF else 0) |
        (if (parityFlag(@truncate(res))) state.PF else 0);
}

pub fn flagsSub(r: *Regs, sz: u8, a0: u64, b0: u64, borrow: u1) void {
    const m = mask(sz);
    const a = a0 & m;
    const b = b0 & m;
    const s1 = @subWithOverflow(a, b);
    const s2 = @subWithOverflow(s1[0], @as(u64, borrow));
    const res: u64 = s2[0] & m;
    const cf = s1[1] != 0 or s2[1] != 0;
    const of = ((a ^ b) & (a ^ res) & signbit(sz)) != 0;
    const af = ((a ^ b ^ res) & 0x10) != 0;
    r.eflags = (r.eflags & ~(state.CF | state.OF | state.AF | state.SF | state.ZF | state.PF)) |
        (if (cf) state.CF else 0) |
        (if (of) state.OF else 0) |
        (if (af) state.AF else 0) |
        (if (res == 0) state.ZF else 0) |
        (if (res & signbit(sz) != 0) state.SF else 0) |
        (if (parityFlag(@truncate(res))) state.PF else 0);
}

/// INC/DEC: like ADD/SUB by 1 but CF is preserved.
pub fn flagsIncDec(r: *Regs, sz: u8, a0: u64, dec: bool) void {
    const m = mask(sz);
    const a = a0 & m;
    const res: u64 = if (dec) (a -% 1) & m else (a +% 1) & m;
    const cf = r.eflags & state.CF;
    // DEC overflows only from the minimum signed value, INC only into the
    // sign bit (0x7f.. -> 0x80..): not the a ^ res form, which flags DEC 0
    // and misses DEC 0x80.. (glibc's memcmp tail tests `dec; jle`).
    const of = if (dec) a == signbit(sz) else res == signbit(sz);
    const af = ((a ^ 1 ^ res) & 0x10) != 0;
    r.eflags = (r.eflags & ~(state.OF | state.AF | state.SF | state.ZF | state.PF)) | cf |
        (if (of) state.OF else 0) |
        (if (af) state.AF else 0) |
        (if (res == 0) state.ZF else 0) |
        (if (res & signbit(sz) != 0) state.SF else 0) |
        (if (parityFlag(@truncate(res))) state.PF else 0);
}

pub inline fn cond(r: *const Regs, cc: u8) bool {
    const f = r.eflags;
    return switch (cc & 0xf) {
        0x0 => f & state.OF != 0,
        0x1 => f & state.OF == 0,
        0x2 => f & state.CF != 0,
        0x3 => f & state.CF == 0,
        0x4 => f & state.ZF != 0,
        0x5 => f & state.ZF == 0,
        0x6 => f & state.CF != 0 or f & state.ZF != 0,
        0x7 => f & state.CF == 0 and f & state.ZF == 0,
        0x8 => f & state.SF != 0,
        0x9 => f & state.SF == 0,
        0xa => f & state.PF != 0,
        0xb => f & state.PF == 0,
        0xc => (f & state.SF != 0) != (f & state.OF != 0),
        0xd => (f & state.SF != 0) == (f & state.OF != 0),
        0xe => f & state.ZF != 0 or (f & state.SF != 0) != (f & state.OF != 0),
        else => f & state.ZF == 0 and (f & state.SF != 0) == (f & state.OF != 0),
    };
}

/// Sign-extend from a runtime bit count (1..64).
pub inline fn sextR(v: u64, bits: u8) u64 {
    const sh: u6 = @intCast(64 - @as(u32, bits));
    return @bitCast(@as(i64, @bitCast(v << sh)) >> sh);
}

pub inline fn signOf(v: u64, sz: u8) bool {
    return v & signbit(sz) != 0;
}
