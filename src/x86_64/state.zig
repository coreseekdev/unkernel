// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! x86-64 architectural state: the register file (`struct kw_regs` of
//! include/kw_emu.h with KW_USER_ISA_X86_64, checked in run.zig) and the
//! x86-64 part of the private area of struct kw_cpu (`Priv`, a field of
//! kwemu.Priv).

const std = @import("std");

comptime {
    // XMM registers are read and written as arrays of lanes: only right on a
    // little-endian host (x86-64, aarch64 and wasm all are).
    std.debug.assert(@import("builtin").cpu.arch.endian() == .little);
}

/// Guest registers; identical layout to `struct kw_regs` (the x86-64
/// variant of include/kw_emu.h). The first 27 words are exactly Linux's
/// `struct user_regs_struct`.
pub const Regs = extern struct {
    r15: u64 = 0,
    r14: u64 = 0,
    r13: u64 = 0,
    r12: u64 = 0,
    rbp: u64 = 0,
    rbx: u64 = 0,
    r11: u64 = 0,
    r10: u64 = 0,
    r9: u64 = 0,
    r8: u64 = 0,
    rax: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    orig_rax: u64 = 0,
    rip: u64 = 0,
    cs: u64 = 0x33,
    eflags: u64 = 0x202,
    rsp: u64 = 0,
    ss: u64 = 0x2b,
    fs_base: u64 = 0,
    gs_base: u64 = 0,
    ds: u64 = 0,
    es: u64 = 0,
    fs: u64 = 0,
    gs: u64 = 0,
    mxcsr: u32 = 0x1f80,
    _pad: u32 = 0,
    /// XMM0..XMM15; the memory image of `uint64_t xmm[16][2]`. Kept as two
    /// 64-bit halves so no 128-bit shift or multiplication is ever needed
    /// (those become compiler-rt calls the kernel does not link).
    xmm: [16][2]u64 align(16) = @splat(.{ 0, 0 }),
    /// x87 ST(0)..ST(7), physical order (the stack top is fsw bits 11..13).
    /// Each is the little-endian 80-bit x87 value in the low 10 bytes of
    /// the 16-byte slot (the kernel treats them as opaque bytes).
    x87: [8][2]u64 align(16) = @splat(.{ 0, 0 }),
    fcw: u16 = 0x037f,
    fsw: u16 = 0,
    ftw: u16 = 0,
    fop: u16 = 0,
    fip: u64 = 0,
    fdp: u64 = 0,
};

/// The x86-64 part of kwemu's private area in struct kw_cpu. Everything
/// here is emulator-private (not ABI). The exclusive monitor's address is
/// `core.Hart.resv` (cleared by kw_clear_reservation and kw_set_pgd).
pub const Priv = extern struct {
    /// Enabled optional features. x86-64 baseline needs none beyond SSE2,
    /// which is part of the described ISA, so this stays 0 for now.
    isa: u64 = 0,
    /// How the last kw_run that ended for an interrupt or the budget saw
    /// it, and the start pc of the last block (the kernel's profiler uses
    /// the A64 values; kept here so a future tier can report the same).
    stop_tier: u32 = 0,
    _pad: u32 = 0,
    stop_block: u64 = 0,
};

/// RFLAGS bits this CPU models.
pub const CF: u64 = 1 << 0;
pub const PF: u64 = 1 << 2;
pub const AF: u64 = 1 << 4;
pub const ZF: u64 = 1 << 6;
pub const SF: u64 = 1 << 7;
pub const TF: u64 = 1 << 8;
pub const IF: u64 = 1 << 9;
pub const DF: u64 = 1 << 10;
pub const OF: u64 = 1 << 11;
/// Set by every model: bit 1 is always 1.
pub const FLAGS_RESERVED: u64 = 1 << 1;

/// Parity of the low byte (SF/PF/ZF helpers).
pub inline fn parity(v: u8) u64 {
    return if (@popCount(v) & 1 == 0) PF else 0;
}
