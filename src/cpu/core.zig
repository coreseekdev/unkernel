// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! Guest-CPU types and primitives shared by the MMU and block cache
//! (src/emu/kwemu.zig), the JIT core (src/emu/jitcore.zig) and the A64 CPU
//! (src/a64): the non-register hart state (traps, exclusive monitor), event
//! kinds, access kinds, the AES tables and carry-less multiplication. The
//! softfloat that A64's FP builds on is fpu.zig.

const std = @import("std");
const builtin = @import("builtin");
pub const fpu = @import("fpu.zig");

/// Several CPUs share the memory (a wasm build with atomics, for an SMP
/// kernel: zig build -Dkwemu-atomics): exclusives and LSE atomics are
/// atomic read-modify-writes, a store-exclusive is a compare-and-swap
/// against the value the load-exclusive read, and barriers are full
/// barriers. Otherwise one CPU owns the memory and plain accesses suffice.
pub const smp = builtin.cpu.arch.isWasm() and std.Target.wasm.featureSetHas(builtin.cpu.features, .atomics);

/// Values match `enum kw_event_kind`.
pub const Kind = enum(u32) {
    budget = 0,
    syscall = 1,
    fault = 2,
    illegal = 3,
    breakpoint = 4,
    misaligned = 5,
    interrupt = 6,
    /// #DE from DIV/IDIV: the kernel delivers SIGFPE (x86-64).
    divide = 7,
    /// Internal (never reported to the kernel): a counter read (MRS
    /// CNTVCT_EL0); the run loop supplies the count.
    counter = 0x100,
};

/// Values match `enum kw_access`.
pub const Access = enum(u32) { read = 0, write = 1, exec = 2 };

pub const Error = error{PageFault};

pub const no_resv: u64 = std.math.maxInt(u64);

/// Non-register hart state (lives inside the opaque part of kw_cpu).
pub const Hart = extern struct {
    /// Exclusive-monitor address (virtual), or no_resv.
    resv: u64 = no_resv,
    /// Valid when an instruction returned .trap: syscall/illegal/
    /// breakpoint/misaligned/counter.
    trap: Kind = .budget,
    _pad: u32 = 0,
    /// Raw instruction for .illegal and .breakpoint, address for .misaligned.
    trap_val: u64 = 0,
    /// The value the load-exclusive read at `resv` (smp: the
    /// store-exclusive succeeds only if it is still there).
    resv_val: u64 = 0,
    /// Target of the atomic read-modify-write that makes a barrier a full
    /// barrier (smp).
    fence_word: u32 = 0,
    _pad2: u32 = 0,
};

pub const Exit = enum {
    /// Sequential instruction retired.
    next,
    /// Taken branch retired (a block boundary: poll interrupts here).
    jump,
    /// The instruction did not retire (except SVC); see Hart.trap. The pc
    /// is left on the instruction.
    trap,
};

pub inline fn sext(v: u64, comptime bits: u7) u64 {
    const sh: u6 = @intCast(64 - @as(u32, bits));
    return @bitCast(@as(i64, @bitCast(v << sh)) >> sh);
}

// ---- AES ---------------------------------------------------------------------------
//
// The FIPS-197 tables and column mixes behind A64's AESE/AESD/AESMC/AESIMC
// (src/a64/crypto.zig) and the JIT's AES tables (jitcore.zig `AesTab`).
// SubBytes is a table lookup indexed by data, so code built on these is
// not constant-time against cache timing.

pub const aes = struct {
    /// x * 2 in GF(2^8) mod x^8 + x^4 + x^3 + x + 1, without a branch.
    pub inline fn xt(x: u8) u8 {
        return (x << 1) ^ (0x1b & (0 -% (x >> 7)));
    }

    /// x * c in GF(2^8) (c a constant).
    pub inline fn mul(x: u8, comptime c: u8) u8 {
        var p: u8 = 0;
        var a = x;
        inline for (0..8) |i| {
            if (c >> i & 1 != 0) p ^= a;
            a = xt(a);
        }
        return p;
    }

    /// FIPS-197 S-box: the inverse in GF(2^8) (0 for 0), then the affine map.
    pub const sbox: [256]u8 = blk: {
        @setEvalBranchQuota(200000);
        var t: [256]u8 = undefined;
        for (0..256) |i| {
            const x: u8 = i;
            // x^254 = x^-1 (square and multiply over the bits of 254)
            var inv: u8 = 1;
            var p: u8 = x;
            var e: u8 = 254;
            while (e != 0) : (e >>= 1) {
                if (e & 1 != 0) inv = gmulRt(inv, p);
                p = gmulRt(p, p);
            }
            if (x == 0) inv = 0;
            t[i] = inv ^ std.math.rotl(u8, inv, 1) ^ std.math.rotl(u8, inv, 2) ^ std.math.rotl(u8, inv, 3) ^ std.math.rotl(u8, inv, 4) ^ 0x63;
        }
        break :blk t;
    };
    pub const inv_sbox: [256]u8 = blk: {
        var t: [256]u8 = undefined;
        for (0..256) |i| t[sbox[i]] = i;
        break :blk t;
    };

    /// a * b in GF(2^8); used only at compile time (it branches on b).
    fn gmulRt(a0: u8, b0: u8) u8 {
        var p: u8 = 0;
        var a = a0;
        var b = b0;
        while (b != 0) : (b >>= 1) {
            if (b & 1 != 0) p ^= a;
            a = xt(a);
        }
        return p;
    }

    /// Key-expansion round constants, rounds 1..10 (and a trailing 0).
    pub const rcon = [11]u8{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x00 };

    pub inline fn mixColumn(col: u32) u32 {
        const s0: u8 = @truncate(col);
        const s1: u8 = @truncate(col >> 8);
        const s2: u8 = @truncate(col >> 16);
        const s3: u8 = @truncate(col >> 24);
        const b0 = xt(s0) ^ (xt(s1) ^ s1) ^ s2 ^ s3;
        const b1 = s0 ^ xt(s1) ^ (xt(s2) ^ s2) ^ s3;
        const b2 = s0 ^ s1 ^ xt(s2) ^ (xt(s3) ^ s3);
        const b3 = (xt(s0) ^ s0) ^ s1 ^ s2 ^ xt(s3);
        return @as(u32, b0) | @as(u32, b1) << 8 | @as(u32, b2) << 16 | @as(u32, b3) << 24;
    }
    pub inline fn invMixColumn(col: u32) u32 {
        const s0: u8 = @truncate(col);
        const s1: u8 = @truncate(col >> 8);
        const s2: u8 = @truncate(col >> 16);
        const s3: u8 = @truncate(col >> 24);
        const b0 = mul(s0, 0xe) ^ mul(s1, 0xb) ^ mul(s2, 0xd) ^ mul(s3, 0x9);
        const b1 = mul(s0, 0x9) ^ mul(s1, 0xe) ^ mul(s2, 0xb) ^ mul(s3, 0xd);
        const b2 = mul(s0, 0xd) ^ mul(s1, 0x9) ^ mul(s2, 0xe) ^ mul(s3, 0xb);
        const b3 = mul(s0, 0xb) ^ mul(s1, 0xd) ^ mul(s2, 0x9) ^ mul(s3, 0xe);
        return @as(u32, b0) | @as(u32, b1) << 8 | @as(u32, b2) << 16 | @as(u32, b3) << 24;
    }
};

// ---- carry-less multiplication ------------------------------------------------------
//
// A fixed sequence (PMULL, src/a64/crypto.zig): BearSSL's "bmul64" (16
// integer multiplications of the operands masked to every fourth bit; a
// column of each product has at most 16 terms, so its sum never carries
// into the next column of the same class below bit 64), and the reflected
// high half from the same on bit-reversed operands. No branch on or index
// by data; constant-time where integer multiplication is (x86-64, AArch64).

pub const bitmanip = struct {
    const m0: u64 = 0x1111_1111_1111_1111;

    /// The low 64 bits of the carry-less product of a and b.
    pub fn clmul(a: u64, b: u64) u64 {
        var x: [4]u64 = undefined;
        var y: [4]u64 = undefined;
        inline for (0..4) |i| {
            x[i] = a & (m0 << i);
            y[i] = b & (m0 << i);
        }
        var r: u64 = 0;
        inline for (0..4) |k| {
            var z: u64 = 0;
            inline for (0..4) |i| z ^= x[i] *% y[(k + 4 - i) % 4];
            r |= z & (m0 << k);
        }
        return r;
    }
    /// Bits 63..126 of the carry-less product.
    pub fn clmulr(a: u64, b: u64) u64 {
        return @bitReverse(clmul(@bitReverse(a), @bitReverse(b)));
    }
    /// Bits 64..127 of the carry-less product.
    pub fn clmulh(a: u64, b: u64) u64 {
        return clmulr(a, b) >> 1;
    }
};
