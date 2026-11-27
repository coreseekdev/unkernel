// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! The C ABI of include/kw_emu.h (x86-64), the reference run loop
//! (`runRef`: one instruction at a time through decode.zig and exec.zig,
//! the semantic oracle) and the decoded basic-block tier (`run`: cached
//! stateless Insns, validated by the raw bytes at the host address). The
//! wasm JIT is the next tier (HANDOFF.md phase 4). struct kw_cpu, the
//! Sv48-format page-table walker, the TLBs and the flushes are kwemu.Cpu
//! (src/emu/kwemu.zig).

const std = @import("std");
const builtin = @import("builtin");
const core = @import("../cpu/core.zig");
const kwemu = @import("../emu/kwemu.zig");
const c = @import("common.zig");
const decode = @import("decode.zig");
const Op = decode.Op;
const exec = @import("exec.zig");
const kw_h = @import("kw_h");
const options = @import("kwemu_options");

pub const Regs = c.Regs;
const Cpu = kwemu.Cpu;

/// Poll *irq_pending at least this often (instructions) on straight-line
/// code.
const poll_every = 64;

comptime {
    // Layout must match struct kw_regs in include/kw_emu.h when built with
    // KW_USER_ISA_X86_64.
    const H = kw_h.struct_kw_regs;
    std.debug.assert(@sizeOf(Regs) == @sizeOf(H));
    std.debug.assert(@alignOf(Regs) == 16 and @alignOf(H) == 16);
    for (.{ "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs" }, .{
        0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200, 208,
    }) |f, off| {
        std.debug.assert(@offsetOf(Regs, f) == @offsetOf(H, f));
        std.debug.assert(@offsetOf(Regs, f) == off);
    }
    std.debug.assert(@offsetOf(Regs, "xmm") == 224);
    std.debug.assert(@offsetOf(Regs, "x87") == 480);
    std.debug.assert(@offsetOf(Regs, "fcw") == 608);
    std.debug.assert(@offsetOf(Regs, "fsw") == 610);
    std.debug.assert(@offsetOf(Regs, "ftw") == 612);
    std.debug.assert(@offsetOf(Regs, "fop") == 614);
    std.debug.assert(@offsetOf(Regs, "fip") == 616);
    std.debug.assert(@offsetOf(Regs, "fdp") == 624);
    std.debug.assert(@sizeOf(Regs) == 640);
    std.debug.assert(kw_h.KW_ABI_VERSION == kwemu.abi_version);
}

fn event(cpu: *Cpu, kind: core.Kind, access: u32, addr: u64, insn: u64) u32 {
    cpu.ev = .{ .kind = @intFromEnum(kind), .access = access, .addr = addr, .insn = insn };
    return @intFromEnum(kind);
}

pub fn run(cpu: *Cpu, regs: *Regs) u32 {
    // The block cache is a single global table; SMP builds keep the
    // reference loop until it is per-CPU.
    if (core.smp) return runRef(cpu, regs);
    return runDecoded(cpu, regs);
}

// ---- decoded-op tier ------------------------------------------------------------
//
// A decoded basic-block cache. A block is up to 24 instructions in one page,
// decoded into stateless `Insn`s (the decoder no longer computes an absolute
// effective address; `eaOf` reads base/index at execution). A hit validates
// the raw bytes at the host address and runs the cached `Insn`s without
// decoding; a self-modifying store or a remapped page changes the raw bytes
// or the host tag and forces a re-decode. Blocks end after a control-flow
// instruction or at a page boundary, so a branch target starts a new lookup.
//
// This is the decoded-op tier (HANDOFF phase 4), not the wasm JIT. The cache
// is global and its entries are immutable after decode; the checks make it
// safe across CPUs and address spaces. SMP builds fall back to the reference
// loop until the cache is made per-CPU.

const block_insns = 24;
const block_sets = 256;
const BIns = struct {
    len: u8 = 0,
    raw: u64 = 0,
    ins: decode.Insn = .{},
};
const BEntry = struct {
    pc: u64 = 0,
    host: u64 = 0,
    n: u8 = 0,
    mask: u64 = 0,
    valid: bool = false,
    ins: [block_insns]BIns = @splat(.{}),
};
var bcache: [block_sets]BEntry = @splat(.{});

inline fn bIndex(pc: u64) usize {
    return @intCast(((pc >> 1) ^ (pc >> 13)) & (block_sets - 1));
}

fn rawMatch(host: u64, raw: u64, len: u8) bool {
    const mask: u64 = if (len == 8) 0xffff_ffff_ffff_ffff else (@as(u64, 1) << @intCast(len * 8)) - 1;
    const cur: u64 = switch (len) {
        1 => Cpu.hostRead(u8, host),
        2 => Cpu.hostRead(u16, host),
        3 => Cpu.hostRead(u16, host) | (@as(u64, Cpu.hostRead(u8, host + 2)) << 16),
        4 => Cpu.hostRead(u32, host),
        else => Cpu.hostRead(u64, host), // len 5..8; decode stopped if the page lacks 8
    };
    return ((cur ^ raw) & mask) == 0;
}

fn blockGet(cpu: *Cpu, pc: u64, host: u64) ?*const BEntry {
    const e = &bcache[bIndex(pc)];
    if (!e.valid or e.pc != pc or e.host != host or e.n == 0) return null;
    var off: u64 = 0;
    for (e.ins[0..@as(usize, e.n)]) |*bi| {
        if (!rawMatch(host + off, bi.raw, bi.len)) return null;
        off += bi.len;
    }
    cpu.markCode(host & ~@as(u64, 4095), e.mask);
    return e;
}

fn endsBlock(op: Op) bool {
    return switch (op) {
        .jmp, .call, .ret, .jcc, .loopne, .loope, .loop, .jrcxz, .syscall, .int3, .ud2, .hlt, .int_n => true,
        else => false,
    };
}

fn blockDecode(s: c.St, pc: u64, host: u64) ?*const BEntry {
    const e = &bcache[bIndex(pc)];
    var n: usize = 0;
    var cur = pc;
    var local: decode.Insn = undefined;
    while (n < block_insns) {
        const off = cur & 4095;
        s.r.rip = cur; // decode.one starts at r.rip
        decode.one(s, &local) catch break;
        if (local.len == 0 or local.len > 8) break;
        if (off + local.len > 4096) break;
        if (local.len >= 5 and off + 8 > 4096) break;
        e.ins[n] = .{ .len = local.len, .raw = local.raw, .ins = local };
        n += 1;
        cur +%= local.len;
        if (endsBlock(local.op) or (cur & 4095) == 0) break;
    }
    if (n == 0) return null;
    const first = (pc & 4095) >> 6;
    const last = ((cur - 1) & 4095) >> 6;
    var mask: u64 = 0;
    var ch = first;
    while (ch <= last) : (ch += 1) mask |= @as(u64, 1) << @intCast(ch);
    s.m.markCode(host & ~@as(u64, 4095), mask);
    e.pc = pc;
    e.host = host;
    e.n = @intCast(n);
    e.mask = mask;
    e.valid = true;
    return e;
}

pub fn runDecoded(cpu: *Cpu, regs: *Regs) u32 {
    const start = cpu.budget;
    var left = start;
    const icount0 = cpu.icount;
    defer {
        cpu.budget = left;
        cpu.icount = icount0 +% (start - left);
    }
    const irq = cpu.irq_pending;
    if (irq) |p| if (p.* != 0) return stopEvent(cpu, .interrupt, .entry, regs.rip);
    const h = &cpu.priv.hart;
    const s: c.St = .{ .r = regs, .h = h, .m = cpu };
    var since_poll: u32 = 0;
    while (true) {
        if (left == 0) return stopEvent(cpu, .budget, .decoded, regs.rip);
        const ipc = regs.rip;
        cpu.icount = icount0 +% (start - left);
        const host = cpu.execHost(ipc) catch {
            cpu.priv.smc = 0;
            return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
        };
        var entry = blockGet(cpu, ipc, host);
        if (entry == null) entry = blockDecode(s, ipc, host);
        if (entry) |be| {
            var cur = be.pc;
            var k: usize = 0;
            var brk = false;
            while (k < be.n) : (k += 1) {
                if (left == 0) {
                    regs.rip = cur;
                    return stopEvent(cpu, .budget, .decoded, cur);
                }
                const at = cur;
                const bi = &be.ins[k];
                cpu.icount = icount0 +% (start - left);
                cur +%= bi.len;
                regs.rip = cur;
                const e = exec.one(s, &bi.ins) catch {
                    regs.rip = at;
                    cpu.priv.smc = 0;
                    return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
                };
                const wrote_code = cpu.priv.smc != 0;
                cpu.priv.smc = 0;
                switch (e) {
                    .next => {
                        left -= 1;
                        since_poll += 1;
                        if (wrote_code) brk = true else if (since_poll < poll_every) continue;
                    },
                    .jump => {
                        left -= 1;
                        brk = true;
                    },
                    .trap => {
                        if (h.trap == .syscall) {
                            left -= 1;
                            return event(cpu, .syscall, 0, 0, 0);
                        }
                        regs.rip = at;
                        return switch (h.trap) {
                            .breakpoint => event(cpu, .breakpoint, 0, at, h.trap_val),
                            .misaligned => event(cpu, .misaligned, 0, h.trap_val, 0),
                            .divide => event(cpu, .divide, 0, at, h.trap_val),
                            else => event(cpu, .illegal, 0, at, h.trap_val),
                        };
                    },
                }
                since_poll = 0;
                if (irq) |p| if (p.* != 0) {
                    return stopEvent(cpu, .interrupt, .decoded, at);
                };
                if (brk) break;
            }
            if (brk) continue;
            continue;
        }
        // The first instruction could not be cached (long, straddling or a
        // decode fault): run it alone, exactly as the reference loop does.
        var local: decode.Insn = undefined;
        decode.one(s, &local) catch |err| switch (err) {
            error.PageFault => {
                cpu.priv.smc = 0;
                return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
            },
            error.Illegal => {
                regs.rip = ipc;
                return event(cpu, .illegal, 0, ipc, h.trap_val);
            },
        };
        if ((ipc & 4095) + local.len > 4096) {
            cpu.probe(ipc +% local.len - 1, .exec) catch {
                cpu.priv.smc = 0;
                return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
            };
        }
        regs.rip = ipc +% local.len;
        const e = exec.one(s, &local) catch {
            regs.rip = ipc;
            cpu.priv.smc = 0;
            return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
        };
        cpu.priv.smc = 0;
        switch (e) {
            .next => {
                left -= 1;
                since_poll += 1;
                if (since_poll < poll_every) continue;
            },
            .jump => left -= 1,
            .trap => {
                if (h.trap == .syscall) {
                    left -= 1;
                    return event(cpu, .syscall, 0, 0, 0);
                }
                regs.rip = ipc;
                return switch (h.trap) {
                    .breakpoint => event(cpu, .breakpoint, 0, ipc, h.trap_val),
                    .misaligned => event(cpu, .misaligned, 0, h.trap_val, 0),
                    .divide => event(cpu, .divide, 0, ipc, h.trap_val),
                    else => event(cpu, .illegal, 0, ipc, h.trap_val),
                };
            },
        }
        since_poll = 0;
        if (irq) |p| if (p.* != 0) return stopEvent(cpu, .interrupt, .decoded, ipc);
    }
}

pub fn runRef(cpu: *Cpu, regs: *Regs) u32 {
    const start = cpu.budget;
    var left = start;
    const icount0 = cpu.icount;
    defer {
        cpu.budget = left;
        cpu.icount = icount0 +% (start - left);
    }
    const irq = cpu.irq_pending;
    if (irq) |p| if (p.* != 0) return stopEvent(cpu, .interrupt, .entry, regs.rip);
    const h = &cpu.priv.hart;
    const s: c.St = .{ .r = regs, .h = h, .m = cpu };
    var since_poll: u32 = 0;
    while (true) {
        if (left == 0) return stopEvent(cpu, .budget, .budget, regs.rip);
        const ipc = regs.rip;
        // RDTSC and the counter read see the instructions retired so far.
        cpu.icount = icount0 +% (start - left);
        // Instruction fetch is an exec access: a non-executable page faults
        // here even though the decoder reads the bytes through the data
        // path (an instruction may straddle into the next page).
        cpu.probe(ipc, .exec) catch {
            cpu.priv.smc = 0;
            return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
        };
        var ins: decode.Insn = undefined;
        decode.one(s, &ins) catch |err| switch (err) {
            error.PageFault => {
                cpu.priv.smc = 0;
                return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
            },
            error.Illegal => {
                regs.rip = ipc;
                return event(cpu, .illegal, 0, ipc, h.trap_val);
            },
        };
        if ((ipc & 4095) + ins.len > 4096) {
            cpu.probe(ipc +% ins.len - 1, .exec) catch {
                cpu.priv.smc = 0;
                return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
            };
        }
        regs.rip = ipc +% ins.len;
        const e = exec.one(s, &ins) catch {
            regs.rip = ipc;
            cpu.priv.smc = 0;
            return event(cpu, .fault, cpu.priv.fault_access, cpu.priv.fault_addr, 0);
        };
        cpu.priv.smc = 0;
        switch (e) {
            .next => {
                left -= 1;
                since_poll += 1;
                if (since_poll < poll_every) continue;
            },
            .jump => left -= 1,
            .trap => {
                if (h.trap == .syscall) {
                    left -= 1; // SYSCALL retires; rip is already past it
                    return event(cpu, .syscall, 0, 0, 0);
                }
                regs.rip = ipc;
                return switch (h.trap) {
                    .breakpoint => event(cpu, .breakpoint, 0, ipc, h.trap_val),
                    .misaligned => event(cpu, .misaligned, 0, h.trap_val, 0),
                    .divide => event(cpu, .divide, 0, ipc, h.trap_val),
                    else => event(cpu, .illegal, 0, ipc, h.trap_val),
                };
            },
        }
        since_poll = 0;
        if (irq) |p| if (p.* != 0) return stopEvent(cpu, .interrupt, .reference, ipc);
    }
}

pub const StopTier = enum(u32) { none = 0, entry = 1, reference = 2, decoded = 3, compiled = 4, budget = 5 };

pub fn stopEvent(cpu: *Cpu, kind: core.Kind, tier: StopTier, block_pc: u64) u32 {
    cpu.priv.x86_64.stop_tier = @intFromEnum(tier);
    cpu.priv.x86_64.stop_block = block_pc;
    return event(cpu, kind, 0, 0, 0);
}

pub fn cpuInit(cpu: *Cpu) void {
    kwemu.cpuInit(cpu);
}

pub fn setIsa(cpu: *Cpu, isa: u64) u64 {
    cpu.priv.x86_64.isa = isa;
    cpu.resetCache();
    return cpu.priv.x86_64.isa;
}

/// Export the C ABI (from the library root only, so the unit tests can link
/// the native archive without duplicate symbols).
pub fn exportAbi() void {
    @export(&kw_cpu_init, .{ .name = "kw_cpu_init" });
    @export(&kw_run, .{ .name = "kw_run" });
    @export(&kw_set_pgd, .{ .name = "kw_set_pgd" });
    @export(&kw_flush_tlb_all, .{ .name = "kw_flush_tlb_all" });
    @export(&kw_flush_tlb_range, .{ .name = "kw_flush_tlb_range" });
    @export(&kw_clear_reservation, .{ .name = "kw_clear_reservation" });
    @export(&kw_abi_version, .{ .name = "kw_abi_version" });
    @export(&kw_isa_supported, .{ .name = "kw_isa_supported" });
    @export(&kw_set_isa, .{ .name = "kw_set_isa" });
    @export(&kw_host_reset, .{ .name = "kw_host_reset" });
    @export(&kw_debug_run_ref, .{ .name = "kw_debug_run_ref" });
    @export(&kw_debug_last_stop, .{ .name = "kw_debug_last_stop" });
}

fn kw_debug_run_ref(cpu: *Cpu, regs: *Regs) callconv(.c) u32 {
    return runRef(cpu, regs);
}
fn kw_debug_last_stop(cpu: *Cpu, block: *u64) callconv(.c) u32 {
    block.* = cpu.priv.x86_64.stop_block;
    return cpu.priv.x86_64.stop_tier;
}

fn kw_cpu_init(cpu: *Cpu) callconv(.c) void {
    cpuInit(cpu);
}
fn kw_run(cpu: *Cpu, regs: *Regs) callconv(.c) u32 {
    return run(cpu, regs);
}
fn kw_set_pgd(cpu: *Cpu, pgd: u64) callconv(.c) void {
    kwemu.setPgd(cpu, pgd);
}
fn kw_flush_tlb_all(cpu: *Cpu) callconv(.c) void {
    cpu.flushAll();
}
fn kw_flush_tlb_range(cpu: *Cpu, start: u64, end: u64) callconv(.c) void {
    cpu.flushRange(start, end);
}
fn kw_clear_reservation(cpu: *Cpu) callconv(.c) void {
    kwemu.clearReservation(cpu);
}
fn kw_abi_version() callconv(.c) u32 {
    return kwemu.abi_version;
}
fn kw_isa_supported() callconv(.c) u64 {
    return 0;
}
fn kw_set_isa(cpu: *Cpu, isa: u64) callconv(.c) u64 {
    return setIsa(cpu, isa);
}
fn kw_host_reset(cpu: *Cpu) callconv(.c) void {
    kwemu.hostReset(cpu);
}
