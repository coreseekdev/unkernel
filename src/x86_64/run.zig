// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! The C ABI of include/kw_emu.h (x86-64) and the reference run loop: one
//! instruction at a time through decode.zig and exec.zig. This is the
//! semantic oracle; a decoded-op tier and the wasm JIT come later
//! (HANDOFF.md phase 4). struct kw_cpu, the Sv48-format page-table walker,
//! the TLBs and the flushes are kwemu.Cpu (src/emu/kwemu.zig).

const std = @import("std");
const builtin = @import("builtin");
const core = @import("../cpu/core.zig");
const kwemu = @import("../emu/kwemu.zig");
const c = @import("common.zig");
const decode = @import("decode.zig");
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
    return runRef(cpu, regs);
}

/// The reference loop: decode and execute one instruction at a time,
/// polling *irq_pending after every taken branch and every 64 instructions.
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
