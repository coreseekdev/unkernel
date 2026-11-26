// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! wasm64 front end of the x86-64 kwemu test harness (links the wasm64
//! libkwemu.a).
//!
//! Imports (module "env"): host_write(fd: i32, ptr, len), host_now_ns() -> f64.
//! Exports: kwh_buf(len) -> ptr, kwh_run(elf_len, args_len, flags) -> status.

const std = @import("std");
const kw = @import("kw_h");
const harness = @import("harness.zig");

extern "env" fn host_write(fd: i32, ptr: [*]const u8, len: usize) void;
extern "env" fn host_now_ns() f64;

pub const panic = std.debug.FullPanic(struct {
    fn f(msg: []const u8, _: ?usize) noreturn {
        host_write(2, "harness panic: ", 15);
        host_write(2, msg.ptr, msg.len);
        host_write(2, "\n", 1);
        @trap();
    }
}.f);

fn hostWrite(fd: i32, bytes: []const u8) void {
    host_write(fd, bytes.ptr, bytes.len);
}
fn nowNs() u64 {
    return @intFromFloat(@max(0, host_now_ns()));
}

var cpu_block: [kw.KW_CPU_SIZE]u8 align(8) = undefined;
var scratch: [48 << 20]u8 = undefined;
var phys: ?[]align(4096) u8 = null;
var phys_used: usize = 0;
const phys_size = 512 << 20;

export fn kwh_buf(len: usize) ?[*]u8 {
    return if (len <= scratch.len) &scratch else null;
}

export fn kwh_run(elf_len: usize, args_len: usize, flags: u32) i32 {
    if (phys) |p| @memset(p[0..phys_used], 0) else {
        const pages = phys_size / 65536;
        const old = @wasmMemoryGrow(0, pages + 1);
        if (old < 0) return -1;
        const start = std.mem.alignForward(usize, @as(usize, @intCast(old)) * 65536, 4096);
        phys = @as([*]align(4096) u8, @ptrFromInt(start))[0..phys_size];
    }
    var argv: [harness.max_args - 3][]const u8 = undefined;
    var argc: usize = 0;
    var it = std.mem.splitScalar(u8, scratch[elf_len..][0..args_len], 0);
    while (it.next()) |s| {
        if (s.len == 0) continue;
        if (argc == argv.len) return -3;
        argv[argc] = s;
        argc += 1;
    }
    var m = harness.Machine.init(.{ .write = hostWrite, .now_ns = nowNs }, .{
        .stats = flags & 1 != 0,
        .verbose = flags & 2 != 0,
    }, phys.?, &cpu_block);
    m.load(scratch[0..elf_len], argv[0..argc], &.{ "HOME=/", "PATH=/bin", "TERM=dumb" }) catch |e| {
        hostWrite(2, @errorName(e));
        hostWrite(2, ": cannot load guest\n");
        return -2;
    };
    const status = m.run();
    phys_used = @intCast(m.next_frame);
    return status;
}
