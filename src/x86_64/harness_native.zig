// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! Native front end of the x86-64 kwemu harness (links the x86-64 native
//! libkwemu.a).
//! usage: kwemu-harness-x86 [--stats] [--verbose] [--slice N] [--mem MiB] guest.elf [args...]

const std = @import("std");
const kw = @import("kw_h");
const harness = @import("harness.zig");

var io: std.Io = undefined;

fn hostWrite(fd: i32, bytes: []const u8) void {
    const f = if (fd == 2) std.Io.File.stderr() else std.Io.File.stdout();
    f.writeStreamingAll(io, bytes) catch {};
}

fn nowNs() u64 {
    return @intCast(@max(0, std.Io.Clock.awake.now(io).toNanoseconds()));
}

var cpu_block: [kw.KW_CPU_SIZE]u8 align(8) = undefined;

pub fn main(init: std.process.Init) !u8 {
    io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var opt: harness.Options = .{};
    var mem_mib: usize = 512;
    var i: usize = 1;
    while (i < args.len and std.mem.startsWith(u8, args[i], "--")) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--stats")) opt.stats = true;
        if (std.mem.eql(u8, args[i], "--verbose")) opt.verbose = true;
        if (std.mem.eql(u8, args[i], "--slice") and i + 1 < args.len) {
            i += 1;
            opt.slice = try std.fmt.parseInt(u64, args[i], 10);
        }
        if (std.mem.eql(u8, args[i], "--mem") and i + 1 < args.len) {
            i += 1;
            mem_mib = try std.fmt.parseInt(usize, args[i], 10);
        }
    }
    if (i >= args.len) {
        hostWrite(2, "usage: kwemu-harness-x86 [--stats] [--verbose] [--slice N] [--mem MiB] guest.elf [args...]\n");
        return 2;
    }
    const image = try std.Io.Dir.cwd().readFileAlloc(io, args[i], gpa, .limited(256 << 20));
    defer gpa.free(image);
    const mem = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(4096), mem_mib << 20);
    defer std.heap.page_allocator.free(mem);
    var m = harness.Machine.init(.{ .write = hostWrite, .now_ns = nowNs }, opt, mem, &cpu_block);
    const env: []const []const u8 = &.{ "HOME=/", "PATH=/bin", "TERM=dumb" };
    m.load(image, args[i..], env) catch |e| {
        hostWrite(2, @errorName(e));
        hostWrite(2, ": cannot load guest\n");
        return 2;
    };
    return m.run();
}
