// SPDX-License-Identifier: MIT
//! f80 round/trunc without pulling in the f128 implementations (which the
//! wasm64 kernel does not link). Both use the integer conversions that the
//! x87rt subset already provides.
const rt = @import("../compiler_rt.zig");
const std = @import("std");

comptime {
    rt.symbol(&__roundx, "__roundx");
    rt.symbol(&__truncx, "__truncx");
    rt.symbol(&__floorx, "__floorx");
    rt.symbol(&__ceilx, "__ceilx");
    rt.symbol(&__ashlti3, "__ashlti3");
    rt.symbol(&__lshrti3, "__lshrti3");
    rt.symbol(&__multi3, "__multi3");
}

fn big(x: f80) bool {
    if (std.math.isNan(x) or std.math.isInf(x)) return true;
    return x >= 0x1p63 or x <= -0x1p63;
}

pub fn __roundx(x: f80) callconv(.c) f80 {
    if (big(x)) return x;
    const t: f80 = @floatFromInt(@as(i64, @intFromFloat(x)));
    const d = x - t;
    if (d >= 0.5) return t + 1;
    if (d <= -0.5) return t - 1;
    return t;
}

pub fn __truncx(x: f80) callconv(.c) f80 {
    if (big(x)) return x;
    return @floatFromInt(@as(i64, @intFromFloat(x)));
}

fn asU(x: i128) u128 {
    return @bitCast(x);
}
fn asI(x: u128) i128 {
    return @bitCast(x);
}

pub fn __ashlti3(a: i128, b: i32) callconv(.c) i128 {
    var v: [2]u64 = @bitCast(asU(a));
    const n: u7 = @intCast(@as(u32, @bitCast(b)) & 127);
    if (n >= 64) {
        v[1] = if (n == 64) v[0] else v[0] << @intCast(n - 64);
        v[0] = 0;
    } else if (n != 0) {
        v[1] = (v[1] << @intCast(n)) | (v[0] >> @intCast(64 - n));
        v[0] <<= @intCast(n);
    }
    return asI(@bitCast(v));
}

pub fn __lshrti3(a: i128, b: i32) callconv(.c) i128 {
    var v: [2]u64 = @bitCast(asU(a));
    const n: u7 = @intCast(@as(u32, @bitCast(b)) & 127);
    if (n >= 64) {
        v[0] = if (n == 64) v[1] else v[1] >> @intCast(n - 64);
        v[1] = 0;
    } else if (n != 0) {
        v[0] = (v[0] >> @intCast(n)) | (v[1] << @intCast(64 - n));
        v[1] >>= @intCast(n);
    }
    return asI(@bitCast(v));
}

pub fn __multi3(a: i128, b: i128) callconv(.c) i128 {
    const av: [2]u64 = @bitCast(asU(a));
    const bv: [2]u64 = @bitCast(asU(b));
    var hi0: u64 = undefined;
    var lo0: u64 = undefined;
    rt.wideMultiply(u64, av[0], bv[0], &hi0, &lo0);
    const lo = lo0;
    const hi = hi0 +% av[0] *% bv[1] +% av[1] *% bv[0];
    return asI(@bitCast([2]u64{ lo, hi }));
}

pub fn __floorx(x: f80) callconv(.c) f80 {
    if (big(x)) return x;
    const t: f80 = @floatFromInt(@as(i64, @intFromFloat(x)));
    return if (x < t) t - 1 else t;
}

pub fn __ceilx(x: f80) callconv(.c) f80 {
    if (big(x)) return x;
    const t: f80 = @floatFromInt(@as(i64, @intFromFloat(x)));
    return if (x > t) t + 1 else t;
}
