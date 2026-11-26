// SPDX-License-Identifier: MIT
//! Zig's x87 soft-float builtins, vendored because the kernel's compiler-rt
//! has no f80 helpers for wasm64: without these the module imports
//! __addxf3, __extenddfxf2, ... which the host does not provide. The files
//! are from Zig 0.16.0 (MIT); x87rt/compiler_rt.zig is the tiny slice of
//! compiler_rt.zig they use.
comptime {
    _ = @import("x87rt/addxf3.zig");
    _ = @import("x87rt/subxf3.zig");
    _ = @import("x87rt/mulxf3.zig");
    _ = @import("x87rt/divxf3.zig");
    _ = @import("x87rt/extenddfxf2.zig");
    _ = @import("x87rt/extendsfxf2.zig");
    _ = @import("x87rt/truncxfdf2.zig");
    _ = @import("x87rt/truncxfsf2.zig");
    _ = @import("x87rt/fixxfdi.zig");
    _ = @import("x87rt/fixxfsi.zig");
    _ = @import("x87rt/floatdixf.zig");
    _ = @import("x87rt/floatsixf.zig");
    _ = @import("x87rt/cmpxf2.zig");
    _ = @import("x87rt/gexf2.zig");
    _ = @import("x87rt/sqrt.zig");
    _ = @import("x87rt/x87extra.zig");
    _ = @import("x87rt/fmod.zig");
}
