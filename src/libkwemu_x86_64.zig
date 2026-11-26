// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! Root of the x86-64 kwemu library build (static archive + relocatable
//! object), selected with `-Dkw-user-isa=x86_64`. The contract is
//! include/kw_emu.h built with KW_USER_ISA_X86_64; the C ABI is exported
//! from x86_64/run.zig on top of the MMU in emu/kwemu.zig.

const x86 = @import("x86_64/run.zig");

comptime {
    x86.exportAbi();
}

pub const panic = @import("std").debug.no_panic;
