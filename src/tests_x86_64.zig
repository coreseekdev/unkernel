// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! Native unit-test root of the x86-64 CPU (`zig build test-x86-64` and the
//! `test` step).
test {
    _ = @import("x86_64/tests.zig");
}
