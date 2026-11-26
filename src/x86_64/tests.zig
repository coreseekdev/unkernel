// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! Unit tests of the x86-64 reference interpreter (native): instruction
//! semantics, flags, memory forms, SSE2, the system instructions and
//! precise faults. The differential guests (test/guest/x86_64 and
//! test/x86-64-test.mjs) cover the long tail against qemu-x86_64; add a
//! test here for anything a guest cannot reach or for an edge case the
//! compiler never emits.

const std = @import("std");
const t = std.testing;
const mach = @import("machine.zig");
const state = @import("state.zig");
const Machine = mach.Machine;

const EV_BUDGET = mach.EV_BUDGET;
const EV_SYSCALL = mach.EV_SYSCALL;
const EV_FAULT = mach.EV_FAULT;
const EV_ILLEGAL = mach.EV_ILLEGAL;
const EV_BREAKPOINT = mach.EV_BREAKPOINT;
const EV_MISALIGNED = mach.EV_MISALIGNED;

/// syscall
const syscall = [_]u8{ 0x0f, 0x05 };
/// ud2
const ud2 = [_]u8{ 0x0f, 0x0b };

fn flags(m: *Machine) u64 {
    return m.regs.eflags;
}

test "x86_64: mov imm, add and syscall retire" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc0, 0x2a, 0, 0, 0, // mov rax, 42
        0x48, 0x83, 0xc0, 0x08, // add rax, 8
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 50), m.regs.rax);
    try t.expectEqual(@as(u64, 0x100d), m.regs.rip);
    try t.expectEqual(@as(u64, 3), m.cpu.icount);
}

test "x86_64: 8/16/32-bit writes zero-extend, 8-bit registers and REX" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // mov rax, -1
        0xb0, 0x12, // mov al, 0x12
        0x66, 0xb8, 0x34, 0x12, // mov ax, 0x1234
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0x1234_5678), m.regs.rax);
}

test "x86_64: AH/CH/DH/BH without REX, SPL/BPL/SIL/DIL with REX" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0x48, 0xb8, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // mov rax, 0x7766554433221100
        0x48, 0xc7, 0xc4, 0x00, 0x01, 0x00, 0x00, // mov rsp, 0x100
        0xb4, 0xaa, // mov ah, 0xaa
        0x40, 0xb4, 0xbb, // rex mov spl, 0xbb
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0x7766_5544_3322_aa00), m.regs.rax);
    try t.expectEqual(@as(u64, 0x1bb), m.regs.rsp);
}

test "x86_64: ALU flags (add/sub/cmp, CF, OF, ZF, SF, PF, AF)" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    // 0x7fffffff + 1: OF=1, SF=1, ZF=0, CF=0; then 1 - 1: ZF=1, CF=0.
    m.code(0x1000, &([_]u8{
        0xb8, 0xff, 0xff, 0xff, 0x7f, // mov eax, 0x7fffffff
        0x83, 0xc0, 0x01, // add eax, 1
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0x8000_0000), m.regs.rax);
    try t.expect(flags(&m) & state.OF != 0);
    try t.expect(flags(&m) & state.SF != 0);
    try t.expect(flags(&m) & state.ZF == 0);
    try t.expect(flags(&m) & state.CF == 0);

    var n = try Machine.init(t.allocator);
    defer n.deinit();
    n.code(0x1000, &([_]u8{
        0x31, 0xc0, // xor eax,eax (ZF=1)
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x83, 0xe8, 0x01, // sub eax, 1
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, n.run(100));
    try t.expectEqual(@as(u64, 0), n.regs.rax);
    try t.expect(flags(&n) & state.ZF != 0);
    try t.expect(flags(&n) & state.CF == 0);
    try t.expect(flags(&n) & state.OF == 0);
}

test "x86_64: adc and sbb consume carry" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0xf9, // stc
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x83, 0xd0, 0x00, // adc eax, 0
        0x83, 0xd8, 0x00, // sbb eax, 0
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 2), m.regs.rax); // (1 + 1) - 0 = 2
}

test "x86_64: inc/dec preserve CF, neg/not" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0xf9, // stc
        0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff
        0xff, 0xc0, // inc eax -> 0, ZF=1, CF stays 1
        0xf7, 0xd8, // neg eax -> 0
        0xf7, 0xd0, // not eax -> 0xffffffff
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0xffff_ffff), m.regs.rax);
    try t.expect(flags(&m) & state.CF == 0);
}

test "x86_64: shifts by imm and CL, sar sign fill" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0x48, 0xb8, 0x00, 0, 0, 0, 0, 0, 0, 0x80, // mov rax, 0x8000000000000000
        0x48, 0xd1, 0xf8, // sar rax, 1
        0x48, 0xc1, 0xe8, 0x02, // shr rax, 2
        0xb1, 0x03, // mov cl, 3
        0x48, 0xd3, 0xe8, // shr rax, cl
    } ++ syscall));
    m.regs.rip = 0x100a; // at sar
    m.regs.rax = 0x8000_0000_0000_0000;
    try t.expectEqual(EV_BUDGET, m.run(1));
    try t.expectEqual(@as(u64, 0xc000_0000_0000_0000), m.regs.rax);
    try t.expectEqual(EV_BUDGET, m.run(1));
    try t.expectEqual(@as(u64, 0x3000_0000_0000_0000), m.regs.rax);
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0x0600_0000_0000_0000), m.regs.rax);
}

test "x86_64: mul, imul forms, div and idiv" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc0, 0x07, 0, 0, 0, // mov rax, 7
        0x48, 0xc7, 0xc3, 0x09, 0, 0, 0, // mov rbx, 9
        0x48, 0x0f, 0xaf, 0xc3, // imul rax, rbx
        0x48, 0x6b, 0xc0, 0x02, // imul rax, rax, 2
        0x48, 0x31, 0xd2, // xor rdx, rdx
        0x48, 0xf7, 0xf3, // div rbx
        0x48, 0x89, 0xd0, // mov rax, rdx (remainder)
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0), m.regs.rax); // 126 / 9 = 14 r 0
    try t.expectEqual(@as(u64, 0), m.regs.rdx);

    var n = try Machine.init(t.allocator);
    defer n.deinit();
    n.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc0, 0xfd, 0xff, 0xff, 0xff, // mov rax, -3
        0x48, 0x99, // cqo
        0x48, 0xc7, 0xc3, 0x02, 0, 0, 0, // mov rbx, 2
        0x48, 0xf7, 0xfb, // idiv rbx
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, n.run(100));
    try t.expectEqual(@as(u64, @bitCast(@as(i64, -1))), n.regs.rax);
    try t.expectEqual(@as(u64, @bitCast(@as(i64, -1))), n.regs.rdx);
}

test "x86_64: stack, call/ret and leave" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x80000, 1);
    m.regs.rsp = 0x80f00;
    var code_buf: [64]u8 = @splat(0x90);
    const callfn = [_]u8{ 0xe8, 0x07, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0xc7, 0xc0, 0x2a, 0, 0, 0, 0xc3 };
    @memcpy(code_buf[0..callfn.len], &callfn);
    m.code(0x1000, &code_buf);
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 42), m.regs.rax);
    try t.expectEqual(@as(u64, 0x80f00), m.regs.rsp);

    var n = try Machine.init(t.allocator);
    defer n.deinit();
    n.mapData(0x80000, 1);
    n.regs.rsp = 0x800f0;
    n.regs.rbp = 0x800f8;
    const val: u64 = 0x1234_5678;
    @memcpy(n.at(0x800f8)[0..8], std.mem.asBytes(&val));
    n.code(0x1000, &([_]u8{ 0xc9, 0x50 } ++ syscall)); // leave; push rax
    try t.expectEqual(EV_SYSCALL, n.run(100));
    try t.expectEqual(@as(u64, 0x1234_5678), n.regs.rbp);
}

test "x86_64: memory forms (SIB, disp, RIP-relative), movzx/movsx/lea" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x20000, 2);
    const w0: u64 = 0x1122_3344_5566_7788;
    const w1: u64 = 0x8877_6655_4433_2211;
    @memcpy(m.at(0x20000)[0..8], std.mem.asBytes(&w0));
    @memcpy(m.at(0x20010)[0..8], std.mem.asBytes(&w1));
    m.at(0x20020)[0] = 0xf0;
    m.at(0x20024)[0] = 0x7f;
    const d1: u32 = 0x8000_0001;
    @memcpy(m.at(0x20028)[0..4], std.mem.asBytes(&d1));
    m.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc3, 0x00, 0x00, 0x02, 0x00, // mov rbx, 0x20000
        0x48, 0xc7, 0xc1, 0x00, 0, 0, 0, // mov rcx, 0
        0x48, 0x8b, 0x44, 0x8b, 0x00, // mov rax, [rbx+rcx*4]
        0x0f, 0xb6, 0x4b, 0x20, // movzx ecx, byte [rbx+0x20]
        0x48, 0x0f, 0xbe, 0x4b, 0x24, // movsx rcx, byte [rbx+0x24]
        0x48, 0x63, 0x53, 0x28, // movsxd rdx, dword [rbx+0x28]
        0x48, 0x8d, 0x74, 0x8b, 0x10, // lea rsi, [rbx+rcx*4+0x10]
        0x48, 0xa3, 0x00, 0x00, 0x03, 0x00, 0, 0, 0, 0, // mov [0x30000], rax
        0x48, 0x8b, 0x3d, 0x02, 0x00, 0x00, 0x00, // mov rdi, [rip+2]
        0x0f, 0x05, // syscall
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, // data
    }));
    // data page 0x30000
    m.mapData(0x30000, 1);
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0x1122_3344_5566_7788), m.regs.rax);
    try t.expectEqual(@as(u64, 0x2020c), m.regs.rsi);
    try t.expectEqual(@as(u64, 0xffff_ffff_8000_0001), m.regs.rdx);
    // The RIP-relative load reads the 8 data bytes after the syscall.
    try t.expectEqual(@as(u64, 0x2211_ffeeddcc_bbaa), m.regs.rdi);
    // The moffs store went to 0x30000.
    const stored = std.mem.readInt(u64, m.at(0x30000)[0..8], .little);
    try t.expectEqual(@as(u64, 0x1122_3344_5566_7788), stored);
}

test "x86_64: jcc, cmovcc, setcc" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
        0x83, 0xf8, 0x05, // cmp eax, 5
        0xbb, 0x01, 0x00, 0x00, 0x00, // mov ebx, 1
        0x74, 0x05, // je +5 (to cmov)
        0xbb, 0x02, 0x00, 0x00, 0x00, // mov ebx, 2 (skipped)
        0x48, 0x0f, 0x44, 0xd9, // cmove rbx, rcx (rcx=0)
        0x0f, 0x95, 0xc0, // setne al (ZF=1 so al=0)
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0), m.regs.rbx);
    try t.expectEqual(@as(u64, 0), m.regs.rax & 0xff);
}

test "x86_64: rep movsb and rep stosb" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x20000, 2);
    @memcpy(m.at(0x20000)[0..5], "hello");
    m.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc6, 0x00, 0x00, 0x02, 0x00, // mov rsi, 0x20000
        0x48, 0xc7, 0xc7, 0x00, 0x10, 0x02, 0x00, // mov rdi, 0x21000
        0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5
        0xf3, 0xa4, // rep movsb
        0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
        0xaa, // stosb (ecx now 0, but not rep)
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqualStrings("hello", m.at(0x21000)[0..5]);
    try t.expectEqual(@as(u8, 42), m.at(0x21005)[0]);
    try t.expectEqual(@as(u64, 0x21006), m.regs.rdi);
}

test "x86_64: SSE2 packed add, movdqu load/store" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x20000, 1);
    // {1,2,3,4} and {10,20,30,40}
    const a = [_]u32{ 1, 2, 3, 4 };
    const b = [_]u32{ 10, 20, 30, 40 };
    @memcpy(m.at(0x20000)[0..16], std.mem.asBytes(&a));
    @memcpy(m.at(0x20010)[0..16], std.mem.asBytes(&b));
    m.code(0x1000, &([_]u8{
        0xf3, 0x0f, 0x6f, 0x04, 0x25, 0x00, 0x00, 0x02, 0x00, // movdqu xmm0, [0x20000]
        0xf3, 0x0f, 0x6f, 0x0c, 0x25, 0x10, 0x00, 0x02, 0x00, // movdqu xmm1, [0x20010]
        0x66, 0x0f, 0xfe, 0xc1, // paddd xmm0, xmm1
        0xf3, 0x0f, 0x7f, 0x04, 0x25, 0x00, 0x00, 0x02, 0x00, // movdqu [0x20000], xmm0
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    const got: []const u32 = @alignCast(std.mem.bytesAsSlice(u32, m.at(0x20000)[0..16]));
    try t.expectEqual(@as(u32, 11), got[0]);
    try t.expectEqual(@as(u32, 22), got[1]);
    try t.expectEqual(@as(u32, 33), got[2]);
    try t.expectEqual(@as(u32, 44), got[3]);
}

test "x86_64: SSE scalar float, conversion and MXCSR" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x20000, 1);
    const one: f32 = 1.5;
    const two: f32 = 2.25;
    @memcpy(m.at(0x20000)[0..4], std.mem.asBytes(&one));
    @memcpy(m.at(0x20004)[0..4], std.mem.asBytes(&two));
    m.code(0x1000, &([_]u8{
        0xf3, 0x0f, 0x10, 0x04, 0x25, 0x00, 0x00, 0x02, 0x00, // movss xmm0, [0x20000]
        0xf3, 0x0f, 0x58, 0x04, 0x25, 0x04, 0x00, 0x02, 0x00, // addss xmm0, [0x20004]
        0xf3, 0x0f, 0x11, 0x04, 0x25, 0x10, 0x00, 0x02, 0x00, // movss [0x20010], xmm0
        0xf3, 0x0f, 0x2c, 0xc0, // cvttss2si eax, xmm0
        0x66, 0x0f, 0x2e, 0xc0, // ucomiss xmm0, xmm0 (ZF=1)
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    const got: f32 = @bitCast(std.mem.readInt(u32, m.at(0x20010)[0..4], .little));
    try t.expectEqual(@as(f32, 3.75), got);
    try t.expectEqual(@as(u64, 3), m.regs.rax);
    try t.expect(flags(&m) & state.ZF != 0);
}

test "x86_64: cpuid and rdtsc" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x0f, 0xa2, // cpuid
        0x48, 0x31, 0xc0, // xor rax, rax
        0x0f, 0x31, // rdtsc
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expect((m.regs.rdx << 32 | (m.regs.rax & 0xffff_ffff)) > 0);
}

test "x86_64: SYSCALL sets rcx/r11 and retires with rip past it" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &([_]u8{
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
    } ++ syscall));
    m.regs.eflags |= state.IF | state.FLAGS_RESERVED;
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 60), m.regs.rax);
    try t.expectEqual(@as(u64, 0x1007), m.regs.rcx);
    try t.expectEqual(@as(u64, 0x1007), m.regs.rip);
    try t.expectEqual(m.regs.eflags, m.regs.r11);
    try t.expectEqual(@as(u64, 2), m.cpu.icount);
}

test "x86_64: a faulting instruction has no architectural effect" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    // Code page is R|X: a qword INC there must fault on the write probe
    // before flags or memory change.
    m.code(0x1000, &([_]u8{
        0xf9, // stc
        0x48, 0xc7, 0xc0, 0x05, 0, 0, 0, // mov rax, 5
        0x48, 0xff, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00, // inc qword [0x1000]
    }));
    try t.expectEqual(EV_FAULT, m.run(100));
    try t.expectEqual(@as(u64, 5), m.regs.rax);
    try t.expect(flags(&m) & state.CF != 0);
    try t.expectEqual(@as(u64, 0x1008), m.regs.rip);
    try t.expectEqual(@as(u64, 0x1000), m.cpu.ev.addr & ~@as(u64, 0xfff));
    try t.expectEqual(@as(u32, 1), m.cpu.ev.access); // write
}

test "x86_64: ud2 and int3 report illegal/breakpoint at the instruction" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.code(0x1000, &ud2);
    try t.expectEqual(EV_ILLEGAL, m.run(10));
    try t.expectEqual(@as(u64, 0x1000), m.regs.rip);
    try t.expectEqual(@as(u64, 0x0b0f), m.cpu.ev.insn);

    var n = try Machine.init(t.allocator);
    defer n.deinit();
    n.code(0x1000, &[_]u8{0xcc});
    try t.expectEqual(EV_BREAKPOINT, n.run(10));
    try t.expectEqual(@as(u64, 0x1000), n.regs.rip);
}

test "x86_64: movdqa requires alignment" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x20000, 1);
    m.code(0x1000, &([_]u8{
        0x66, 0x0f, 0x6f, 0x04, 0x25, 0x01, 0x00, 0x02, 0x00, // movdqa xmm0, [0x20001]
    }));
    try t.expectEqual(EV_MISALIGNED, m.run(10));
    try t.expectEqual(@as(u64, 0x20001), m.cpu.ev.addr);
}

test "x86_64: bswap, popcnt, tzcnt, bt, cmpxchg and xadd" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x20000, 1);
    const five: u64 = 5;
    @memcpy(m.at(0x20000)[0..8], std.mem.asBytes(&five));
    m.code(0x1000, &([_]u8{
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0x0f, 0xc8, // bswap eax
        0xf3, 0x0f, 0xb8, 0xc0, // popcnt eax, eax
        0xf3, 0x0f, 0xbc, 0xd8, // tzcnt ebx, eax
        0x48, 0xc7, 0xc0, 0x00, 0x00, 0x02, 0x00, // mov rax, 0x20000
        0x48, 0x0f, 0xba, 0x20, 0x02, // bt [rax], 2 (bit 2 of 5 is 1)
        0x48, 0xc7, 0xc3, 0x05, 0, 0, 0, // mov rbx, 5
        0x48, 0xc7, 0xc2, 0x06, 0, 0, 0, // mov rdx, 6
        0x48, 0x0f, 0xc1, 0x18, // xadd [rax], rbx (5+5=10, rbx=5)
        0x48, 0x31, 0xc9, // xor rcx, rcx
        0x48, 0x0f, 0xb1, 0x18, // cmpxchg [rax], rbx (rax=0x20000? no: accumulator is rax)
    } ++ syscall));
    // The last cmpxchg compares RAX (0x20000) with [0x20000] (10) and
    // fails: ZF=0 and RAX gets 10.
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 10), m.regs.rax);
    try t.expect(flags(&m) & state.ZF == 0);
    try t.expectEqual(@as(u64, 10), std.mem.readInt(u64, m.at(0x20000)[0..8], .little));
}

test "x86_64: a faulting push and pop leave rsp unchanged" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    // rsp points into the read-execute code page: the push's store faults.
    m.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc0, 0x2a, 0, 0, 0, // mov rax, 42
        0x50, // push rax
    }));
    m.regs.rsp = 0x1008;
    try t.expectEqual(EV_FAULT, m.run(10));
    try t.expectEqual(@as(u64, 0x1008), m.regs.rsp);
    try t.expectEqual(@as(u64, 0x1007), m.regs.rip);

    // pop to a faulting memory destination: rax and rsp both stay.
    var n = try Machine.init(t.allocator);
    defer n.deinit();
    n.mapData(0x20000, 1);
    const ret: u64 = 0xdead_beef;
    @memcpy(n.at(0x20000)[0..8], std.mem.asBytes(&ret));
    n.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc0, 0x11, 0, 0, 0, // mov rax, 0x11
        0x8f, 0x04, 0x25, 0x00, 0x30, 0x00, 0x00, // pop qword [0x30000]
    }));
    n.regs.rsp = 0x20000;
    try t.expectEqual(EV_FAULT, n.run(10));
    try t.expectEqual(@as(u64, 0x11), n.regs.rax);
    try t.expectEqual(@as(u64, 0x20000), n.regs.rsp);
}

test "x86_64: clflush is a no-op and movnti stores" {
    var m = try Machine.init(t.allocator);
    defer m.deinit();
    m.mapData(0x20000, 1);
    m.code(0x1000, &([_]u8{
        0x48, 0xc7, 0xc0, 0x00, 0x00, 0x02, 0x00, // mov rax, 0x20000
        0x0f, 0xae, 0x38, // clflush [rax]
        0x48, 0xc7, 0xc3, 0x78, 0x56, 0x34, 0x12, // mov rbx, 0x12345678
        0x48, 0x0f, 0xc3, 0x18, // movnti [rax], rbx
    } ++ syscall));
    try t.expectEqual(EV_SYSCALL, m.run(100));
    try t.expectEqual(@as(u64, 0x1234_5678), std.mem.readInt(u64, m.at(0x20000)[0..8], .little));
}
