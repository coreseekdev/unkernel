// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
//! A tiny "kernel" that drives the x86-64 kwemu through the C ABI only
//! (include/kw_emu.h with KW_USER_ISA_X86_64), the way the real wasm Linux
//! kernel will:
//!
//!   * builds Sv48 page tables in its own "physical memory" buffer
//!     (physical address 0x8000_0000 = first byte of the buffer);
//!   * loads a static x86-64 ELF, builds argv/envp/auxv on the stack;
//!   * demand paging: mmap/brk/stack only *reserve* pages (non-valid PTEs
//!     carrying a software "reserved" bit + prot); faults allocate frames;
//!   * new PTEs start with A=0/D=0, so the emulator faults again and the
//!     kernel sets A (and D on writes) and flushes the TLB range;
//!   * runs in budget slices and services the Linux x86-64 syscalls a
//!     static musl program needs.
//!
//! Platform-independent: native and wasm front ends supply a `Host`.

const std = @import("std");
const kw = @import("kw_h");

pub const Host = struct {
    write: *const fn (fd: i32, bytes: []const u8) void,
    now_ns: *const fn () u64,
};

pub const Options = struct {
    slice: u64 = 2_000_000,
    stats: bool = false,
    verbose: bool = false,
    fake_time: bool = false,
};

/// Not in the ABI: the x86-64 run loop.
extern fn kw_debug_run_ref(cpu: *kw.struct_kw_cpu, regs: *kw.struct_kw_regs) u32;

pub const max_args = 1024;

const page: u64 = 4096;
const pa_base: u64 = 0x8000_0000;

const pte_v: u64 = 1 << 0;
const pte_r: u64 = 1 << 1;
const pte_w: u64 = 1 << 2;
const pte_x: u64 = 1 << 3;
const pte_u: u64 = 1 << 4;
const pte_a: u64 = 1 << 6;
const pte_d: u64 = 1 << 7;
const pte_resv: u64 = 1 << 8;
const prot_bits = pte_r | pte_w | pte_x;

const stack_top: u64 = 0x3f_ffff_0000;
const stack_size: u64 = 8 << 20;
const mmap_base: u64 = 0x3f_0000_0000;
const exec_bias: u64 = 0x1000_0000;

// errno
const ENOENT = 2;
const EBADF = 9;
const ENOMEM = 12;
const EFAULT = 14;
const EINVAL = 22;
const ENOTTY = 25;
const ESPIPE = 29;
const ENOSYS = 38;
const ERANGE = 34;

pub const Stats = struct {
    syscalls: u64 = 0,
    demand_faults: u64 = 0,
    ad_faults: u64 = 0,
    spurious_faults: u64 = 0,
    slices: u64 = 0,
};

pub const Machine = struct {
    host: Host,
    opt: Options,
    mem: []align(4096) u8,
    next_frame: u64 = 0,
    root: u64 = 0,
    cpu: *kw.struct_kw_cpu,
    regs: kw.struct_kw_regs = std.mem.zeroes(kw.struct_kw_regs),
    brk_start: u64 = 0,
    brk: u64 = 0,
    mmap_top: u64 = mmap_base,
    exit_code: ?u8 = null,
    rng: u64 = 0x9e37_79b9_7f4a_7c15,
    stats: Stats = .{},

    pub fn init(host: Host, opt: Options, mem: []align(4096) u8, cpu_block: *align(8) [kw.KW_CPU_SIZE]u8) Machine {
        var m: Machine = .{ .host = host, .opt = opt, .mem = mem, .cpu = @ptrCast(cpu_block) };
        kw.kw_cpu_init(m.cpu);
        m.cpu.phys_base = @intFromPtr(mem.ptr) -% pa_base;
        m.root = m.allocFrame();
        kw.kw_set_pgd(m.cpu, m.root);
        m.regs.eflags = 0x202;
        m.regs.cs = 0x33;
        m.regs.ss = 0x2b;
        m.regs.mxcsr = 0x1f80;
        return m;
    }

    fn print(m: *Machine, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        m.host.write(2, std.fmt.bufPrint(&buf, fmt, args) catch return);
    }

    fn allocFrame(m: *Machine) u64 {
        if (m.next_frame + page > m.mem.len) {
            m.print("harness: out of physical memory\n", .{});
            @panic("oom");
        }
        const pa = pa_base + m.next_frame;
        m.next_frame += page;
        return pa;
    }

    fn hostPtr(m: *Machine, pa: u64) [*]u8 {
        return m.mem.ptr + @as(usize, @intCast(pa - pa_base));
    }

    fn table(m: *Machine, pa: u64) *[512]u64 {
        return @ptrCast(@alignCast(m.hostPtr(pa)));
    }

    fn slot(m: *Machine, va: u64, create: bool) ?*u64 {
        var t = m.root;
        var level: u6 = 3;
        while (level > 0) : (level -= 1) {
            const e = &m.table(t)[@intCast((va >> (12 + 9 * level)) & 511)];
            if (e.* & pte_v == 0) {
                if (!create) return null;
                e.* = ((m.allocFrame() >> 12) << 10) | pte_v;
            }
            t = (e.* >> 10) << 12;
        }
        return &m.table(t)[@intCast((va >> 12) & 511)];
    }

    fn protPte(prot: u64) u64 {
        var p: u64 = 0;
        if (prot & 1 != 0) p |= pte_r;
        if (prot & 2 != 0) p |= pte_w | pte_r;
        if (prot & 4 != 0) p |= pte_x;
        return p;
    }

    fn reserve(m: *Machine, start: u64, end: u64, prot: u64) void {
        var va = start;
        while (va < end) : (va += page) {
            const s = m.slot(va, true).?;
            if (s.* & pte_v != 0) {
                s.* = (s.* & ~prot_bits) | protPte(prot);
            } else s.* = pte_resv | protPte(prot);
        }
        kw.kw_flush_tlb_range(m.cpu, start, end);
    }

    fn unmap(m: *Machine, start: u64, end: u64) void {
        var va = start;
        while (va < end) : (va += page) {
            if (m.slot(va, false)) |s| s.* = 0;
        }
        kw.kw_flush_tlb_range(m.cpu, start, end);
    }

    fn protect(m: *Machine, start: u64, end: u64, prot: u64) void {
        var va = start;
        while (va < end) : (va += page) {
            const s = m.slot(va, false) orelse continue;
            if (s.* & (pte_v | pte_resv) != 0) s.* = (s.* & ~prot_bits) | protPte(prot);
        }
        kw.kw_flush_tlb_range(m.cpu, start, end);
    }

    fn populate(m: *Machine, s: *u64) void {
        const frame = m.allocFrame();
        s.* = ((frame >> 12) << 10) | (s.* & prot_bits) | pte_v | pte_u;
        m.stats.demand_faults += 1;
    }

    fn userPage(m: *Machine, va: u64) ?[]u8 {
        const s = m.slot(va, false) orelse return null;
        if (s.* & pte_v == 0) {
            if (s.* & pte_resv == 0) return null;
            m.populate(s);
        }
        const off: usize = @intCast(va & (page - 1));
        return m.hostPtr(((s.* >> 10) & ((1 << 44) - 1)) << 12)[off..page];
    }

    fn copyOut(m: *Machine, va: u64, bytes: []const u8) bool {
        var done: usize = 0;
        while (done < bytes.len) {
            const p = m.userPage(va + done) orelse return false;
            const n = @min(p.len, bytes.len - done);
            @memcpy(p[0..n], bytes[done..][0..n]);
            done += n;
        }
        return true;
    }

    fn copyIn(m: *Machine, va: u64, out: []u8) bool {
        var done: usize = 0;
        while (done < out.len) {
            const p = m.userPage(va + done) orelse return false;
            const n = @min(p.len, out.len - done);
            @memcpy(out[0..n], p[0..n]);
            done += n;
        }
        return true;
    }

    fn put64(m: *Machine, va: u64, v: u64) void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        _ = m.copyOut(va, &b);
    }
    fn get64(m: *Machine, va: u64) ?u64 {
        var b: [8]u8 = undefined;
        if (!m.copyIn(va, &b)) return null;
        return std.mem.readInt(u64, &b, .little);
    }

    // ---- ELF loading ---------------------------------------------------------------

    pub fn load(m: *Machine, image: []const u8, argv: []const []const u8, envp: []const []const u8) !void {
        const rd = struct {
            fn f(comptime T: type, b: []const u8, off: u64) T {
                return std.mem.readInt(T, b[@intCast(off)..][0..@sizeOf(T)], .little);
            }
        }.f;
        if (image.len < 64 or !std.mem.eql(u8, image[0..4], "\x7fELF") or image[4] != 2 or image[5] != 1) return error.BadElf;
        if (rd(u16, image, 18) != 62) return error.NotX86_64;
        const etype = rd(u16, image, 16);
        const entry0 = rd(u64, image, 24);
        const phoff = rd(u64, image, 32);
        const phentsize = rd(u16, image, 54);
        const phnum = rd(u16, image, 56);
        const bias: u64 = if (etype == 3) exec_bias else 0;

        var phdr_va: u64 = 0;
        var max_end: u64 = 0;
        for (0..phnum) |i| {
            const ph = phoff + i * phentsize;
            const ptype = rd(u32, image, ph);
            const pflags = rd(u32, image, ph + 4);
            const off = rd(u64, image, ph + 8);
            const vaddr = rd(u64, image, ph + 16) + bias;
            const filesz = rd(u64, image, ph + 32);
            const memsz = rd(u64, image, ph + 40);
            if (ptype == 3) return error.DynamicElf;
            if (ptype == 6) phdr_va = vaddr;
            if (ptype != 1 or memsz == 0) continue;
            if (phdr_va == 0 and off <= phoff and phoff < off + filesz) phdr_va = vaddr + (phoff - off);
            const start = vaddr & ~(page - 1);
            const end = (vaddr + memsz + page - 1) & ~(page - 1);
            var prot: u64 = 0;
            if (pflags & 4 != 0) prot |= 1;
            if (pflags & 2 != 0) prot |= 2;
            if (pflags & 1 != 0) prot |= 4;
            var va = start;
            while (va < end) : (va += page) {
                const s = m.slot(va, true).?;
                s.* |= protPte(prot);
                if (s.* & pte_v == 0) s.* |= pte_resv;
            }
            if (!m.copyOut(vaddr, image[@intCast(off)..][0..@intCast(filesz)])) return error.BadElf;
            max_end = @max(max_end, end);
        }
        m.brk_start = max_end;
        m.brk = max_end;

        m.reserve(stack_top - stack_size, stack_top, 3);
        var sp = stack_top - 16;
        if (argv.len + envp.len > max_args) return error.TooManyArgs;
        var ptrs: [max_args]u64 = undefined;
        var n: usize = 0;
        for (argv) |a| {
            sp -= a.len + 1;
            _ = m.copyOut(sp, a);
            _ = m.copyOut(sp + a.len, &.{0});
            ptrs[n] = sp;
            n += 1;
        }
        for (envp) |e| {
            sp -= e.len + 1;
            _ = m.copyOut(sp, e);
            _ = m.copyOut(sp + e.len, &.{0});
            ptrs[n] = sp;
            n += 1;
        }
        sp -= 16;
        const random_va = sp;
        var rnd: [16]u8 = undefined;
        for (&rnd) |*b| b.* = @truncate(m.random());
        _ = m.copyOut(random_va, &rnd);
        // AT_HWCAP: FPU|TSC|CX8|CMOV|SSE|SSE2 (CPUID.1:EDX bits libc looks
        // at); AT_PLATFORM points at "x86_64".
        const hwcap: u64 = (1 << 0) | (1 << 4) | (1 << 8) | (1 << 15) | (1 << 25) | (1 << 26);
        sp -= 9;
        const platform_va = sp;
        _ = m.copyOut(platform_va, "x86_64\x00");
        const auxv = [_][2]u64{
            .{ 3, phdr_va },                           .{ 4, phentsize }, .{ 5, phnum },         .{ 6, page },
            .{ 7, 0 },                                 .{ 8, 0 },         .{ 9, entry0 + bias }, .{ 11, 0 },
            .{ 12, 0 },                                .{ 13, 0 },        .{ 14, 0 },            .{ 15, platform_va },
            .{ 16, hwcap },                            .{ 17, 100 },      .{ 23, 0 },            .{ 25, random_va },
            .{ 31, if (argv.len > 0) ptrs[0] else 0 }, .{ 0, 0 },
        };
        const words = 1 + argv.len + 1 + envp.len + 1 + auxv.len * 2;
        sp = (sp - words * 8) & ~@as(u64, 15);
        var w = sp;
        m.put64(w, argv.len);
        w += 8;
        for (0..argv.len) |i| {
            m.put64(w, ptrs[i]);
            w += 8;
        }
        m.put64(w, 0);
        w += 8;
        for (0..envp.len) |i| {
            m.put64(w, ptrs[argv.len + i]);
            w += 8;
        }
        m.put64(w, 0);
        w += 8;
        for (auxv) |av| {
            m.put64(w, av[0]);
            m.put64(w + 8, av[1]);
            w += 16;
        }
        m.regs.rip = entry0 + bias;
        m.regs.rsp = sp;
    }

    fn pc(m: *const Machine) u64 {
        return m.regs.rip;
    }

    fn random(m: *Machine) u64 {
        m.rng ^= m.rng << 13;
        m.rng ^= m.rng >> 7;
        m.rng ^= m.rng << 17;
        return m.rng;
    }

    // ---- run loop ------------------------------------------------------------------

    fn step(m: *Machine, budget: u64) u32 {
        m.cpu.budget = budget;
        return kw.kw_run(m.cpu, &m.regs);
    }

    fn service(m: *Machine, kind: u32) void {
        const ev = m.cpu.ev;
        switch (kind) {
            kw.KW_EV_BUDGET => m.stats.slices += 1,
            kw.KW_EV_INTERRUPT => {},
            kw.KW_EV_SYSCALL => m.syscall(),
            kw.KW_EV_FAULT => m.fault(ev.addr, ev.access),
            kw.KW_EV_ILLEGAL => m.die(4, "illegal instruction 0x{x} at rip=0x{x}", .{ ev.insn, m.pc() }),
            kw.KW_EV_BREAKPOINT => m.die(5, "breakpoint at rip=0x{x}", .{m.pc()}),
            kw.KW_EV_MISALIGNED => m.die(7, "misaligned access at 0x{x} rip=0x{x}", .{ ev.addr, m.pc() }),
            else => m.die(6, "unknown event {d}", .{kind}),
        }
    }

    fn now(m: *Machine) u64 {
        return if (m.opt.fake_time) m.cpu.icount * 10 else m.host.now_ns();
    }

    pub fn run(m: *Machine) u8 {
        const t0 = m.host.now_ns();
        while (m.exit_code == null) m.service(m.step(m.opt.slice));
        const dt = @max(m.host.now_ns() - t0, 1);
        if (m.opt.stats) {
            const n = m.cpu.icount;
            const mips = @as(f64, @floatFromInt(n)) / @as(f64, @floatFromInt(dt)) * 1000.0;
            m.print("[kwemu] instret={d} time={d}ms MIPS={d:.1} syscalls={d} demand_faults={d} ad_faults={d} spurious={d} frames={d}\n", .{
                n,                     dt / 1_000_000,    mips,                    m.stats.syscalls,
                m.stats.demand_faults, m.stats.ad_faults, m.stats.spurious_faults, m.next_frame / page,
            });
        }
        return m.exit_code.?;
    }

    fn die(m: *Machine, sig: u8, comptime fmt: []const u8, args: anytype) void {
        m.print("[harness] " ++ fmt ++ "\n", args);
        m.exit_code = 128 + sig;
    }

    fn fault(m: *Machine, va: u64, access: u32) void {
        const pg = va & ~(page - 1);
        const s = m.slot(va, false) orelse {
            return m.die(11, "segfault at 0x{x} (no table) rip=0x{x}", .{ va, m.pc() });
        };
        const pte = s.*;
        if (pte & pte_v == 0) {
            if (pte & pte_resv == 0) return m.die(11, "segfault at 0x{x} rip=0x{x}", .{ va, m.pc() });
            m.populate(s);
            return;
        }
        const need: u64 = switch (access) {
            kw.KW_ACCESS_READ => pte_r,
            kw.KW_ACCESS_WRITE => pte_w,
            else => pte_x,
        };
        if (pte & need == 0 or pte & pte_u == 0)
            return m.die(11, "protection fault ({d}) at 0x{x} rip=0x{x}", .{ access, va, m.pc() });
        const new = pte | pte_a | (if (access == kw.KW_ACCESS_WRITE) pte_d else 0);
        if (new == pte) {
            m.stats.spurious_faults += 1;
            if (m.stats.spurious_faults > 1000) return m.die(11, "fault loop at 0x{x}", .{va});
        } else m.stats.ad_faults += 1;
        s.* = new;
        kw.kw_flush_tlb_range(m.cpu, pg, pg + page);
    }

    // ---- syscalls --------------------------------------------------------------------

    fn neg(e: u64) u64 {
        return 0 -% e;
    }

    /// x86-64 Linux: number in rax, arguments in rdi, rsi, rdx, r10, r8, r9,
    /// result in rax.
    fn syscall(m: *Machine) void {
        m.stats.syscalls += 1;
        const nr = m.regs.rax;
        const a = [6]u64{ m.regs.rdi, m.regs.rsi, m.regs.rdx, m.regs.r10, m.regs.r8, m.regs.r9 };
        const ret: u64 = switch (nr) {
            0 => 0, // read: EOF
            1 => m.sysWrite(a[0], a[1], a[2]),
            20 => blk: { // writev
                var total: u64 = 0;
                var i: u64 = 0;
                while (i < a[2]) : (i += 1) {
                    const base = m.get64(a[1] + i * 16) orelse break :blk neg(EFAULT);
                    const len = m.get64(a[1] + i * 16 + 8) orelse break :blk neg(EFAULT);
                    const r = m.sysWrite(a[0], base, len);
                    if (@as(i64, @bitCast(r)) < 0) break :blk r;
                    total += r;
                }
                break :blk total;
            },
            3 => 0, // close
            8 => neg(ESPIPE), // lseek
            9 => m.sysMmap(a[0], a[1], a[2], a[3], a[4]),
            10 => blk: { // mprotect
                m.protect(a[0], a[0] + pageUp(a[1]), a[2]);
                break :blk 0;
            },
            11 => blk: { // munmap
                if (a[0] & (page - 1) != 0) break :blk neg(EINVAL);
                m.unmap(a[0], a[0] + pageUp(a[1]));
                break :blk 0;
            },
            12 => m.sysBrk(a[0]),
            13 => blk: { // rt_sigaction: no handlers, SIG_DFL
                if (a[2] != 0) {
                    const zero: [32]u8 = @splat(0);
                    if (!m.copyOut(a[2], &zero)) break :blk neg(EFAULT);
                }
                break :blk 0;
            },
            14 => 0, // rt_sigprocmask
            157 => blk: { // prctl
                if (a[0] == 15) { // PR_GET_NAME
                    var nm: [16]u8 = @splat(0);
                    @memcpy(nm[0..7], "busybox");
                    if (!m.copyOut(a[1], &nm)) break :blk neg(EFAULT);
                }
                break :blk 0;
            },
            16 => neg(ENOTTY), // ioctl
            24 => 0, // sched_yield
            35 => 0, // nanosleep
            39 => 1, // getpid
            60 => { // exit
                m.exit_code = @truncate(a[0]);
                return;
            },
            62 => { // kill
                m.die(@truncate(a[1]), "killed by signal {d}", .{a[1]});
                return;
            },
            63 => blk: { // uname
                var u: [6 * 65]u8 = @splat(0);
                for ([_][]const u8{ "Linux", "kwemu", "6.12.0", "#1", "x86_64", "localdomain" }, 0..) |str, i| @memcpy(u[i * 65 ..][0..str.len], str);
                break :blk if (m.copyOut(a[0], &u)) 0 else neg(EFAULT);
            },
            79 => blk: { // getcwd: the root of the guest tree
                if (a[0] == 0) break :blk neg(EINVAL);
                if (a[1] < 2) break :blk neg(ERANGE);
                if (!m.copyOut(a[0], "/\x00")) break :blk neg(EFAULT);
                break :blk 2;
            },
            89, 257, 262, 267 => neg(ENOENT), // openat/fstatat/newfstatat/readlinkat
            96 => blk: { // gettimeofday
                const ns = m.now();
                break :blk if (m.copyOut(a[0], std.mem.asBytes(&[2]u64{ @intCast(ns / 1_000_000_000), (ns % 1_000_000_000) / 1000 }))) 0 else neg(EFAULT);
            },
            102, 104, 107, 108 => 0, // get[e]uid/get[e]gid
            110 => 0, // getppid
            131 => 0, // sigaltstack
            158 => blk: { // arch_prctl
                switch (a[0]) {
                    0x1002 => { // ARCH_SET_FS
                        m.regs.fs_base = a[1];
                        break :blk 0;
                    },
                    0x1003 => break :blk m.regs.fs_base, // ARCH_GET_FS
                    else => break :blk neg(EINVAL),
                }
            },
            186 => 1, // gettid
            202 => 0, // futex
            217 => neg(ENOENT), // getdents64
            218 => 1, // set_tid_address
            228 => blk: { // clock_gettime
                const ns = m.now();
                var ts = [2]u64{ ns / 1_000_000_000, ns % 1_000_000_000 };
                break :blk if (m.copyOut(a[1], std.mem.asBytes(&ts))) 0 else neg(EFAULT);
            },
            231 => { // exit_group
                m.exit_code = @truncate(a[0]);
                return;
            },
            273 => 0, // set_robust_list
            302 => neg(ENOSYS), // prlimit64
            318 => blk: { // getrandom
                var i: u64 = 0;
                while (i < a[1]) : (i += 1) {
                    if (!m.copyOut(a[0] + i, &.{@as(u8, @truncate(m.random()))})) break :blk neg(EFAULT);
                }
                break :blk a[1];
            },
            332 => neg(ENOENT), // statx
            334 => neg(ENOSYS), // rseq
            else => blk: {
                if (m.opt.verbose) m.print("[harness] unimplemented syscall {d}\n", .{nr});
                break :blk neg(ENOSYS);
            },
        };
        m.regs.rax = ret;
    }

    fn pageUp(v: u64) u64 {
        return (v + page - 1) & ~(page - 1);
    }

    fn sysWrite(m: *Machine, fd: u64, buf: u64, len: u64) u64 {
        if (fd != 1 and fd != 2) return neg(EBADF);
        var done: u64 = 0;
        while (done < len) {
            const p = m.userPage(buf + done) orelse return if (done > 0) done else neg(EFAULT);
            const n = @min(p.len, len - done);
            m.host.write(@intCast(fd), p[0..@intCast(n)]);
            done += n;
        }
        return len;
    }

    fn sysBrk(m: *Machine, want: u64) u64 {
        if (want < m.brk_start) return m.brk;
        const old_end = pageUp(m.brk);
        const new_end = pageUp(want);
        if (new_end > old_end) m.reserve(old_end, new_end, 3) else if (new_end < old_end) m.unmap(new_end, old_end);
        m.brk = want;
        return m.brk;
    }

    fn sysMmap(m: *Machine, addr: u64, len0: u64, prot: u64, flags: u64, fd: u64) u64 {
        const MAP_FIXED = 0x10;
        const MAP_ANONYMOUS = 0x20;
        if (flags & MAP_ANONYMOUS == 0 or @as(i64, @bitCast(fd)) != -1) return neg(ENOSYS);
        if (len0 == 0) return neg(EINVAL);
        const len = pageUp(len0);
        var va: u64 = undefined;
        if (flags & MAP_FIXED != 0) {
            if (addr & (page - 1) != 0) return neg(EINVAL);
            va = addr;
            m.unmap(va, va + len);
        } else {
            m.mmap_top -= len;
            va = m.mmap_top;
        }
        m.reserve(va, va + len, prot);
        return va;
    }
};
