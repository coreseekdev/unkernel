<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- Copyright (C) 2026 Pooya Parsa <pooya@pi0.io> -->
# Handoff: x86-64 browser support and RISC-V revival

Date: 2026-11-26
Status: phase 0 and the phase 1 reference interpreter are implemented and
tested; phases 2-5 are the next rounds. See "Current state" below before
starting.

## Current state (2026-11-26)

Done in this tree:

- **Phase 0, build-time ISA selection.** `-Dkw-user-isa=aarch64|x86_64`
  (default aarch64) selects the bundle ISA. `include/kw_emu.h` has the
  x86-64 `struct kw_regs` behind `KW_USER_ISA_X86_64` (the generated
  kernel copy is unchanged for AArch64, so `KW_ABI_VERSION` stays 4); the
  x86-64 wasm64 object and harness install to `lib/x86_64/` and
  `x86_64/`; with `-Dkw-user-isa=x86_64` they also take the primary
  `lib/kwemu.o`, `lib/libkwemu.a` and `bin/kwemu-harness.wasm` names (the
  A64 ones stay under `lib/aarch64/` and `bin/aarch64/`). The default A64
  build and all its tests are unchanged.
- **Phase 1, the x86-64 reference interpreter** (`src/x86_64/`):
  variable-length decode (REX, ModRM/SIB, address/operand sizes, RIP
  relative), the integer baseline, string instructions, atomics
  (XCHG/XADD/CMPXCHG/8B/16B), bits/shifts, precise faults, SYSCALL,
  CPUID, RDTSC/RDTSCP, CLFLUSH/MOVNTI as their effects, and SSE2 packed,
  scalar, conversion and comparison operations. XMM state is two 64-bit
  halves, so the wasm64 object imports no functions at all (the A64 test's
  rule: no `__multi3`, `__lshrti3`, `fmin` or `memcpy`).
- **Phase 1 tests.** `src/x86_64/tests.zig` (native unit tests: flags,
  addressing, stack, faults, SSE), a mini-kernel harness
  (`src/x86_64/harness.zig`: Sv48 page tables with A/D demand faults, ELF
  loader, ~25 x86-64 Linux syscalls), native and wasm64 front ends, five
  static x86-64 musl guests (`test/guest/x86_64/`), and
  `test/x86-64-test.mjs`, which runs them native and wasm64 and against
  qemu-x86_64 when it is installed. `zig build test` runs all of it.
- **Phase 2, the x86-64 user-ABI kernel patch** (`0056-wasm-run-x86-64-user-space.patch`,
  selected with `CONFIG_WASM_USER_X86_64` / `KW_USER_ISA=x86_64`): the
  x86-64 syscall table and register ABI, clone order, `arch_prctl`,
  `EM_X86_64`, x86 `rt_sigframe`/`rt_sigreturn`, FS/GS bases, 47-bit
  `TASK_SIZE`, x86 `uname -m`, `/proc/cpuinfo`, seccomp arch and the
  matching ptrace/core-dump gating. `KW_USER_ISA=x86_64
  kernel/build.sh kernel` builds it into `vendor/build/kernel-x86_64/`
  (the AArch64 outputs are untouched). A static x86-64 init runs through
  the real kernel (syscalls, `arch_prctl`, signals, fork/exec/wait, power
  off).
- **Remaining phase 2 work:** Alpine's dynamic loader starts but faults
  (the x86-64 dynamic ELF path and the loader's own emulation still need
  work); Debian's static BusyBox reaches its shell but an applet command
  (`true`, `uname`) still crashes in `ash`'s applet/lookup path. The
  immediate cause is glibc's aligned `__strcmp_sse2`: it returns 0 for
  some unequal pairs (`"abc"`/`"abd"`; `__strcmp_sse2_unaligned` is
  correct), so `ash` reads the token `true` as `then`. The emulator's
  handling of that function's alignment/jump-table path is the remaining
  bug. The harness's `getcwd`, `rt_sigaction` query and `prctl` are
  implemented so the same path can be reproduced under `kwemu-harness-x86`. x86-64 ptrace regsets and core-dump notes are not
  implemented (`HAVE_ARCH_TRACEHOOK` stays off for x86); x87 is a precise
  #UD; the decoded-op tier and wasm JIT are phase 4; riscv64 is phase 3.

The next round continues phase 2 from the x86-64 kernel patch: finish the
dynamic loader/Alpine path, then the static BusyBox shell (the remaining
`ash` applet lookup bug), then threads/futex/signal conformance with
kwtest/abitest. Keep the reference interpreter as the oracle for the
decoded-op tier and reuse the guest corpus.

## 1. Objective and priorities

Add a browser/Node branch that runs unmodified **x86-64 Linux ELF** programs on
unkernel, then revive the removed **riscv64** user-mode CPU support using the
same build-time ISA selection.

The target architecture is:

```text
unmodified x86-64 or riscv64 ELF
  -> ISA reference interpreter
  -> decoded-op tier and wasm JIT
  -> real Linux kernel in arch/wasm, with the matching user ABI
  -> existing kwnet, 9p/vsock, block, display and kwvk devices
```

The browser backend is **x86-64/riscv64 to WebAssembly**, never AsmJit or native
x86-64 code. A future native runtime may reuse the decoder, semantics, kernel
UAPI, rootfs and tests with a native x86-64 backend, but that backend is not part
of the first delivery.

Priorities:

1. **P0:** x86-64 in the browser and Node, with a useful Alpine user space,
   networking and host file systems.
2. **P1:** riscv64 restored to the same functional level by adapting the old
   implementation to the current core.
3. **P2:** x86-64 and riscv64 wasm JIT and kwvk.
4. **Later:** native x86-64 DBT, host-MMU acceleration and persistent AOT.

Do not let the riscv64 restoration block the first x86-64 BusyBox milestone, and
do not start the native backend before the browser branch works.

## 2. Facts to preserve

- `arch/wasm` runs a real Linux kernel. It is not a syscall reimplementation.
- The current guest is AArch64. `src/a64` has a reference interpreter, a
  decoded-op tier and a wasm JIT.
- `src/emu/` contains the mostly ISA-neutral MMU, TLBs, block cache and JIT
  core. `src/emu/jitcore.zig` owns regions, compile policy and host imports.
- User page tables use the Sv48 layout regardless of the user ISA. Keep this
  format for x86-64; guest applications cannot observe the kernel's PTE format.
  Do not introduce x86 PML4 page tables.
- The kwemu contract is `include/kw_emu.h`. The kernel has a generated copy;
  any layout or semantic change requires a coordinated `KW_ABI_VERSION` bump.
- kwnet, 9p, vsock, block and the other device drivers are independent of the
  guest instruction set.
- kwvk is a guest Vulkan ICD over vsock, with a WebGPU renderer and SPIR-V to
  WGSL translation on the host. Its guest ICD must be rebuilt for each ISA, but
  the host protocol and renderer should remain shared.
- The current data-disk policy resets data written by another guest
  architecture. Do not silently share a data disk between incompatible ISAs.

## 3. RISC-V recovery points in git history

Two commits are the useful references. Locate them by subject rather than
copying an old branch wholesale.

### Last tree with the complete RISC-V CPU

Find the commit titled `Remove the riscv64 CPU, reset the kwemu ABI to 2` and
inspect its parent:

```sh
git log --all --oneline --grep='Remove the riscv64 CPU'
git show --stat --summary <removal-commit>
git ls-tree -r --name-only <removal-commit>^ src include guest test
```

The parent contains the old implementation, including:

- `src/emu/exec.zig`: RISC-V reference execution;
- `src/emu/jit.zig`: RISC-V wasm JIT emitter;
- `src/emu/kwemu_test.zig`: instruction and integration tests;
- `src/tests.zig`, `src/tests_wasm.zig` and `test/kwemu-test.mjs`;
- the root-level `guest/` RISC-V test programs, including integer, FP, atomic,
  compressed, AES and other extension tests;
- the old shared CPU and FP code in `src/cpu/core.zig` and `src/cpu/fpu.zig`.

### Last tree before the AArch64 user-ABI switch

Find `Switch the guest CPU to AArch64` and inspect its parent for the RISC-V
kernel UAPI and build integration:

```sh
git log --all --oneline --grep='Switch the guest CPU to AArch64'
git show --name-status <switch-commit>
git ls-tree -r --name-only <switch-commit>^ kernel/patches/linux guest
```

Use the old RISC-V syscall table, ELF definitions, signal frames, ptrace
layouts, feature advertisement and guest build settings as references.

**Do not directly cherry-pick the old CPU or kernel series.** The common core,
Sv48 address space, JIT regions, host contract, kwemu ABI and test harness have
changed. Port semantics onto the current code and prove them with the current
tests.

## 4. Build-time ISA model

Start with compile-time selection, not a runtime multi-ISA plugin system. The
exact option name may be chosen during implementation; `KW_USER_ISA` below is a
proposed name, not an existing interface.

```text
KW_USER_ISA=aarch64  -> current src/a64 + arm64 UAPI + arm64 rootfs
KW_USER_ISA=x86_64   -> new src/x86_64 + x86-64 UAPI + x86-64 rootfs
KW_USER_ISA=riscv64  -> restored RISC-V CPU + RISC-V UAPI + riscv64 rootfs
```

Keep the default build byte-for-byte compatible with the current AArch64
behaviour. Each bundle must advertise exactly the ISA and features its CPU and
kernel implement.

For the first release layout, prefer separate output directories and separate
`distros.json` files per bundle/ISA. Do not immediately redesign the release
schema. Image and data-disk names must not collide across ISAs.

Update `AGENTS.md`, `.agents/kwemu.md`, `.agents/kernel.md`,
`.agents/testing.md` and the relevant guest documentation as the multi-ISA
architecture becomes real.

## 5. Execution plan

### Phase 0: baseline and ISA scaffolding

1. Read `AGENTS.md` and the area guides before editing. Check `git status` and
   preserve unrelated work.
2. Run the existing baseline checks that will be touched, at least
   `zig build test` and `kernel/build.sh kernel`.
3. Add the build-time ISA selection and per-ISA guest output directories.
4. Keep AArch64 as the default and prove there is no behaviour change.

Acceptance: the existing A64 tests and kernel boot pass before any x86-64 or
RISC-V semantic work starts.

### Phase 1: x86-64 reference interpreter

Create `src/x86_64/` with a reference interpreter as the semantic oracle.
Initially support the x86-64 Linux userspace baseline and SSE2. Do not expose
AVX/AVX2 through CPUID until their semantics and tests exist.

Required core behaviour:

- variable-length instruction decode, ModRM/SIB, REX and operand/address-size
  handling;
- general registers, RIP, RFLAGS, SSE state and FS/GS TLS;
- lazy or deferred flags with exact materialisation at every fault, helper,
  interrupt and block exit;
- precise faults: an instruction that faults has no architectural effect except
  for explicitly permitted repeated/string progress;
- `syscall`, `cpuid`, `rdtsc` and the required system instructions;
- stack, the x86-64 red zone, atomics and alignment rules;
- the memory and code-coherence hooks expected by `src/emu/`.

For decoding, evaluate Kernarium's x86-64 target and test corpus first. If its
frontend is too coupled, evaluate Zydis or Blink's trimmed XED. Do not spend the
first milestone writing a complete new decoder unless the existing options are
shown not to fit.

Add `test/guest/x86_64/`, an `x86_64_guests` build list and a
`test/x86-64-test.mjs` runner modelled on the A64 tests. Use qemu-x86-64 and,
where practical, native x86-64 execution as oracles. Reuse Kernarium's
masked-flags, retirement, SMC and exception test ideas.

Acceptance:

- static x86-64 hello and integer/SSE2 test guests match qemu-x86-64 output and
  exit status;
- instruction count, register state, memory and faults match the reference;
- unsupported encodings raise SIGILL rather than failing the host;
- `zig build test` covers both native and wasm64 harnesses.

### Phase 2: x86-64 Linux UAPI and Alpine

Add an x86-64 user-ABI patch at the end of the kernel series. Relevant current
files include:

- `arch/wasm/kernel/traps.c`, `process.c`, `signal.c`, `ptrace.c`, `sys.c`;
- `arch/wasm/kernel/syscall_table.c` and `Makefile.syscalls`;
- `arch/wasm/include/asm/elf.h` and `arch/wasm/include/uapi/asm/`;
- `arch/wasm/kernel/cpu.c` and the kwemu feature/ISA glue in `mm/tlb.c`.

Implement x86-64 syscall numbers and argument registers, `EM_X86_64`, auxv,
`clone`, TLS, signal frames, `rt_sigreturn`, ptrace layouts and the expected
`uname -m`. Initially disable the vDSO/vsyscall and let libc use real syscalls.

Build an x86-64 static BusyBox and then an x86-64 Alpine image. Add per-ISA
pins and guest tool builds instead of reusing the AArch64 binaries.

Acceptance:

1. Static BusyBox runs `uname -a`, file operations and a shell.
2. Dynamic musl programs run.
3. Alpine x86-64 boots under the CLI.
4. `fork/execve/mmap/COW`, threads, futexes and signals pass kwtest/abitest.
5. Networking and a read-only host mount work, with `pnpm test:net`,
   `pnpm test:9p` and the relevant API/distro checks.

Do not start the JIT before this milestone is stable.

### Phase 3: restore riscv64

Recover the old RISC-V reference interpreter and test guests from the removal
commit's parent, then adapt them to the current core and build-time ISA model.

- Start with the old supported `rv64imafdc` surface; RVV and later extensions
  are not part of the first restoration.
- Reuse the current shared softfloat where its RISC-V semantics match.
- Restore RISC-V syscall ABI, ELF, signal frames, auxv/HWCAP, `clone`, TLS,
  atomics and cacheflush behaviour from the pre-AArch64-switch references.
- Restore the old guest tests under a new `test/guest/riscv64/` layout and run
  them against qemu-riscv64.
- Build a riscv64 static BusyBox and Alpine image.
- Adapt the old wasm emitter only after the restored interpreter and UAPI pass.

Acceptance: riscv64 reaches the same Phase 2 shell, process, network and hostFS
checks as x86-64, with no A64 regression.

### Phase 4: wasm JIT for x86-64 and riscv64

For x86-64, add a decoded-op tier and use `src/emu/jitcore.zig` for hot blocks.
Translate frequent integer, branch and memory operations first; complex FP,
SIMD and system operations may call the reference interpreter.

For riscv64, adapt the old `src/emu/jit.zig` emission logic to the current JIT
core, regions, host contract and invalidation rules.

Both ISAs must preserve:

- exact state at faults, traps, hand-backs and interrupts;
- budget and retirement counts;
- code-page and cross-CPU SMC invalidation;
- TLB misses and page-straddling accesses;
- no host imports beyond the supported contract.

Acceptance: output and exit status match the interpreter and qemu, JIT-off and
JIT-on kernel tests pass, and real Alpine work completes with identical
results. Run focused fuzzing for new x86-64 block and flag logic.

### Phase 5: browser integration and kwvk

- Let the page select a bundle matching the requested ISA; do not weaken the
  existing ABI mismatch checks.
- Build `vk/icd` for x86-64 and riscv64 glibc guests while keeping the host
  renderer and protocol shared.
- Validate `vulkaninfo`, compute, headless triangle and then `vkcube` through
  the existing kwvk test drivers.
- Keep external present as the fast path and readback as fallback.
- Use `pnpm dev` for manual browser validation. Do not run `web/test/` unless
  the user explicitly asks for browser tests.

Acceptance: the browser boots the selected x86-64 or riscv64 Alpine image,
uses the network and host mount, and runs the kwvk smoke workloads where the
corresponding guest libraries are available.

## 6. Validation commands

Use the narrow checks for the area changed, not the full release matrix.

```sh
zig build test
kernel/build.sh kernel
node js/cli.ts --append "console=hvc0 rdinit=/usr/bin/kwtest"
node js/cli.ts --append "console=hvc0 rdinit=/usr/bin/kwtest" --no-jit
node js/cli.ts --append "console=hvc0 rdinit=/usr/bin/abitest"
pnpm test:net
pnpm test:9p
pnpm test:api
pnpm test:distro
pnpm test:vk
vk/build.sh
node test/vk/relay.mjs -- vulkaninfo --summary
node test/vk/unkernel-check.mjs
```

Also run guest-image builds into temporary output roots when changing image
logic, as documented in `guest/README.md` and `.agents/testing.md`.

For JIT control-flow changes, add the relevant fuzz run. For SMP changes, build
and test the SMP kernel and run `zig build test -Dkwemu-atomics=true`.

The full matrix is only for a release or when explicitly requested. After every
build/test run, inspect `git status` and remove generated logs or test artifacts
that are not part of the change.

## 7. Project constraints

- Follow the kernel patch workflow: durable changes belong in
  `kernel/patches/linux/`; do not treat `vendor/` as source.
- Bump `KW_ABI_VERSION` in both header copies for every layout or semantic ABI
  change and check the generated copies stay synchronized.
- New files carry the project's SPDX and copyright header.
- Do not use `switch_root` in guest init and never clear the persistent
  `kwdisk:kwdata-v1` IndexedDB store.
- Keep unsupported instructions and features unadvertised. A guest illegal
  instruction is a correctness issue, not a reason to hide the workload.
- Do not run browser tests unless asked, do not run the full matrix except for a
  release or explicit request, and do not commit or push unless the user asks.
- If a change contradicts a project document, update that document in the same
  change.

## 8. Definition of done

The handoff is complete when all of the following are demonstrated:

- The current AArch64 build and tests still pass.
- x86-64 Alpine boots in Node and manually in the browser, with dynamic musl,
  processes, threads, signals, network and hostFS.
- riscv64 Alpine reaches the same level using the restored CPU and UAPI.
- x86-64 and riscv64 JIT results match their interpreters and qemu; JIT-off is
  available as a fallback.
- The corresponding kwvk guest ICD loads, and the smoke workloads run.
- Kernel/ABI, guest, SDK and agent documentation matches the actual multi-ISA
  behaviour.
- No unrelated files, generated artifacts or user data are changed.

A native x86-64 backend is a separate follow-up, not a reason to delay the
browser branch.

## 9. External references

- Kernarium: native User-mode Linux, x86-64 frontend, software MMU, instruction
  corpus and JIT semantics. Use it primarily as the x86-64 semantic and testing
  reference.
- Blink: compact x86-64 user-mode JIT, linear-memory and SMC techniques. Its
  syscall layer is not a replacement for unkernel's real Linux kernel.
- container2wasm and qemu-wasm: proof that x86-64 full-system emulation works in
  browsers, but they emulate the kernel too and are not the target architecture.
