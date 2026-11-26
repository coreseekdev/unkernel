# kernel/

Linux 7.3 built as one wasm module (`arch/wasm`, grown from Joel Severin's
linux-wasm port), with the kwemu aarch64 CPU (`src/`, contract in
`include/kw_emu.h`) linked in to run unmodified aarch64 user space, and the
bundle that carries it with the base initramfs (the guest side is in the
top-level `guest/`, its README.md). The overview is the top-level README.md; the
reference for changing anything here is in `.agents/` (start at
[.agents/kernel.md](../.agents/kernel.md)).

| Path | What |
| --- | --- |
| `build.sh` | every kernel-side build step (below) |
| `patches/linux/` | the kernel series on Linux v7.3.4 (`7595a62d45e`), applied as branch `kw-arm64-user` in `vendor/src/linux-wasm-kernel` (.agents/kernel.md, Tree and patch workflow) |
| `patches/llvm/` | the wasm-ld patches (.agents/toolchain.md) |
| `tools/` | `bundle.mjs` (the bundle), `kwdiff.mjs` (the UP-to-SMP patch), `kwsparse.mjs`, `fake-llvm/` (Kbuild's toolchain wrapper), `env.sh` (host tools and the build helpers) |

## Build

`./setup.sh` (repository root) checks the prerequisites and runs `zig
build` and `kernel/build.sh all`. Steps, each on its own:

| Step | Output |
| --- | --- |
| `toolchain` | `wasm-ld` from LLVM 22.1.8 with `patches/llvm/` (clang 22 comes from the system; .agents/toolchain.md) |
| `binaryen` | Binaryen 133 in `vendor/toolchain/binaryen` (`lower` fetches it if needed) |
| `kernel` | the UP kernel `vendor/build/kernel/vmlinux` (wasm64) with kwemu from `zig-out/lib/libkwemu.a`, then `lower` and the bundle; the quick loop |
| `smp` | the SMP kernel in `vendor/build/kernel-smp`, then the bundle with its patch |
| `lower` | `vmlinux32.wasm`, the 32-bit-memory build every host runs |
| `datadisk` | `vendor/build/disk/kwdata.kwsparse.gz`, the data disk template |
| `base` | the base initramfs `vendor/build/initramfs/base.cpio` and `base-test.cpio` (`guest/build.sh base`) and the bundle `vendor/build/bundle/unkernel.wasm` (kernel, base initramfs, command line, template, SMP patch), also copied to `web/kernel/`; `KW_BASE_OUT=dir` writes all three to dir and copies nothing |
| `distro [NAME...]` | the distro images `vendor/build/distro/NAME.{erofs,ext4}`, their ids `NAME.id` and the index `distros.json` (`guest/build.sh distro`) |
| `all` | all of the above |
| `stats` | `vendor/build/bundle/unkernel-stats.wasm`, kwemu with exit counters (`--stats`; not in `all`) |

`kernel`, `smp`, `lower` and `datadisk` refresh the bundle when
`base.cpio` exists, and `distros.json` (its ABI and base id) when there are
images. `KSRC`, `KOUT`, `KOUT_SMP` and `KW_BUILD` build another tree or into
another output root; the header of `build.sh` lists every variable.
Downloads are pinned (`build.sh`, `tools/env.sh`, `guest/**/pins.sh`).

## Run

```sh
node js/cli.ts                                                    # Alpine on the bundle; Ctrl-] quits; --help lists options
node js/cli.ts --distro debian                                    # Debian; --distro none: the base shell
node js/cli.ts --append "console=hvc0 rdinit=/usr/bin/kwtest"     # kernel tests as /init (no distro)
node js/cli.ts --cpus 2 --append "console=hvc0 rdinit=/usr/bin/kwtest"   # the same on the SMP kernel
node js/cli.ts --kernel vendor/build/kernel/vmlinux --append "console=hvc0 rdinit=/usr/bin/kwtest"   # the wasm64 build (with base.cpio)
node js/cli.ts --data /tmp/kwdata.img                             # with the data disk at /data (changes persist)
```

Which tests to run for a change: .agents/testing.md.

## Guest ISA

The default kernel runs AArch64 user space. `KW_USER_ISA=x86_64
kernel/build.sh kernel` builds the x86-64 user ABI instead
(`CONFIG_WASM_USER_X86_64`, `arch/wasm/configs/kw_x86.config`) into
`vendor/build/kernel-x86_64/`; the AArch64 outputs are not touched. The
x86-64 patch is `kernel/patches/linux/0056-wasm-run-x86-64-user-space.patch`
and the emulator side is `src/x86_64/` (HANDOFF.md).
