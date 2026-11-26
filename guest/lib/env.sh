# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
# Sourced by the guest/ build scripts (bash). Sources kernel/tools/env.sh
# (root, vendor, build, zig, fetch_verified, need_zig, ...) and sets:
#   guest       this directory's parent (guest/)
#   dl          vendor/downloads
#   base_out    the base initramfs's outputs (base.cpio, base-test.cpio and
#               their staging trees): $KW_BASE_OUT if set, else
#               $build/initramfs
#   base_bundle the distroless bundle the base build ends in (kernel/build.sh
#               base): $KW_BASE_OUT/unkernel.wasm if set, else
#               $build/bundle/unkernel.wasm
#   cc_guest    zig cc for the guest programs: static aarch64 musl for the
#               generic CPU (ARMv8.0, what kwemu runs), with no build
#               directory in the output
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/kernel/tools/env.sh"
guest="$root/guest"
dl="$vendor/downloads"
if [ -n "${KW_BASE_OUT:-}" ]; then
	base_out="$(realpath -m "$KW_BASE_OUT")"
	base_bundle="$base_out/unkernel.wasm"
else
	base_out="$build/initramfs"
	base_bundle="$build/bundle/unkernel.wasm"
fi
# The guest ISA is KW_USER_ISA (the kernel build's switch): aarch64 is the
# default and x86_64 selects the same tools and static libc for x86-64.
guest_isa="${KW_USER_ISA:-aarch64}"
case "$guest_isa" in
	aarch64 | x86_64) ;;
	*) echo "KW_USER_ISA must be aarch64 or x86_64" >&2; exit 2 ;;
esac
if [ "$guest_isa" = x86_64 ]; then guest_cpu=x86_64; else guest_cpu=generic; fi
cc_guest=("$zig" cc -target "$guest_isa-linux-musl" -mcpu="$guest_cpu" -static -O2 -s "-ffile-prefix-map=$root/=")
