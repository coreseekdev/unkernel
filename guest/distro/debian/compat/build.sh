#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
# Build a Debian trixie amd64 image (debian:trixie-slim already has bash,
# perl-base, coreutils, tar/gzip and the loader) that runs the x86-64
# compatibility suite (kw-init in this directory) instead of a desktop, and an erofs
# image labelled kwroot for `js/cli.ts --distro`.
#
#   guest/distro/debian/compat/build.sh [ROOTFS_DIR] [IMAGE]
#
# The suite covers the shell, coreutils, tar/gzip, perl (arithmetic,
# strings, sort, FP, signals, fork, pipes, regex, memory) and the static
# musl guests from test/guest/x86_64 (built by `zig build`, installed at
# /opt/compat). Every line is deterministic, so the same rootfs can run in
# a native chroot and under kwemu and the logs diffed; see README.md.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
out="${1:-/tmp/kw-compat-root}"
img="${2:-/tmp/kw-compat.erofs}"
container=kw-compat-build

command -v docker >/dev/null || { echo "compat: docker is required" >&2; exit 1; }
erofs="$root/vendor/toolchain/erofs-utils/bin/mkfs.erofs"
[ -x "$erofs" ] || erofs="$(command -v mkfs.erofs || true)"
[ -n "$erofs" ] || { echo "compat: mkfs.erofs not found (build the toolchain)" >&2; exit 1; }

for g in inttest fptest sse2test strtest; do
	[ -x "$root/zig-out/guest/x86_64/$g.elf" ] || {
		echo "compat: zig-out/guest/x86_64/$g.elf is missing; run zig build first" >&2
		exit 1
	}
done

# debian:trixie-slim already carries bash, perl (perl-base), coreutils,
# find/diff, tar/gzip and the loader, which is everything the suite uses.
docker rm -f "$container" >/dev/null 2>&1 || true
docker run --name "$container" debian:trixie-slim true

rm -rf "$out"
mkdir -p "$out"
docker export "$container" | sudo -n tar -xpf - -C "$out"
docker rm -f "$container" >/dev/null

# Docker export leaves /dev empty; the suite and perl need the usual
# character devices, and a native chroot needs them too (a container whose
# device cgroup rejects mknod'ed nodes can bind-mount the host ones).
sudo -n mkdir -p "$out/dev" "$out/opt/compat"
for spec in "null 1 3" "zero 1 5" "random 1 8" "urandom 1 9"; do
	set -- $spec
	sudo -n mknod -m 666 "$out/dev/$1" c "$2" "$3" 2>/dev/null || true
done
for g in inttest fptest sse2test strtest; do
	sudo -n cp "$root/zig-out/guest/x86_64/$g.elf" "$out/opt/compat/"
done
sudo -n cp "$here/kw-init" "$out/usr/local/sbin/kw-init"
sudo -n chmod 755 "$out/usr/local/sbin/kw-init" "$out/opt/compat/"*.elf
sudo -n chown -R root:root "$out"
sudo -n "$erofs" -L kwroot "$img" "$out"
sudo -n chmod 644 "$img"

echo "compat: $out"
echo "compat: $img ($(du -h "$img" | cut -f1))"
echo "compat: boot with --distro $img (logs COMPAT-START .. COMPAT-DONE)"
