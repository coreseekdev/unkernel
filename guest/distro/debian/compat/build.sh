#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
# Build a Debian trixie amd64 image that runs the x86-64 compatibility
# suite (kw-init in this directory) instead of a desktop, and an erofs
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

docker rm -f "$container" >/dev/null 2>&1 || true
docker run --name "$container" debian:trixie-slim bash -euxc '
	apt-get update
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		perl gawk findutils diffutils
'

rm -rf "$out"
mkdir -p "$out"
docker export "$container" | sudo -n tar -xpf - -C "$out"
docker rm -f "$container" >/dev/null

sudo -n mkdir -p "$out/opt/compat"
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
