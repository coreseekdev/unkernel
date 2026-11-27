#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build the Debian trixie amd64 + Firefox rootfs used for the x86-64
# headless-Firefox test, and a bootable erofs image labelled kwroot.
#
#   guest/distro/debian/firefox/build.sh [ROOTFS_DIR] [IMAGE]
#
# Defaults: /tmp/kw-firefox-root and /tmp/kw-firefox.erofs. The rootfs is
# made by Docker (debian:trixie-slim, firefox-esr, fonts-dejavu-core) and a
# warm headless profile at /opt/ffp, then kw-init (this directory) is
# installed over the image's init. The image boots Firefox headless and
# prints the screenshot as base64 between PNGSTART and PNGEND; it is a test
# asset, not the normal Debian desktop image.
#
# The kernel bundle is built separately:
#   KW_USER_ISA=x86_64 KW_BUILD=/tmp/kwbuild kernel/build.sh kernel
#   KW_USER_ISA=x86_64 KW_BUILD=/tmp/kwbuild KW_BASE_OUT=/tmp/kwout \
#     KW_VK=0 KW_RELEASE=1 kernel/build.sh base
#   node js/cli.ts --kernel /tmp/kwout/unkernel.wasm \
#     --distro /tmp/kw-firefox.erofs --mem 2048 --timeout 400
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
out="${1:-/tmp/kw-firefox-root}"
img="${2:-/tmp/kw-firefox.erofs}"
container=kw-firefox-build

command -v docker >/dev/null || { echo "firefox: docker is required" >&2; exit 1; }
erofs="$root/vendor/toolchain/erofs-utils/bin/mkfs.erofs"
[ -x "$erofs" ] || erofs="$(command -v mkfs.erofs || true)"
[ -n "$erofs" ] || { echo "firefox: mkfs.erofs not found (build the toolchain)" >&2; exit 1; }

docker rm -f "$container" >/dev/null 2>&1 || true
docker run --name "$container" debian:trixie-slim bash -euxc '
	apt-get update
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		firefox-esr fonts-dejavu-core ca-certificates
	mkdir -p /opt/ffp
	export HOME=/root MOZ_CRASHREPORTER_DISABLE=1 MOZ_CRASHREPORTER=0
	timeout 180 firefox-esr --headless --no-remote --profile /opt/ffp \
		--screenshot /tmp/profile.png about:blank
	rm -f /opt/ffp/lock /opt/ffp/.parentlock
'

rm -rf "$out"
mkdir -p "$out"
docker export "$container" | sudo -n tar -xpf - -C "$out"
docker rm -f "$container" >/dev/null
sudo -n cp "$here/kw-init" "$out/usr/local/sbin/kw-init"
sudo -n chmod 755 "$out/usr/local/sbin/kw-init"
sudo -n chown -R root:root "$out"
sudo -n "$erofs" -L kwroot "$img" "$out"
sudo -n chmod 644 "$img"

echo "firefox: $out"
echo "firefox: $img ($(du -h "$img" | cut -f1))"
echo "firefox: boot with --distro $img; the init prints the screenshot as base64"
