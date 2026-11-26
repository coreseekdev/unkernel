# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
# Pinned inputs of the Debian image for an x86-64 guest ISA
# (KW_USER_ISA=x86_64), overriding pins.sh. The root file system is the
# official debian:trixie-slim amd64 image of the same debuerreotype epoch
# as the arm64 pin (20261123; 13.8), and the baked lists are trixie's
# main/binary-amd64 (and Contents-amd64) from the snapshot the tarball's
# debian.sources names. There is no x86-64 wlandr in this pin set yet.
DEBIAN_VERSION=13.8
DEBIAN_EPOCH=20261123
DEBIAN_ARCH=amd64
DEBIAN_ARTIFACTS_COMMIT=865e49bb5782df1fa4b4c4d8d474e3583b67bfda
DEBIAN_TARBALL_NAME="debian-trixie-slim-$DEBIAN_EPOCH-amd64.tar.gz"
DEBIAN_URL="https://raw.githubusercontent.com/debuerreotype/docker-debian-artifacts/$DEBIAN_ARTIFACTS_COMMIT/trixie/slim/oci/blobs/rootfs.tar.gz"
DEBIAN_SHA256=40748add9f4f6f944f334cbfc286590d6e93f60fb06f6ee7ffa1b894080ad861
DEBIAN_LISTS_SNAPSHOT="${DEBIAN_EPOCH}T000000Z"
DEBIAN_LISTS="
debian          trixie          InRelease                     bfacad4ca61899ce20d4a0d439f29339f66541561b67506364efb88e27dee870 1795254090
debian          trixie          main/binary-amd64/Packages.xz be3d7d96a040eda0505c1808cccc67f183bbc05dff0842c50f88e6c396557412 1795253916
debian          trixie-updates  InRelease                     076b8950d0c42ed99c37e0c689487eab8d4fc918bbe17a92995568ad2d357469 1795379789
debian          trixie-updates  main/binary-amd64/Packages.xz eea860c5dea11680e64299adb2736c2367c4235763a66f2b70ca61ce1b51978a 1793889047
debian-security trixie-security InRelease                     6594343424d41a49919534585b630ece98cdacf3ce0eb9a9000b77a215401399 1795377866
debian-security trixie-security main/binary-amd64/Packages.xz 9b641b3080d3f78923cac1b24512399af75d743997174934d733f5cf9b6fabda 1795377786
"
DEBIAN_CONTENTS="
main/Contents-amd64.gz 3fb7f46705dee87d0721df64b7bc461a862edb4933c358973d55954e1fb0db48
main/Contents-all.gz   6e22294506feb918d3cd53c3296512911c2fb7ce6bb695d8ee6020a452b39094
"
WLANDR_VERSION=""
WLANDR_TARBALL=""
WLANDR_URL=""
WLANDR_SHA256=""
