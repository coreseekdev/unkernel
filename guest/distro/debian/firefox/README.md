# Debian + Firefox headless test image

`build.sh` builds a Debian trixie amd64 rootfs with `firefox-esr` and a
warm headless profile (`/opt/ffp`), makes an erofs image labelled `kwroot`,
and installs the test init in `kw-init` at `/usr/local/sbin/kw-init`. The
init boots Firefox with `--headless --screenshot`, prints the PNG as
base64 between `PNGSTART` and `PNGEND`, and powers off. It is the
reproducible source of the x86-64 Firefox screenshot used in HANDOFF, not
the normal Debian desktop image (which boots the login shell/kwtty).

```sh
# Docker (debian:trixie-slim + firefox-esr + fonts) -> rootfs and erofs
guest/distro/debian/firefox/build.sh /tmp/kw-firefox-root /tmp/kw-firefox.erofs

# x86-64 kernel bundle
KW_USER_ISA=x86_64 KW_BUILD=/tmp/kwbuild kernel/build.sh kernel
KW_USER_ISA=x86_64 KW_BUILD=/tmp/kwbuild KW_BASE_OUT=/tmp/kwout \
  KW_VK=0 KW_RELEASE=1 kernel/build.sh base

# boot and print the screenshot
node js/cli.ts --kernel /tmp/kwout/unkernel.wasm \
  --distro /tmp/kw-firefox.erofs --mem 2048 --timeout 400
```

The image needs Docker and network on the build host; the boot needs no
network. The normal `guest/distro/debian/build.sh` is the pinned distro
build; this variant is intentionally host-Docker based so it does not make
the guest interpreter build a Firefox package closure.
