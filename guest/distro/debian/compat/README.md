# Debian x86-64 compatibility suite

`build.sh` builds a Debian trixie amd64 rootfs (Docker, `debian:trixie-slim`,
which already carries bash, perl-base, coreutils, tar/gzip and the loader),
installs the suite in `kw-init` as the image's init, copies the
static musl guests from `zig-out/guest/x86_64` into `/opt/compat`, and makes
an erofs image labelled `kwroot`. The suite covers the shell, coreutils,
tar/gzip, perl (arithmetic, strings, sort, FP, signals, fork, pipes, regex,
memory) and the four static guests, and prints only deterministic lines
between `COMPAT-START` and `COMPAT-DONE`, so the same rootfs can be run in a
native chroot and under kwemu and the logs diffed.

```sh
zig build
guest/distro/debian/compat/build.sh /tmp/kw-compat-root /tmp/kw-compat.erofs

# native oracle (the same rootfs)
sudo env -i KW_NOPOWER=1 PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  chroot /tmp/kw-compat-root /bin/sh /usr/local/sbin/kw-init > /tmp/compat-native.log

# x86-64 kernel bundle and the emulator
KW_USER_ISA=x86_64 KW_BUILD=/tmp/kwbuild kernel/build.sh kernel
KW_USER_ISA=x86_64 KW_BUILD=/tmp/kwbuild KW_BASE_OUT=/tmp/kwout \
  KW_VK=0 KW_RELEASE=1 kernel/build.sh base
node js/cli.ts --kernel /tmp/kwout/unkernel.wasm \
  --distro /tmp/kw-compat.erofs --mem 1536 --timeout 600 > /tmp/compat-guest.log

# compare (the guest console has CRLF endings and kernel lines interleaved)
sed -n '/^COMPAT-START$/,/^COMPAT-DONE$/p' /tmp/compat-native.log > /tmp/n.cmp
tr -d '\r' < /tmp/compat-guest.log |
  sed -n '/^COMPAT-START$/,/^COMPAT-DONE$/p' | grep -v '^\[' > /tmp/g.cmp
diff -u /tmp/n.cmp /tmp/g.cmp
```

If the native chroot runs in a container whose device cgroup rejects nodes
created by `mknod` (`cannot create /dev/null: Permission denied`), bind the
host devices into the rootfs before the oracle run:

```sh
for d in null zero random urandom; do
  sudo mount --bind /dev/$d /tmp/kw-compat-root/dev/$d
done
# ... run the oracle ...
for d in null zero random urandom; do
  sudo umount /tmp/kw-compat-root/dev/$d
done
```

The guest needs no network. `kw-init` powers off through the base
initramfs' busybox unless `KW_NOPOWER` is set (the native chroot sets it).
