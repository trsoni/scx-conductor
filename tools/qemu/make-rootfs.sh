#!/usr/bin/env bash
# Build a Debian trixie rootfs image (ext4) for the QEMU guest.
#   sudo tools/qemu/make-rootfs.sh <x86_64|arm64> [out-dir]
# Needs: debootstrap, e2fsprogs; for arm64 on an x86 host also qemu-user-static + binfmt.
# The guest builds scx-conductor itself (clang, libbpf, bpftool are inside), so the
# loader is always the right architecture. The repo is NOT baked in: it is shared
# over virtio-9p at /repo (see run-qemu.sh), so edits on the host show up in the guest.
set -euo pipefail

ARCH=${1:?x86_64 | arm64}
OUT=${2:-"$(cd "$(dirname "$0")/../.." && pwd)/build/rootfs"}
case "$ARCH" in x86_64) DARCH=amd64 ;; arm64) DARCH=arm64 ;; *) echo "bad arch"; exit 2 ;; esac
[ "$(id -u)" = 0 ] || { echo "run as root (debootstrap needs it)"; exit 1; }
command -v debootstrap >/dev/null || { echo "apt install debootstrap"; exit 1; }
if [ "$DARCH" = arm64 ] && [ "$(uname -m)" != aarch64 ]; then
  command -v qemu-aarch64-static >/dev/null || { echo "apt install qemu-user-static binfmt-support"; exit 1; }
fi

PKGS=clang,llvm,lld,make,gcc,libc6-dev,libbpf-dev,libelf-dev,zlib1g-dev,libzstd-dev,bpftool,python3,openssl,procps,iproute2,stress-ng,kmod,pciutils,tpm2-tools,less
mkdir -p "$OUT/$ARCH"
ROOT="$OUT/$ARCH/tree"
rm -rf "$ROOT"
debootstrap --arch="$DARCH" --variant=minbase --include="$PKGS" trixie "$ROOT" http://deb.debian.org/debian

install -m 0755 "$(dirname "$0")/guest-init.sh" "$ROOT/sbin/conductor-init"
mkdir -p "$ROOT/repo" "$ROOT/sys/fs/bpf" "$ROOT/sys/kernel/debug"
echo conductor-qemu > "$ROOT/etc/hostname"
echo "root::0:0:root:/root:/bin/bash" > "$ROOT/etc/passwd"

IMG="$OUT/$ARCH/rootfs.ext4"
rm -f "$IMG"
truncate -s 6G "$IMG"
mkfs.ext4 -q -F -d "$ROOT" "$IMG"
echo "rootfs: $IMG"
