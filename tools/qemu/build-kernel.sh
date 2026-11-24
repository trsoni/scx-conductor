#!/usr/bin/env bash
# Build a sched_ext-enabled kernel for QEMU.
#   tools/qemu/build-kernel.sh <x86_64|arm64> <path-to-linux-source> [out-dir]
# Produces <out>/<arch>/{bzImage|Image} and <out>/<arch>/vmlinux (for BTF/debug).
# Also copies tools/sched_ext/include into third_party/scx-include so the BPF
# headers match this exact kernel.
set -euo pipefail

ARCH=${1:?arch: x86_64 | arm64}
SRC=${2:?path to a Linux source tree with sched_ext (tools/sched_ext must exist)}
OUT=${3:-"$(cd "$(dirname "$0")/../.." && pwd)/build/kernels"}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

[ -d "$SRC/tools/sched_ext/include/scx" ] || { echo "error: $SRC has no tools/sched_ext (kernel too old?)"; exit 1; }
command -v pahole >/dev/null || { echo "error: pahole (dwarves) is required for CONFIG_DEBUG_INFO_BTF"; exit 1; }

case "$ARCH" in
  x86_64) KARCH=x86_64; IMG=arch/x86/boot/bzImage; CROSS="" ;;
  arm64)  KARCH=arm64;  IMG=arch/arm64/boot/Image
          if [ "$(uname -m)" = aarch64 ]; then CROSS=""; else CROSS="aarch64-linux-gnu-"; fi ;;
  *) echo "unknown arch $ARCH"; exit 2 ;;
esac
if [ -n "$CROSS" ]; then command -v "${CROSS}gcc" >/dev/null || { echo "error: need ${CROSS}gcc (apt install gcc-aarch64-linux-gnu)"; exit 1; }; fi

BUILD="$OUT/$ARCH/obj"
mkdir -p "$BUILD"
MAKE=(make -C "$SRC" O="$BUILD" ARCH="$KARCH" ${CROSS:+CROSS_COMPILE=$CROSS} -j"$(nproc)")

"${MAKE[@]}" defconfig
( cd "$SRC" && ./scripts/kconfig/merge_config.sh -m -O "$BUILD" "$BUILD/.config" "$HERE/kernel.config" )
"${MAKE[@]}" olddefconfig

# Fail early if the options that matter did not survive dependency resolution.
for opt in SCHED_CLASS_EXT BPF_SYSCALL DEBUG_INFO_BTF PSI NET_9P_VIRTIO; do
  grep -q "^CONFIG_${opt}=y" "$BUILD/.config" || { echo "error: CONFIG_${opt} not enabled after olddefconfig"; exit 1; }
done

"${MAKE[@]}"
cp "$BUILD/$IMG" "$OUT/$ARCH/"
cp "$BUILD/vmlinux" "$OUT/$ARCH/vmlinux"

# BPF headers from the same tree
"$REPO/tools/fetch-scx-include.sh" "$SRC"
echo "kernel: $OUT/$ARCH/$(basename "$IMG")"
