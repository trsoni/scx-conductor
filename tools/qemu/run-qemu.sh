#!/usr/bin/env bash
# Boot the guest and run the test suite.
#   tools/qemu/run-qemu.sh <x86_64|arm64> [-- extra guest args, comma separated e.g. skip-ab,skip-e2e]
# Prerequisite artifacts (from build-kernel.sh and make-rootfs.sh):
#   build/kernels/<arch>/{bzImage|Image}   build/rootfs/<arch>/rootfs.ext4
# Exit status: 0 = guest printed CONDUCTOR-GUEST-RESULT: PASS, 1 = FAIL / timeout.
set -uo pipefail

ARCH=${1:?x86_64 | arm64}
GUEST_ARGS=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
K="$REPO/build/kernels/$ARCH"
R="$REPO/build/rootfs/$ARCH/rootfs.ext4"
LOG="$REPO/build/qemu-$ARCH.log"
SMP=${SMP:-4}
MEM=${MEM:-4G}
TIMEOUT=${TIMEOUT:-3600}     # arm64 under TCG on an x86 host is slow: compile happens inside the guest

[ -f "$R" ] || { echo "missing $R (run make-rootfs.sh)"; exit 1; }
HOST=$(uname -m)
APPEND="root=/dev/vda rw init=/sbin/conductor-init panic=-1 loglevel=4 conductor.args=$GUEST_ARGS"

case "$ARCH" in
  x86_64)
    KERNEL="$K/bzImage"
    ACCEL=(); CPU=max
    if [ "$HOST" = x86_64 ] && [ -w /dev/kvm ]; then ACCEL=(-enable-kvm); CPU=host; fi
    CMD=(qemu-system-x86_64 -machine q35 -cpu "$CPU" "${ACCEL[@]}"
         -append "console=ttyS0 $APPEND")
    ;;
  arm64)
    KERNEL="$K/Image"
    ACCEL=(); CPU=max
    if [ "$HOST" = aarch64 ] && [ -w /dev/kvm ]; then ACCEL=(-enable-kvm); CPU=host; fi
    CMD=(qemu-system-aarch64 -machine virt,gic-version=max -cpu "$CPU" "${ACCEL[@]}"
         -append "console=ttyAMA0 $APPEND")
    ;;
  *) echo "bad arch"; exit 2 ;;
esac
[ -f "$KERNEL" ] || { echo "missing $KERNEL (run build-kernel.sh)"; exit 1; }

mkdir -p "$REPO/build"
rm -f "$REPO/build/guest-result.json"
timeout "$TIMEOUT" "${CMD[@]}" \
  -smp "$SMP" -m "$MEM" -nographic -no-reboot \
  -kernel "$KERNEL" \
  -drive file="$R",format=raw,if=none,id=hd0 -device virtio-blk-pci,drive=hd0 \
  -fsdev local,id=repo,path="$REPO",security_model=none,multidevs=remap \
  -device virtio-9p-pci,fsdev=repo,mount_tag=repo \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  </dev/null 2>&1 | tee "$LOG"

if grep -q '^CONDUCTOR-GUEST-RESULT: PASS' "$LOG"; then
  echo "== $ARCH: PASS (log: $LOG)"; exit 0
fi
echo "== $ARCH: FAIL or timed out (log: $LOG)"; exit 1
