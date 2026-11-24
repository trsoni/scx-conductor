#!/bin/bash
# PID 1 inside the QEMU guest. Mounts pseudo-filesystems and the shared repo,
# runs the guest test suite, prints a machine-readable verdict and powers off.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mkdir -p /dev/pts /tmp /run
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
mount -t bpf bpf /sys/fs/bpf
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null

if ! mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 repo /repo; then
  echo "CONDUCTOR-GUEST-RESULT: FAIL (could not mount 9p repo share)"
  poweroff -f
fi

echo "CONDUCTOR-GUEST-BOOT: $(uname -srm)"
cd /repo || poweroff -f
# CONDUCTOR_GUEST_ARGS comes from the kernel command line (conductor.args=...)
ARGS=$(sed -n 's/.*conductor\.args=\([^ ]*\).*/\1/p' /proc/cmdline | tr ',' ' ')
bash tests/guest/run_all.sh $ARGS
rc=$?
if [ $rc -eq 0 ]; then
  echo "CONDUCTOR-GUEST-RESULT: PASS"
else
  echo "CONDUCTOR-GUEST-RESULT: FAIL (rc=$rc)"
fi
sync
poweroff -f
