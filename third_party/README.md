# third_party/

`scx-include/` is populated by `tools/fetch-scx-include.sh <linux-src>` (also run by `tools/qemu/build-kernel.sh`).
It holds `tools/sched_ext/include/*` from the kernel tree you boot and is git-ignored on purpose: the headers
must match the kernel, so they are never vendored here.
