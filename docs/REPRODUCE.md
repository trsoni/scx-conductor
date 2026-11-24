# Reproducing: build, QEMU (x86_64 and arm64), bare metal

> **Status:** the Python parts are tested (211 unit tests). The BPF template, the loader and the generation pipeline
> were compiled and run up to the kernel verifier on x86_64 in the authoring sandbox, which has no sched_ext kernel.
> The kernel, rootfs and QEMU steps below are written from the kernel.org sched_ext documentation and standard tooling
> and **have never been executed**. Expect a small number of first-run issues and record them in `memory/test-log.md`.
> To try on-device generation on a laptop, start with `docs/LAPTOP.md`.

## 0. Host prerequisites

Debian / Ubuntu host:

```bash
sudo apt install build-essential flex bison bc libssl-dev libelf-dev dwarves pahole \
     qemu-system-x86 qemu-system-arm debootstrap e2fsprogs python3 openssl git
# arm64 target on an x86 host additionally:
sudo apt install gcc-aarch64-linux-gnu qemu-user-static binfmt-support
```

You also need a **Linux source tree that contains sched_ext** (`tools/sched_ext/` present). Use a current stable
release or `torvalds/linux`. The BPF headers are taken from that same tree so kfunc names match the kernel you boot:

```bash
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git ~/linux
```

## 1. Kernel (once per architecture)

```bash
tools/qemu/build-kernel.sh x86_64 ~/linux
tools/qemu/build-kernel.sh arm64  ~/linux       # cross-compiles on x86
```

This merges `tools/qemu/kernel.config` into `defconfig`, aborts if `CONFIG_SCHED_CLASS_EXT`, `BPF_SYSCALL`,
`DEBUG_INFO_BTF`, `PSI` or `NET_9P_VIRTIO` do not survive `olddefconfig`, builds, and copies the image to
`build/kernels/<arch>/` and the scx headers to `third_party/scx-include/`.

## 2. Root filesystem (once per architecture)

```bash
sudo tools/qemu/make-rootfs.sh x86_64
sudo tools/qemu/make-rootfs.sh arm64
```

A Debian trixie image with clang, libbpf, bpftool, python3, openssl, stress-ng, tpm2-tools. The `gen` stage builds BPF inside the guest, so clang, bpftool and libbpf must be there (they are, for the `build` stage). The repo itself is not
baked in: it is shared into the guest over virtio-9p at `/repo`, so host edits are visible immediately. The guest
compiles the BPF program and loader itself (into a tmpfs `/tmp/cbuild`), so binaries are always the right
architecture and the two architectures never overwrite each other.

## 3. Run the suite

```bash
tools/qemu/run-qemu.sh x86_64
tools/qemu/run-qemu.sh arm64            # TCG on an x86 host: slow (compile happens in the guest)
tools/qemu/run-qemu.sh arm64 -- skip-ab,skip-e2e,skip-gen    # faster subset
```

`run-qemu.sh` boots with `-enable-kvm` when host and target architectures match and `/dev/kvm` is writable, else TCG.
It prints the serial console, stores it in `build/qemu-<arch>.log`, and exits 0 only if the guest printed
`CONDUCTOR-GUEST-RESULT: PASS`. Per-stage results land in `build/guest-result.json`.

Stages (details in `docs/TESTING.md`): `env`, `build`, `unit`, `loader`, `watchdog`, `ab-latency`, `governor`, `gen`.

Defaults: 4 vCPUs, 4 GiB, 1 h timeout. Override with `SMP=8 MEM=8G TIMEOUT=7200`.

### Optional: TPM-backed audit in QEMU

Install `swtpm`, start it, and add `-chardev socket,id=chrtpm,path=/tmp/swtpm.sock -tpmdev emulator,id=tpm0,chardev=chrtpm
-device tpm-tis,tpmdev=tpm0` (x86 `q35`; on arm64 `virt` use `tpm-tis-device`) to `run-qemu.sh`. With `/dev/tpmrm0`
present the daemon extends PCR 16 on every audit record (`audit.jsonl` entries then show `"tpm": true`). PCR 16 is the
resettable debug PCR; pick a real PCR policy for production.

## 4. Without QEMU: a real machine or an existing VM

Needs root, a kernel with `CONFIG_SCHED_CLASS_EXT=y`, `CONFIG_DEBUG_INFO_BTF=y`, PSI enabled, and clang, libbpf
(>= the version your scx headers expect), bpftool, python3, openssl.

```bash
tools/fetch-scx-include.sh ~/linux          # or point SCX_INC at your distro's scx headers
make                                         # build/conductor_load + build/scx_conductor.bpf.o
sudo bash tests/guest/run_all.sh             # same stages as QEMU, on this machine
sudo python3 -m conductord doctor            # can this machine build, verify and load generated schedulers?
```

`tools/fetch-scx-include.sh` accepts either a Linux tree or a checkout of github.com/sched-ext/scx.

Warning: the `watchdog` and `governor` stages load a real scheduler on the machine. They use partial mode for the
stall test, but the `ab-latency` and `governor` stages run a full-system scheduler for tens of seconds. Do it on a
disposable box first.

## 5. Running the daemon

Generate-on-device platforms (`laptop`, `mobile`, `vm`) need a signing key on the device:

```bash
sudo python3 -m conductord run --platform laptop --dev-self-sign      # dev/test only: key lives on the device
python3 -m conductord ctl status
python3 -m conductord ctl hold gaming          # pin; 'release' to go back to inference
python3 -m conductord ctl hint camera --pids 4242 --ttl 30
sudo python3 -m conductord ctl rollback        # unload and stay on stock until 'release'
python3 -m conductord audit-verify /var/lib/conductor/audit.jsonl
```

A key held on the same device does not defend against a compromised root; it protects against bugs and corruption
between forge and loader. For anything exposed, use approved-only manifests.

### On-device generation

`conductord gen / gen-list / gen-show / gen-approve / gen-reject / doctor`, plus `run --gen-backend ... [--gen-on-demand]`.
Procedure, recovery and what to record: **`docs/LAPTOP.md`**. Design: `docs/ARCHITECTURE.md` section 3b.

### Approved-only flow (iot, automotive)

On the forge host / CI, with the private key kept offline:

```bash
python3 -m conductord keygen --priv forge.key --pub trusted.pub
python3 -m conductord forge-approved --platform iot --arch aarch64 --priv forge.key --out approved/iot
```

Ship `trusted.pub`, `approved/iot/`, `build/scx_conductor.bpf.o` and `build/conductor_load` in the image, then:

```bash
python3 -m conductord run --platform iot --pubkey /etc/conductor/trusted.pub --approved-dir /etc/conductor/approved
```

The manifest pins the BPF object's SHA-256 and the architecture, so build the object in CI, sign after the build, and
sign per architecture (`--arch x86_64` / `aarch64`). `packaging/conductord.service` is a starting unit file.
