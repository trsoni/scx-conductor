# scx-conductor build. Works natively on x86_64 and arm64 (build inside the
# guest/device so the loader is the right architecture; BPF is CO-RE).
#
#   make SCX_INC=/path/to/linux/tools/sched_ext/include
#
# SCX_INC must come from the SAME kernel version you run (kfunc declarations).
#
# Overrides (all optional):
#   VMLINUX_DIR   directory containing a ready-made vmlinux.h (default: generate one
#                 from /sys/kernel/btf/vmlinux with bpftool)
#   EXTRA_CFLAGS  extra -I flags for clang and cc (e.g. a private libbpf header dir)
#   EXTRA_LDLIBS  extra link flags (e.g. a private libbpf.a and -L dirs)
#
# Targets:
#   make                build/conductor_load + build/scx_conductor.bpf.o
#   make gen SRC=f.c    build a generated scheduler: build/gen/{sched.bpf.o,gen_load}
#   make probe          write build/conductor_probe.h (scx header ABI probe)
#   make test           unit tests

CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc
SCX_INC ?= third_party/scx-include
BUILD   ?= build
EXTRA_CFLAGS ?=
EXTRA_LDLIBS ?=

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
ifdef VMLINUX_DIR
VMLINUX_INC := $(VMLINUX_DIR)
VMLINUX_DEP :=
else
VMLINUX_INC := $(BUILD)
VMLINUX_DEP := $(BUILD)/vmlinux.h
endif
PROBE_H := $(BUILD)/conductor_probe.h

BPF_CFLAGS := -g -O2 -Wall -mcpu=v3 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I$(BUILD) -I$(VMLINUX_INC) -I$(SCX_INC) -I$(SCX_INC)/bpf-compat -Ibpf $(EXTRA_CFLAGS)
CC_FLAGS := -g -O2 -Wall -I$(BUILD) -I$(SCX_INC) -I$(SCX_INC)/bpf-compat -Ibpf $(EXTRA_CFLAGS)
LDLIBS := $(EXTRA_LDLIBS) -lbpf -lelf -lz -lzstd
ABI_HDRS := bpf/conductor.h bpf/conductor_abi.bpf.h

.PHONY: all test clean check-env probe gen
all: check-env $(BUILD)/conductor_load

check-env:
	@test -f $(SCX_INC)/scx/common.bpf.h || { \
	  echo "Missing $(SCX_INC)/scx/common.bpf.h - run tools/fetch-scx-include.sh <linux-src>"; exit 1; }

$(BUILD)/vmlinux.h:
	@mkdir -p $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

probe: $(PROBE_H)
$(PROBE_H): tools/probe-scx-abi.sh $(VMLINUX_DEP)
	@mkdir -p $(BUILD)
	tools/probe-scx-abi.sh $(CLANG) $(ARCH) $(VMLINUX_INC) $(SCX_INC) $(EXTRA_CFLAGS:-I%=%) > $@

$(BUILD)/scx_conductor.bpf.o: bpf/scx_conductor.bpf.c $(ABI_HDRS) $(VMLINUX_DEP) $(PROBE_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/scx_conductor.bpf.skel.h: $(BUILD)/scx_conductor.bpf.o
	$(BPFTOOL) gen skeleton $< name scx_conductor > $@

$(BUILD)/conductor_load: loader/conductor_load.c $(BUILD)/scx_conductor.bpf.skel.h bpf/conductor.h
	$(CC) $(CC_FLAGS) $< -o $@ $(LDLIBS)

# ---- generated scheduler (source written on the device) ----
gen: check-env $(VMLINUX_DEP) $(PROBE_H)
	@test -n "$(SRC)" || { echo "usage: make gen SRC=path/to/generated.bpf.c"; exit 2; }
	@mkdir -p $(BUILD)/gen
	$(CLANG) $(BPF_CFLAGS) -c $(SRC) -o $(BUILD)/gen/sched.bpf.o
	$(BPFTOOL) gen skeleton $(BUILD)/gen/sched.bpf.o name scx_gen > $(BUILD)/gen/scx_gen.bpf.skel.h
	$(CC) -DGEN_BUILD -I$(BUILD)/gen $(CC_FLAGS) loader/conductor_load.c -o $(BUILD)/gen/gen_load $(LDLIBS)

test:
	python3 -m unittest discover -s tests -v

clean:
	rm -rf $(BUILD)
