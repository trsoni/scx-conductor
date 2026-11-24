# scx-conductor build. Works natively on x86_64 and arm64 (build inside the
# guest/device so the loader is the right architecture; BPF is CO-RE).
#
#   make SCX_INC=/path/to/linux/tools/sched_ext/include
#
# SCX_INC must come from the SAME kernel version you run (kfunc declarations).

CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc
SCX_INC ?= third_party/scx-include
BUILD   ?= build

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
VMLINUX_H := $(BUILD)/vmlinux.h

BPF_CFLAGS := -g -O2 -Wall -mcpu=v3 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I$(BUILD) -I$(SCX_INC) -I$(SCX_INC)/bpf-compat -Ibpf
LDLIBS := -lbpf -lelf -lz -lzstd

.PHONY: all test clean check-env
all: check-env $(BUILD)/conductor_load

check-env:
	@test -f $(SCX_INC)/scx/common.bpf.h || { \
	  echo "Missing $(SCX_INC)/scx/common.bpf.h - run tools/fetch-scx-include.sh <linux-src>"; exit 1; }

$(VMLINUX_H):
	@mkdir -p $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/scx_conductor.bpf.o: bpf/scx_conductor.bpf.c bpf/conductor.h $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/scx_conductor.bpf.skel.h: $(BUILD)/scx_conductor.bpf.o
	$(BPFTOOL) gen skeleton $< name scx_conductor > $@

$(BUILD)/conductor_load: loader/conductor_load.c $(BUILD)/scx_conductor.bpf.skel.h bpf/conductor.h
	$(CC) -g -O2 -Wall -I$(BUILD) -I$(SCX_INC) -I$(SCX_INC)/bpf-compat -Ibpf $< -o $@ $(LDLIBS)

test:
	python3 -m unittest discover -s tests -v

clean:
	rm -rf $(BUILD)
