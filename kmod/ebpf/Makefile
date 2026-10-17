# SPDX-License-Identifier: GPL-2.0
# eBPF build for memd core memory I/O helpers.

ARCH ?= arm64
CLANG ?= clang
CC ?= cc

BPF_CFLAGS := -g -O2 -target bpf -I.
ifeq ($(ARCH),arm64)
BPF_CFLAGS += -D__TARGET_ARCH_arm64
else ifeq ($(ARCH),x86_64)
BPF_CFLAGS += -D__TARGET_ARCH_x86
endif

all: vmlinux.h memd_ebpf.bpf.o memd_ebpf

vmlinux.h:
	@if [ -r /sys/kernel/btf/vmlinux ] && command -v bpftool >/dev/null 2>&1; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "vmlinux.h missing; run gen_vmlinux.sh or place manually"; exit 1; \
	fi

memd_ebpf.bpf.o: memd_ebpf.bpf.c memd_ebpf.h memd_offsets.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c memd_ebpf.bpf.c -o memd_ebpf.bpf.o

memd_ebpf: memd_ebpf.c memd_ebpf.h memd_offsets.h
	$(CC) -g -O2 -I. memd_ebpf.c -o memd_ebpf -lbpf -lelf -lz

clean:
	rm -f memd_ebpf.bpf.o memd_ebpf vmlinux.h

.PHONY: all clean