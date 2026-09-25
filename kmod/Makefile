# SPDX-License-Identifier: GPL-2.0
# rwbridge — wuwa-derived driver, 8-target DDK matrix + single SPX deliverable.
#
# Each artifact is built against its own generation's headers (DDK); nothing
# is shared across generations at compile time. Runtime kernel variance
# inside a generation (vendor UTS suffixes) is absorbed by the vermagic
# placeholder + run.sh patch (same contract as before). Symbol resolution
# (kallsyms via kprobe trick) and CFI-disable run at init; failures refuse
# loudly (no degraded operation).
#
# Product surface: socket (PF_DECnet) + ioctl transports. Inline hooks are
# NEVER used (hook/ not built); hide paths are compiled out (flags below).
# Process-hide is a tracked TODO (see README), not present in this tree.
#
# KDIR points at the prepared tree for ONE target (CI sets it per matrix
# job: KMI=android13-5.15 etc.). KMI names the output for packing.
# check-universal runs on the already-built rwbridge.ko, no KDIR needed.

obj-m += rwbridge.o
rwbridge-y := \
    wuwa/core/wuwa.o \
    wuwa/net/wuwa_sock.o \
    wuwa/net/wuwa_protocol.o \
    wuwa/utils/wuwa_utils.o \
    wuwa/utils/karray_list.o \
    wuwa/ioctl/wuwa_ioctl.o \
    wuwa/mm/wuwa_page_walk.o \
    wuwa/mm/wuwa_bindproc.o \
    wuwa/proc/wuwa_proc.o \
    wuwa/inlinehook/hijack_arm64.o

# hijack_arm64.o is linked ONLY for hook_write_range (CFI-disable path).
# check_target_can_hijack and the call-redirection machinery are never
# called (no call sites outside that file); kept compiled to avoid forking
# upstream logic.

ccflags-y += -I$(src)/wuwa/core -I$(src)/wuwa/net -I$(src)/wuwa/ioctl
ccflags-y += -I$(src)/wuwa/mm -I$(src)/wuwa/inlinehook -I$(src)/wuwa/proc
ccflags-y += -I$(src)/wuwa/utils

# Behavior flags (locked, not per-target): CFI-disable ON (needed on
# enforcing kernels — was the plain loader's wall); every hide path OFF;
# dmabuf transport OFF (socket/ioctl cover the product surface).
ccflags-y += -DBUILD_NO_CFI -DWUWA_DISABLE_DMABUF

# Warning profile (upstream-tolerant, load-bearing warnings stay on).
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
ccflags-y += -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
ccflags-y += -Wno-unused-variable

# BTI landing pads are REQUIRED (not optional): BTI-enforcing kernels fault
# on any indirect branch into pad-less code. Pads decode as NOPs elsewhere.
# -march=armv8.5-a is REQUIRED for the flag to take effect at all.
ccflags-y += -mbranch-protection=bti -march=armv8.5-a

# No stack-protector runtime dependency (single image must not depend on
# per-tree helper availability beyond the checked import surface).
ccflags-y += -fno-stack-protector -fno-stack-check
# CFI variant (CFI=1, android14-6.1-cfi job): kcfi typeids so kernel->module
# indirect calls pass the type check on enforcing kernels. kcfi is
# clang-only (CI passes CC=clang for that job). No new imports (typeids
# are local labels). Runtime cfi_bypass stays on regardless.
ifdef CFI
ccflags-y += -fsanitize=kcfi
endif

all:
	@if [ -z "$(KDIR)" ]; then \
		echo "KDIR unset: point it at the prepared tree for one matrix target (see README + CI)"; \
		exit 1; \
	fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

# Static gate: fails the build if the module drifted off the checked
# surface. Import rule (owner-amended for the matrix architecture): GKI
# trees always export printk + the socket/mm/process APIs used here, and
# each artifact is verified against ITS OWN generation's System.map by
# check_universal.py (exact ELF parsing). kallsyms_lookup_name is never
# imported (kprobe-trick runtime resolution only). No procfs (sysfs-free:
# socket/ioctl transport). No CR0/WP games. BTI pads + vermagic
# placeholder stay inline below.
check-universal: all
	@echo "== versions/imports via check_universal.py =="
	@$(NM) -u rwbridge.ko 2>/dev/null | awk '{print $$2}' | sort -u | tee /tmp/rwbridge.undef || \
		($(CROSS_COMPILE)nm -u rwbridge.ko | awk '{print $$2}' | sort -u | tee /tmp/rwbridge.undef)
	@python3 check_universal.py rwbridge.ko /tmp/rwbridge.undef $(KMI) $(KDIR)/System.map
	@echo "== BTI landing pads present =="
	@($(OBJDUMP) -d rwbridge.ko 2>/dev/null || $(CROSS_COMPILE)objdump -d rwbridge.ko) | grep -qiE 'bti([[:space:]]|$$)|hint[[:space:]]' || \
		{ echo "FAIL: no BTI pads (BTI kernels fault on entry -> reboot)"; exit 1; }
	@echo "-- pad count (need >=9 entry points covered) --"; \
	N=$$((($(OBJDUMP) -d rwbridge.ko 2>/dev/null || $(CROSS_COMPILE)objdump -d rwbridge.ko) | grep -ciE 'bti([[:space:]]|$$)|hint[[:space:]]')); \
	echo "pads=$$N"; [ "$$N" -ge 9 ] || \
		{ echo "FAIL: only $$N pads, need >=9 entry points covered"; exit 1; }
	@echo "== vermagic placeholder present =="
	@strings rwbridge.ko | grep -q '^vermagic=' || { echo "FAIL: no vermagic"; exit 1; }
	@echo "-- KMI=$(KMI) checks passed"
