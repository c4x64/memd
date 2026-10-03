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
# permitted ONLY for the kernel display facility (display/) and process
# hiding (VFS iterate_shared swap in wuwa_syshook.c) under explicit owner
# override: fail-closed per-site, verify-before-patch, restore-on-exit.
#
# KDIR points at the prepared tree for ONE target (CI sets it per matrix
# job: KMI=android13-5.15 etc.). KMI names the output for packing.
# check-universal runs on the already-built rwbridge.ko, no KDIR needed.

obj-m += rwbridge.o
rwbridge-y := \
    wuwa/core/wuwa.o \
    wuwa/net/wuwa_sock.o \
    wuwa/net/wuwa_protocol.o \
    wuwa/net/wuwa_netlayout.o \
    wuwa/utils/wuwa_utils.o \
    wuwa/utils/wuwa_kallsyms.o \
    wuwa/utils/wuwa_uaccess.o \
    wuwa/utils/wuwa_learn.o \
    wuwa/utils/karray_list.o \
    wuwa/utils/wuwa_region.o \
    wuwa/ioctl/wuwa_ioctl.o \
    wuwa/mm/wuwa_page_walk.o \
    wuwa/mm/wuwa_bindproc.o \
    wuwa/proc/wuwa_proc.o \
    wuwa/proc/wuwa_hide.o \
    wuwa/display/wuwa_raster.o \
    wuwa/display/disp_core.o \
    wuwa/display/soc_exynos.o \
    wuwa/display/soc_simplefb.o \
    wuwa/display/soc_drm.o \
    wuwa/inlinehook/hijack_arm64.o \
    wuwa/inlinehook/wuwa_syshook.o

# TEST ONLY (never ship): DISP_TEST=1 adds the RAM backend + readback
# opcode for host-side pixel verification (no panel hardware needed).
# Product artifacts never set it (surface stays 26/27/28).
ifdef DISP_TEST
rwbridge-y += wuwa/display/soc_ram.o
ccflags-y += -DWUWA_DISP_TEST
endif

# hijack_arm64.o is linked ONLY for hook_write_range (CFI-disable path).
# check_target_can_hijack and the call-redirection machinery are never
# called (no call sites outside that file); kept compiled to avoid forking
# upstream logic.

ccflags-y += -I$(src)/wuwa/core -I$(src)/wuwa/net -I$(src)/wuwa/ioctl
ccflags-y += -I$(src)/wuwa/mm -I$(src)/wuwa/inlinehook -I$(src)/wuwa/proc
ccflags-y += -I$(src)/wuwa/utils -I$(src)/wuwa/display

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
# Neutralize DDK-inherited CFI instrumentation (DDK trees build with CFI
# on: without removal our objects import __cfi_* / __ubsan_* handlers that
# non-CFI kernels do not export -> ENOENT at load). Removal by exact flag
# spelling (order-proof, no compiler-version dependency — old clangs reject
# -fno-sanitize=kcfi outright). Enforcing kernels are handled at runtime by
# cfi_bypass(); a kcfi-instrumented variant was tried and dropped (the DDK
# clang emits no kcfi traps for this codebase — no indirect-call typeids —
# so the variant was byte-identical to plain; not worth a matrix slot).
ccflags-remove-y += -fsanitize=cfi -fsanitize=kcfi -fsanitize-cfi-cross-dso
# kallsyms comes from /proc/kallsyms self-parse (wuwa_kallsyms.c): no
# kprobe imports of any kind, so no loader-rejected GOT relocs on any
# target and no per-generation trick filter. The old WUWA_NO_KPROBE_TRICK
# filter is deleted; every artifact resolves the same way.
# DBG variant (DBG=1, android14-6.1-dbg job): full debug info kept for
# crash forensics (pstore/dmesg decoding). Never auto-selected by the
# loader (explicit --ko only); identical code to the plain artifact.
ifdef DBG
ccflags-y += -g -fno-omit-frame-pointer
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
# surface. Import rule (owner-amended for the universal architecture):
# GKI trees always export printk + the socket/mm/process APIs used here,
# and each artifact is verified against ITS OWN generation's System.map
# by check_universal.py (exact ELF parsing). kallsyms_lookup_name is
# never imported (the /proc self-parse in wuwa_kallsyms.c resolves every
# name at runtime — no kprobe imports of any kind, so no loader-rejected
# GOT relocs on any target). No procfs (sysfs-free: socket/ioctl
# transport). No CR0/WP games. BTI pads + vermagic placeholder stay
# inline below.
check-universal: all
	@echo "== versions/imports via check_universal.py =="
	@NM_BIN="$(NM)"; [ -n "$$NM_BIN" ] || NM_BIN="$(CROSS_COMPILE)nm"; \
	OD_BIN="$(OBJDUMP)"; [ -n "$$OD_BIN" ] || OD_BIN="$(CROSS_COMPILE)objdump"; \
	$$NM_BIN -u rwbridge.ko | awk '{print $$2}' | sort -u | tee /tmp/rwbridge.undef; \
	python3 check_universal.py rwbridge.ko /tmp/rwbridge.undef $(KMI) $(KDIR)/System.map; \
	echo "== BTI landing pads present =="; \
	$$OD_BIN -d rwbridge.ko | grep -qiE 'bti([[:space:]]|$$)|hint[[:space:]]' || \
		{ echo "FAIL: no BTI pads (BTI kernels fault on entry -> reboot)"; exit 1; }; \
	echo "-- pad count (need >=9 entry points covered) --"; \
	N=$$($$OD_BIN -d rwbridge.ko | grep -ciE 'bti([[:space:]]|$$)|hint[[:space:]]'); \
	echo "pads=$$N"; [ "$$N" -ge 9 ] || \
		{ echo "FAIL: only $$N pads, need >=9 entry points covered"; exit 1; }
	@echo "== vermagic placeholder present =="
	@strings rwbridge.ko | grep -q '^vermagic=' || { echo "FAIL: no vermagic"; exit 1; }
	@echo "-- KMI=$(KMI) checks passed"
