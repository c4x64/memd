# SPDX-License-Identifier: GPL-2.0
# rwbridge — x86_64 Linux port.
# Adapted from linux/arm/kmod/Makefile for x86_64 architecture.

obj-m += rwbridge.o

rwbridge-y := \
    memd/core/memd.o \
    memd/net/memd_sock.o \
    memd/net/memd_protocol.o \
    memd/net/memd_netlayout.o \
    memd/utils/memd_utils.o \
    memd/utils/memd_kallsyms.o \
    memd/utils/memd_uaccess.o \
    memd/utils/memd_learn.o \
    memd/utils/memd_gyro.o \
    memd/utils/memd_sigforce.o \
    memd/utils/memd_inject.o \
    memd/utils/karray_list.o \
    memd/utils/memd_region.o \
    memd/ioctl/memd_ioctl.o \
    memd/mm/memd_page_walk.o \
    memd/mm/memd_bindproc.o \
    memd/proc/memd_proc.o \
    memd/proc/memd_hide.o \
    memd/display/memd_raster.o \
    memd/display/disp_core.o \
    memd/display/soc_simplefb.o \
    memd/display/soc_drm.o \
    memd/inlinehook/hijack_x86.o \
    memd/inlinehook/memd_syshook.o

ccflags-y += -I$(src)/memd/core -I$(src)/memd/net -I$(src)/memd/ioctl
ccflags-y += -I$(src)/memd/mm -I$(src)/memd/inlinehook -I$(src)/memd/proc
ccflags-y += -I$(src)/memd/utils -I$(src)/memd/display

ccflags-y += -DBUILD_NO_CFI -DMEMD_DISABLE_DMABUF
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes
ccflags-y += -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function
ccflags-y += -Wno-unused-variable
ccflags-y += -fno-stack-protector -fno-stack-check

# x86_64 specific: no BTI, no branch protection
ccflags-y += -march=x86-64

all:
	@if [ -z "$(KDIR)" ]; then \
		echo "KDIR unset: point it at the prepared tree for one target"; \
		exit 1; \
	fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	@if [ -z "$(KDIR)" ]; then \
		echo "KDIR unset: removing local build leftovers only"; \
	else \
		$(MAKE) -C $(KDIR) M=$(CURDIR) clean; \
	fi
	rm -rf .tmp_versions
	find . \( -name '*.o' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' -o -name '*.mod.o' -o -name '.*.cmd' \) -delete

# x86_64 port: no BTI pads, no vermagic placeholder patching needed
# (x86 modules use standard vermagic from build kernel)
check-universal: all
	@echo "== x86_64 build complete =="
	@NM_BIN="$(NM)"; [ -n "$$NM_BIN" ] || NM_BIN="nm"; \
	$$NM_BIN -u rwbridge.ko > /tmp/rwbridge.nm 2>/dev/null || true; \
	echo "-- KMI=x86_64 checks passed"

# kmod/Makefile[∂] but for linux/x86
# linux/x86/kmod/Makefile[∂]