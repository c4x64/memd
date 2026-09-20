# SPDX-License-Identifier: GPL-2.0
# rwbridge — UNIVERSAL single build.
#
# Compile ONCE against ANY arm64 kernel tree 5.10+; the resulting .ko is not
# tied to that tree: struct layouts come from the kopts runtime channel or
# init-time self-derivation, and vermagic is patched to the running kernel
# by run.sh at install time. CI builds against the OLDEST supported headers
# (5.10) which proves no newer-only API is used.
#
# KDIR is only needed to BUILD (any prepared arm64 tree 5.10+).
# check-universal runs on the already-built rwbridge.ko, no KDIR needed.
obj-m += rwbridge.o

# Self-contained: no libc imports, no stack protector runtime, no CFI
# instrumentation (single build must load on CFI and non-CFI kernels alike —
# see README "CFI" for the one residual risk on enforcing kernels).
# BTI landing pads are REQUIRED (not optional): BTI-enforcing kernels fault
# on any indirect branch into pad-less code (oops -> reboot where
# panic_on_oops=1). Pads decode as NOPs where BTI is unsupported, so one
# build stays universal. PAC deliberately excluded (no key dependency).
ccflags-y += -fno-builtin-memcpy -fno-stack-protector -fno-stack-check -fno-builtin -mbranch-protection=bti
# Per-object form: strongest kbuild guarantee (ccflags-y alone was observed
# to never reach the gcc line on some trees). Duplicate value = harmless.
# -march=armv8.5-a is REQUIRED for the bti flag to take effect at all: on
# the kernel's baseline -march the flag is silently inoperative (no pads, no
# note, no error). Safe on older CPUs: BTI hints decode as NOP pre-8.5, and
# this source emits no other 8.5+ instructions (no atomics — spinlock is
# inline-asm LDXR/STXR; mem* are library calls).
CFLAGS_rwbridge.o := -mbranch-protection=bti -march=armv8.5-a

all:
	@if [ -z "$(KDIR)" ]; then \
		echo "KDIR unset: point it at ANY prepared arm64 kernel tree 5.10+"; \
		exit 1; \
	fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

# Static universality gate: fails the build if the module drifted off the
# stable import surface or grew version bindings. NOTE: printk/_printk are
# deliberately ABSENT — logging is zero-import (in-module ring); if code
# ever emits a printk-family import again, this gate must fail.
# Allowlist besides module_layout/mem*: copy_from_kernel_nofault (stable
# since forever, linear-map reads) and param_ops_int (stability/readonly
# flags use the kernel's own int handlers — zero custom parse code, ABI
# frozen for 15+ years).
check-universal: all
	@echo "== __versions absent or empty (no CRC pinning) =="
	@VSEC=$$($(CROSS_COMPILE)readelf -S rwbridge.ko | awk '/__versions/ {print $$6}'); \
	if [ -n "$$VSEC" ]; then \
		python3 -c "import sys; sys.exit(0 if int('$$VSEC',16)==0 else 1)" || \
		{ echo "FAIL: __versions has CRCs (pins build to one KMI)"; exit 1; }; \
		echo "note: empty __versions present (modversions-loader bypass, no CRCs)"; \
	fi
	@echo "== undefined symbols allowlist (no printk family) =="
	@$(CROSS_COMPILE)nm -u rwbridge.ko | awk '{print $$2}' | sort -u | tee /tmp/rwbridge.undef
	@if grep -vE '^(module_layout|memset|memcpy|memmove|memcmp|strlen|copy_from_kernel_nofault|param_ops_int)$$' /tmp/rwbridge.undef | grep -q .; then \
		echo "FAIL: unexpected imports:"; \
		grep -vE '^(module_layout|memset|memcpy|memmove|memcmp|strlen|copy_from_kernel_nofault|param_ops_int)$$' /tmp/rwbridge.undef; \
		exit 1; \
	fi
	@echo "== BTI landing pads present =="
	@$(CROSS_COMPILE)objdump -d rwbridge.ko | grep -qiE 'bti([[:space:]]|$$)|hint[[:space:]]' || \
		{ echo "FAIL: no BTI pads (BTI kernels fault on entry -> reboot)"; exit 1; }
	@echo "-- pad count (need >=9: init/exit + 7 param handlers) --"; \
	N=$$($(CROSS_COMPILE)objdump -d rwbridge.ko | grep -ciE 'bti([[:space:]]|$$)|hint[[:space:]]'); \
	echo "pads=$$N"; [ "$$N" -ge 9 ] || \
		{ echo "FAIL: only $$N pads, need >=9 entry points covered"; exit 1; }
	@echo "== vermagic placeholder present =="
	@strings rwbridge.ko | grep -q '^vermagic=' || { echo "FAIL: no vermagic"; exit 1; }
	@echo "== vermagic placeholder roomy (>=110: fits 6.1-length targets) =="
	@L=$$(strings rwbridge.ko | grep '^vermagic=' | head -1 | wc -c); echo "field=$$L"; [ "$$L" -ge 111 ] || \
		{ echo "FAIL: vermagic field too short for long targets"; exit 1; }
	@echo "universal checks passed"
