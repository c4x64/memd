# SPDX-License-Identifier: GPL-2.0
# rwbridge — memd-derived driver, per-KMI DDK matrix + single SPX deliverable.
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
# hiding (VFS iterate_shared swap in memd_syshook.c) under explicit owner
# override: fail-closed per-site, verify-before-patch, restore-on-exit.
#
# KDIR points at the prepared tree for ONE target (CI sets it per matrix
# job: KMI=android13-5.15 etc.). KMI names the output for packing.
# check-universal runs on the already-built rwbridge.ko, no KDIR needed.

obj-m += rwbridge.o
# PARKED (explicit — keep parked, do not delete, do not re-add silently):
# memd/utils/memd_hwbp.o is NOT part of rwbridge-y. It programs the
# removed thread_struct.debug_monitors / struct debug_monitor_state
# model (absent on every matrix DDK; new model is thread debug_info +
# live registers). Re-adding requires a rewrite against that model;
# until then the API stubs in memd_hwbp.h keep ioctl opcodes 21-24
# wired and fail soft (-ENODEV). Deletion is rejected: it would orphan
# the wired ioctl ABI plus retired/HWBP_ANALYSIS_REPORT.md. This list
# is explicit (no wildcard anywhere pulls parked files back in).
# PARKED_OBJS documents parked objects; no rule may reference it.
PARKED_OBJS := memd/utils/memd_hwbp.o
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
    memd/display/soc_exynos.o \
    memd/display/soc_simplefb.o \
    memd/display/soc_drm.o \
    memd/inlinehook/hijack_arm64.o \
    memd/inlinehook/memd_syshook.o

# TEST ONLY (never ship): DISP_TEST=1 adds the RAM backend + readback
# opcode for host-side pixel verification (no panel hardware needed).
# Product artifacts never set it (surface stays 26/27/28).
ifdef DISP_TEST
rwbridge-y += memd/display/soc_ram.o
rwbridge-y += memd/display/memd_vnc.o
ccflags-y += -DMEMD_DISP_TEST
endif

# hijack_arm64.o is linked ONLY for hook_write_range (CFI-disable path).
# check_target_can_hijack and the call-redirection machinery are never
# called (no call sites outside that file); kept compiled to avoid forking
# upstream logic.

ccflags-y += -I$(src)/memd/core -I$(src)/memd/net -I$(src)/memd/ioctl
ccflags-y += -I$(src)/memd/mm -I$(src)/memd/inlinehook -I$(src)/memd/proc
ccflags-y += -I$(src)/memd/utils -I$(src)/memd/display

# Behavior flags (locked, not per-target): CFI-disable ON (needed on
# enforcing kernels — was the plain loader's wall); every hide path OFF;
# dmabuf transport OFF (socket/ioctl cover the product surface).
ccflags-y += -DBUILD_NO_CFI -DMEMD_DISABLE_DMABUF

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
ccflags-remove-y += -fsanitize-cfi-icall-experimental-normalize-integers
# kallsyms comes from /proc/kallsyms self-parse (memd_kallsyms.c): no
# kprobe imports of any kind, so no loader-rejected GOT relocs on any
# target and no per-generation trick filter. The old MEMD_NO_KPROBE_TRICK
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
	# Stage the donor tree's Module.symvers locally so modpost can resolve
	# per-symbol CRCs on 6.x DDKs (implicit lookup stopped feeding them).
	# Writing it into $(CURDIR) lets kbuild merge CRCs instead of importing
	# the whole kernel symvers (which triggers duplicate-export fatals).
	@if [ -f "$(KDIR)/Module.symvers" ]; then cp -f "$(KDIR)/Module.symvers" "$(CURDIR)/Module.symvers"; fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	@if [ -z "$(KDIR)" ]; then \
		echo "KDIR unset: removing local build leftovers only (no kbuild tree)"; \
	else \
		$(MAKE) -C $(KDIR) M=$(CURDIR) clean; \
	fi
	rm -rf .tmp_versions
	find . \( -name '*.o' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' -o -name '*.mod.o' -o -name '.*.cmd' \) -delete
	rm -f modules.order Module.symvers build.log ../blobs.c

# Static gate: fails the build if the module drifted off the checked
# surface. Import rule (owner-amended for the universal architecture):
# GKI trees always export printk + the socket/mm/process APIs used here,
# and each artifact is verified against ITS OWN generation's System.map
# by check_universal.py (exact ELF parsing). kallsyms_lookup_name is
# never imported (the /proc self-parse in memd_kallsyms.c resolves every
# name at runtime — no kprobe imports of any kind, so no loader-rejected
# GOT relocs on any target). No procfs (sysfs-free: socket/ioctl
# transport). No CR0/WP games. BTI pads + vermagic placeholder stay
# inline below.
check-universal: all
	@echo "== versions/imports via check_universal.py =="
	@NM_BIN="$(NM)"; [ -n "$$NM_BIN" ] || NM_BIN="$(CROSS_COMPILE)nm"; \
	OD_BIN="$(OBJDUMP)"; [ -n "$$OD_BIN" ] || OD_BIN="$(CROSS_COMPILE)objdump"; \
	$$NM_BIN -u rwbridge.ko > /tmp/rwbridge.nm || \
		{ echo "FAIL: nm undef dump failed"; exit 1; }; \
	awk '{print $$2}' /tmp/rwbridge.nm | sort -u | tee /tmp/rwbridge.undef || \
		{ echo "FAIL: nm undef dump failed"; exit 1; }; \
	[ -s /tmp/rwbridge.undef ] || \
		{ echo "FAIL: empty undef list (nm produced no symbols)"; exit 1; }; \
	python3 check_universal.py rwbridge.ko /tmp/rwbridge.undef "$(KMI)" "$(KDIR)/System.map" || exit 1; \
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
# kmod/Makefile[∂]

# ---------------------------------------------------------------------------
# fix-versions: adapt a prebuilt .ko to the running kernel.
# ---------------------------------------------------------------------------
MODULE_NAME_LEN ?= 64
KO ?= $(or $(MODULE),$(MODULE_KO),$(INPUT),$(KMODULE),rwbridge.ko)
SYMVERS ?= $(or $(MODULE_SYMVERS),$(SYMVERS_FILE),$(RUNNING_SYMVERS),$(KSYMVERS),/lib/modules/$(shell uname -r)/Module.symvers)
OUT ?= $(or $(OUTPUT),$(DEST),$(FIXED_KO),$(DEST_KO),$(KO))
VERMAGIC ?= $(or $(TARGET_VERMAGIC),$(RUNNING_VERMAGIC),)
UNAME_RELEASE ?= $(shell uname -r)
ALLOW_MISSING ?= 0
DRY_RUN ?= 0
BACKUP ?= 0
VERBOSE ?= 0

define FIX_VERSIONS_PY
import os
import sys
import struct
import shutil
import tempfile

class FixVersionsError(Exception):
    pass

def fail(message):
    raise FixVersionsError(message)

def env_first(names, default=None):
    for name in names:
        value = os.environ.get(name)
        if value is not None and value != "":
            return value
    return default

def env_flag(name):
    value = os.environ.get(name, "0")
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")

def verbose_enabled():
    return env_flag("VERBOSE")

def log_info(message):
    print("info: " + str(message))

def log_warn(message):
    print("warning: " + str(message))

def log_error(message):
    print("error: " + str(message), file=sys.stderr)

ELF_MAGIC = b"\x7fELF"
ELF_CLASS_64 = 2
ELF_DATA_LSB = 1
ELF_VERSION_CURRENT = 1
SUPPORTED_MACHINES = (183, 62)
DEFAULT_MODULE_NAME_LEN = 64

class SymversEntry:
    def __init__(self, crc, symbol, module_name, export_kind, namespace):
        self.crc = crc
        self.symbol = symbol
        self.module_name = module_name
        self.export_kind = export_kind
        self.namespace = namespace

    def __repr__(self):
        return "SymversEntry(crc=0x%x, symbol=%s)" % (self.crc, self.symbol)

class SymversDatabase:
    def __init__(self, path):
        self.path = path
        self.entries = {}
        self.duplicates = []
        self.total_lines = 0
        self.parsed_lines = 0

    def load(self):
        if not os.path.isfile(self.path):
            fail("Module.symvers not found: " + self.path)
        try:
            with open(self.path, "r", errors="replace") as stream:
                for line_number, raw_line in enumerate(stream, 1):
                    self.total_lines += 1
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    fields = line.split()
                    if len(fields) < 2:
                        continue
                    crc_token = fields[0]
                    symbol = fields[1]
                    if not (crc_token.startswith("0x") or crc_token.startswith("0X")):
                        continue
                    try:
                        crc_value = int(crc_token, 16)
                    except ValueError:
                        continue
                    module_name = fields[2] if len(fields) >= 3 else ""
                    export_kind = fields[3] if len(fields) >= 4 else ""
                    namespace = fields[4] if len(fields) >= 5 else ""
                    entry = SymversEntry(crc_value, symbol, module_name, export_kind, namespace)
                    if symbol in self.entries and self.entries[symbol].crc != crc_value:
                        self.duplicates.append((symbol, self.entries[symbol].crc, crc_value))
                    self.entries[symbol] = entry
                    self.parsed_lines += 1
        except OSError as exc:
            fail("cannot read Module.symvers %s: %s" % (self.path, exc))
        if not self.entries:
            fail("no CRC entries parsed from %s" % self.path)
        if verbose_enabled():
            log_info("parsed %d CRC entries from %s (%d lines)" % (
                len(self.entries), self.path, self.total_lines))
        if self.duplicates:
            log_warn("%d duplicate symbols in Module.symvers" % len(self.duplicates))
            for symbol, first, second in self.duplicates[:20]:
                log_warn("duplicate %s: 0x%x vs 0x%x" % (symbol, first, second))

    def has(self, symbol):
        return symbol in self.entries

    def lookup(self, symbol):
        entry = self.entries.get(symbol)
        if entry is None:
            return None
        return entry.crc

    def count(self):
        return len(self.entries)

class ElfSection:
    def __init__(self, index, header_offset, name, sh_type, sh_flags, addr,
                 offset, size, link, info, addralign, entsize):
        self.index = index
        self.header_offset = header_offset
        self.name = name
        self.type = sh_type
        self.flags = sh_flags
        self.addr = addr
        self.offset = offset
        self.size = size
        self.link = link
        self.info = info
        self.addralign = addralign
        self.entsize = entsize
        self.name_offset = 0

    def contains_offset(self, position):
        return self.offset <= position < self.offset + self.size

    def end(self):
        return self.offset + self.size

    def __repr__(self):
        return "ElfSection(name=%s, offset=%d, size=%d)" % (self.name, self.offset, self.size)

class Elf64Image:
    def __init__(self, data):
        self.data = data
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0
        self.sections = []

    def parse(self):
        if len(self.data) < 64:
            fail("file too small to be an ELF image")
        if self.data[:4] != b"\x7fELF":
            fail("not an ELF file")
        if self.data[4] != 2:
            fail("not a 64-bit ELF file")
        if self.data[5] != 1:
            fail("not a little-endian ELF file")
        if self.data[6] != 1:
            fail("unsupported ELF version")
        (self.e_type, self.e_machine) = struct.unpack_from("<HH", self.data, 16)
        self.e_version = struct.unpack_from("<I", self.data, 20)[0]
        self.e_entry = struct.unpack_from("<Q", self.data, 24)[0]
        self.e_phoff = struct.unpack_from("<Q", self.data, 32)[0]
        self.e_shoff = struct.unpack_from("<Q", self.data, 40)[0]
        self.e_flags = struct.unpack_from("<I", self.data, 48)[0]
        self.e_ehsize = struct.unpack_from("<H", self.data, 52)[0]
        self.e_phentsize = struct.unpack_from("<H", self.data, 54)[0]
        self.e_phnum = struct.unpack_from("<H", self.data, 56)[0]
        self.e_shentsize = struct.unpack_from("<H", self.data, 58)[0]
        self.e_shnum = struct.unpack_from("<H", self.data, 60)[0]
        self.e_shstrndx = struct.unpack_from("<H", self.data, 62)[0]
        if self.e_ehsize != 64:
            fail("unexpected ELF header size: %d" % self.e_ehsize)
        if self.e_shentsize not in (0, 64):
            fail("unexpected section header size: %d" % self.e_shentsize)
        if self.e_shnum == 0 or self.e_shnum > 4096:
            fail("implausible section count: %d" % self.e_shnum)
        if self.e_shstrndx >= self.e_shnum:
            fail("bad shstrndx: %d >= %d" % (self.e_shstrndx, self.e_shnum))
        if self.e_shoff <= 0 or self.e_shoff + self.e_shnum * 64 > len(self.data):
            fail("section table out of range")
        if self.e_machine not in SUPPORTED_MACHINES:
            log_warn("unusual ELF machine type: %d (continuing)" % self.e_machine)
        self.sections = []
        for index in range(self.e_shnum):
            base = self.e_shoff + index * 64
            if base + 64 > len(self.data):
                fail("section header %d out of range" % index)
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", self.data, base)
            section = ElfSection(index, base, "", sh_type, sh_flags, sh_addr,
                                sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize)
            section.name_offset = sh_name
            self.sections.append(section)
        shstr = self.sections[self.e_shstrndx]
        if shstr.offset <= 0 or shstr.offset + shstr.size > len(self.data):
            fail("shstrtab out of range")
        shstr_data = self.data[shstr.offset:shstr.offset + shstr.size]
        for section in self.sections:
            start = section.name_offset
            if start < 0 or start >= len(shstr_data):
                fail("section name offset out of range for section %d" % section.index)
            end = shstr_data.find(b"\x00", start)
            if end < 0:
                fail("unterminated section name")
            try:
                section.name = shstr_data[start:end].decode("ascii")
            except UnicodeDecodeError:
                fail("invalid section name encoding")
        if verbose_enabled():
            self.dump_sections()

    def dump_sections(self):
        log_info("ELF sections:")
        for section in self.sections:
            log_info("  [%2d] %-20s off=%-8d size=%-8d type=%d" % (
                section.index, section.name, section.offset, section.size, section.type))

    def find_section(self, name):
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def adjust_for_insertion(self, insert_at, delta):
        old_phoff = self.e_phoff
        old_shoff = self.e_shoff
        if old_phoff >= insert_at:
            self.e_phoff = old_phoff + delta
        if old_shoff >= insert_at:
            self.e_shoff = old_shoff + delta
        struct.pack_into("<Q", self.data, 32, self.e_phoff)
        struct.pack_into("<Q", self.data, 40, self.e_shoff)
        phoff = old_phoff
        phentsize = self.e_phentsize if self.e_phentsize else 56
        for index in range(self.e_phnum):
            header_offset = phoff + index * phentsize
            if header_offset + phentsize > len(self.data):
                fail("program header %d out of range" % index)
            p_offset = struct.unpack_from("<Q", self.data, header_offset + 8)[0]
            if p_offset >= insert_at:
                struct.pack_into("<Q", self.data, header_offset + 8, p_offset + delta)
        shoff = old_shoff
        shentsize = self.e_shentsize if self.e_shentsize else 64
        for index in range(self.e_shnum):
            header_offset = shoff + index * shentsize
            if header_offset + 64 > len(self.data):
                fail("section header %d out of range" % index)
            sh_offset = struct.unpack_from("<Q", self.data, header_offset + 24)[0]
            sh_size = struct.unpack_from("<Q", self.data, header_offset + 32)[0]
            if sh_offset >= insert_at:
                struct.pack_into("<Q", self.data, header_offset + 24, sh_offset + delta)
            elif sh_offset <= insert_at <= sh_offset + sh_size:
                struct.pack_into("<Q", self.data, header_offset + 32, sh_size + delta)
        for section in self.sections:
            if section.offset >= insert_at:
                section.offset += delta
            elif section.offset <= insert_at <= section.offset + section.size:
                section.size += delta

class VersionSectionRewriter:
    def __init__(self, image, database, module_name_len, allow_missing):
        self.image = image
        self.database = database
        self.module_name_len = module_name_len
        self.allow_missing = allow_missing
        self.total_entries = 0
        self.updated_entries = 0
        self.missing = []

    def validate(self):
        if self.module_name_len < 1 or self.module_name_len > 256:
            fail("invalid module name length: %d" % self.module_name_len)
        entry_size = 8 + self.module_name_len
        if entry_size < 9:
            fail("computed entry size too small: %d" % entry_size)

    def run(self):
        self.validate()
        section = self.image.find_section("__versions")
        if section is None:
            log_warn("no __versions section; nothing to rewrite")
            return self.total_entries, self.updated_entries, self.missing
        if section.size == 0:
            log_warn("__versions section is empty; nothing to rewrite")
            return self.total_entries, self.updated_entries, self.missing
        entry_size = 8 + self.module_name_len
        if section.size % entry_size != 0:
            fail("__versions size %d is not a multiple of entry size %d" % (
                section.size, entry_size))
        data = self.image.data
        for position in range(section.offset, section.offset + section.size, entry_size):
            name_bytes = data[position + 8:position + 8 + self.module_name_len]
            name = name_bytes.split(b"\x00", 1)[0].decode("ascii", "replace")
            if not name:
                continue
            self.total_entries += 1
            crc = self.database.lookup(name)
            if crc is not None:
                struct.pack_into("<Q", data, position, crc)
                self.updated_entries += 1
            else:
                self.missing.append(name)
        if self.missing and not self.allow_missing:
            fail("missing CRCs in Module.symvers for: " + ", ".join(sorted(set(self.missing))))
        log_info("rewrote __versions: entries=%d updated=%d missing=%d" % (
            self.total_entries, self.updated_entries, len(self.missing)))
        if self.missing:
            log_warn("unmatched symbols: " + ", ".join(sorted(set(self.missing))))
        return self.total_entries, self.updated_entries, self.missing

class VermagicPatcher:
    def __init__(self, image, release, override):
        self.image = image
        self.release = release
        self.override = override
        self.original = ""
        self.replacement = ""

    def find(self):
        data = self.image.data
        index = data.find(b"vermagic=")
        if index < 0:
            fail("vermagic string not found in module")
        end = data.find(b"\x00", index)
        if end < 0:
            fail("unterminated vermagic string")
        return index, end

    def compute_replacement(self, original):
        original_body = original[len("vermagic="):]
        if self.override:
            override = self.override.strip()
            if override.startswith("vermagic="):
                return override
            if " " in override:
                return "vermagic=" + override
            extras = ""
            if " " in original_body:
                extras = original_body[original_body.index(" "):]
            return "vermagic=" + override + extras
        extras = ""
        if " " in original_body:
            extras = original_body[original_body.index(" "):]
        return "vermagic=" + self.release + extras

    def run(self):
        data = self.image.data
        index, end = self.find()
        original = data[index:end].decode("latin1")
        self.original = original
        replacement = self.compute_replacement(original)
        self.replacement = replacement
        replacement_bytes = replacement.encode("latin1")
        old_length = end - index + 1
        new_length = len(replacement_bytes) + 1
        if new_length <= old_length:
            data[index:index + len(replacement_bytes)] = replacement_bytes
            data[index + len(replacement_bytes)] = 0
            for position in range(index + len(replacement_bytes) + 1, index + old_length):
                data[position] = 0
            log_info("patched vermagic: '%s' -> '%s'" % (original, replacement))
            return original, replacement
        delta = new_length - old_length
        insert_at = end + 1
        self.image.adjust_for_insertion(insert_at, delta)
        data[insert_at:insert_at] = b"\x00" * delta
        data[index:index + len(replacement_bytes)] = replacement_bytes
        data[index + len(replacement_bytes)] = 0
        log_info("patched vermagic: '%s' -> '%s' (extended by %d bytes)" % (
            original, replacement, delta))
        return original, replacement

class AtomicFileWriter:
    def __init__(self, path):
        self.path = path

    def write(self, data):
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".fix-versions-", dir=directory or ".")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(temporary, 0o644)
            except OSError:
                pass
            if os.path.exists(self.path):
                os.replace(temporary, self.path)
            else:
                os.rename(temporary, self.path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

class OutputVerifier:
    def __init__(self, path, expected_vermagic):
        self.path = path
        self.expected_vermagic = expected_vermagic

    def run(self):
        if not os.path.isfile(self.path):
            fail("output file missing after write: " + self.path)
        data = open(self.path, "rb").read()
        image = Elf64Image(data)
        image.parse()
        section = image.find_section("__versions")
        vermagic_index = data.find(b"vermagic=")
        if vermagic_index < 0:
            fail("vermagic missing in output")
        vermagic_end = data.find(b"\x00", vermagic_index)
        actual_vermagic = data[vermagic_index:vermagic_end].decode("latin1")
        if self.expected_vermagic and actual_vermagic != self.expected_vermagic:
            fail("vermagic verification failed: %s != %s" % (actual_vermagic, self.expected_vermagic))
        log_info("verified output: %d bytes, vermagic=%s" % (len(data), actual_vermagic))
        if section is not None:
            log_info("verified __versions: offset=%d size=%d" % (section.offset, section.size))

class FixVersionsJob:
    def __init__(self):
        self.ko_path = env_first(
            ["KO", "MODULE", "MODULE_KO", "INPUT", "KMODULE"], "rwbridge.ko")
        self.symvers_path = env_first(
            ["SYMVERS", "MODULE_SYMVERS", "SYMVERS_FILE", "RUNNING_SYMVERS", "KSYMVERS"],
            "/lib/modules/%s/Module.symvers" % os.environ.get("UNAME_RELEASE", os.uname().release))
        self.out_path = env_first(
            ["OUT", "OUTPUT", "DEST", "FIXED_KO", "DEST_KO"], self.ko_path)
        self.vermagic_override = env_first(
            ["VERMAGIC", "TARGET_VERMAGIC", "RUNNING_VERMAGIC"], "")
        self.release = env_first(
            ["UNAME_RELEASE", "KERNEL_RELEASE", "KVER"], os.uname().release)
        self.allow_missing = env_flag("ALLOW_MISSING") or env_flag("ALLOW_MISSING_CRC")
        self.dry_run = env_flag("DRY_RUN")
        self.backup = env_flag("BACKUP")
        try:
            self.module_name_len = int(os.environ.get("MODULE_NAME_LEN", str(DEFAULT_MODULE_NAME_LEN)))
        except ValueError:
            fail("invalid MODULE_NAME_LEN: " + os.environ.get("MODULE_NAME_LEN", ""))
        self.database = None
        self.image = None
        self.total_entries = 0
        self.updated_entries = 0
        self.missing = []
        self.original_vermagic = ""
        self.new_vermagic = ""

    def validate_inputs(self):
        if not os.path.isfile(self.ko_path):
            fail("input module not found: " + self.ko_path)
        if not os.path.isfile(self.symvers_path):
            fail("Module.symvers not found: " + self.symvers_path)
        log_info("input module: " + self.ko_path)
        log_info("Module.symvers: " + self.symvers_path)
        log_info("output module: " + self.out_path)
        log_info("kernel release: " + self.release)

    def load(self):
        self.database = SymversDatabase(self.symvers_path)
        self.database.load()
        raw = open(self.ko_path, "rb").read()
        self.image = Elf64Image(bytearray(raw))
        self.image.parse()

    def inspect(self):
        if not verbose_enabled():
            return
        parser = ModinfoParser(self.image)
        log_info("modinfo entries: %d" % parser.entry_count())
        if verbose_enabled():
            parser.dump()
        validator = ElfValidator(self.image)
        if validator.validate():
            validator.report()
        crc_verifier = CrcVerifier(self.image, self.database, self.module_name_len)
        crc_verifier.run()

    def run_rewrite(self):
        rewriter = VersionSectionRewriter(
            self.image, self.database, self.module_name_len, self.allow_missing)
        self.total_entries, self.updated_entries, self.missing = rewriter.run()

    def run_vermagic(self):
        patcher = VermagicPatcher(self.image, self.release, self.vermagic_override)
        self.original_vermagic, self.new_vermagic = patcher.run()

    def maybe_backup(self):
        if not self.backup:
            return
        if os.path.abspath(self.out_path) != os.path.abspath(self.ko_path):
            return
        backup_path = self.ko_path + ".bak"
        shutil.copy2(self.ko_path, backup_path)
        log_info("backup written: " + backup_path)

    def write_output(self):
        if self.dry_run:
            log_info("dry run; no file written")
            return
        self.maybe_backup()
        writer = AtomicFileWriter(self.out_path)
        writer.write(self.image.data)
        log_info("wrote %d bytes to %s" % (len(self.image.data), self.out_path))

    def verify(self):
        if self.dry_run:
            return
        verifier = OutputVerifier(self.out_path, self.new_vermagic)
        verifier.run()

    def print_summary(self):
        print("summary: versions=%d/%d vermagic=%s" % (
            self.updated_entries, self.total_entries, self.new_vermagic))
        if self.missing:
            print("summary: missing=%d" % len(self.missing))

    def run(self):
        self.validate_inputs()
        self.load()
        self.inspect()
        self.run_rewrite()
        self.run_vermagic()
        self.write_output()
        self.verify()
        self.print_summary()

def parse_arguments(argv):
    if "--help" in argv or "-h" in argv:
        print("fix-versions: rewrite __versions CRCs and patch vermagic")
        print("Environment variables control all options; see Makefile help.")
        sys.exit(0)
    if "--version" in argv:
        print("fix-versions 1.0")
        sys.exit(0)

class ModinfoParser:
    def __init__(self, image):
        self.image = image
        self.section = image.find_section(".modinfo")
        self._entries = None

    def _load(self):
        if self._entries is not None:
            return self._entries
        entries = []
        if self.section is None or self.section.size == 0:
            self._entries = entries
            return entries
        data = self.image.data
        start = self.section.offset
        end = start + self.section.size
        position = start
        while position < end:
            if data[position] == 0:
                position += 1
                continue
            term = data.find(b"\x00", position, end)
            if term < 0:
                term = end
            raw = data[position:term]
            if raw:
                entries.append(raw)
            position = term + 1
        self._entries = entries
        return entries

    def all_entries(self):
        return list(self._load())

    def as_mapping(self):
        mapping = {}
        for raw in self._load():
            if b"=" in raw:
                key, value = raw.split(b"=", 1)
                try:
                    mapping[key.decode("latin1")] = value.decode("latin1")
                except UnicodeDecodeError:
                    mapping[key.decode("latin1", "replace")] = value.decode("latin1", "replace")
        return mapping

    def get(self, key):
        return self.as_mapping().get(key)

    def has_key(self, key):
        return key in self.as_mapping()

    def entry_count(self):
        return len(self._load())

    def dump(self):
        for raw in self._load():
            try:
                print("modinfo: " + raw.decode("latin1"))
            except UnicodeDecodeError:
                print("modinfo: " + repr(raw))

class ElfValidator:
    def __init__(self, image):
        self.image = image
        self.errors = []
        self.warnings = []

    def validate(self):
        self.errors = []
        self.warnings = []
        data = self.image.data
        if len(data) < 64:
            self.errors.append("file too small")
            return False
        if data[:4] != b"\x7fELF":
            self.errors.append("bad ELF magic")
            return False
        if self.image.e_shoff <= 0 or self.image.e_shoff + self.image.e_shnum * 64 > len(data):
            self.errors.append("section table out of range")
        for section in self.image.sections:
            if section.offset < 0 or section.size < 0:
                self.errors.append("negative section offset/size: " + section.name)
                continue
            if section.offset + section.size > len(data):
                self.errors.append("section out of range: " + section.name)
            if section.size > 0 and section.offset == 0 and section.index != 0:
                self.warnings.append("section has zero file offset: " + section.name)
        if not self.image.find_section(".modinfo"):
            self.warnings.append("no .modinfo section")
        if not self.image.find_section("__versions"):
            self.warnings.append("no __versions section")
        return len(self.errors) == 0

    def report(self):
        for warning in self.warnings:
            log_warn(warning)
        for error in self.errors:
            log_error(error)
        if not self.errors and not self.warnings:
            log_info("ELF validation passed")

class CrcVerifier:
    def __init__(self, image, database, module_name_len=64):
        self.image = image
        self.database = database
        self.module_name_len = module_name_len
        self.checked = 0
        self.matched = 0
        self.unmatched = []

    def run(self):
        section = self.image.find_section("__versions")
        if section is None or section.size == 0:
            log_info("CRC verification: no __versions entries")
            return 0, 0, []
        entry_size = 8 + self.module_name_len
        data = self.image.data
        for position in range(section.offset, section.offset + section.size, entry_size):
            if position + entry_size > len(data):
                break
            name = data[position + 8:position + 8 + self.module_name_len].split(b"\x00", 1)[0].decode("ascii", "replace")
            if not name:
                continue
            self.checked += 1
            crc = struct.unpack_from("<Q", data, position)[0]
            expected = self.database.lookup(name)
            if expected is None:
                self.unmatched.append(name)
            elif expected != crc:
                self.unmatched.append(name + "(crc mismatch)")
            else:
                self.matched += 1
        log_info("CRC verification: checked=%d matched=%d unmatched=%d" % (
            self.checked, self.matched, len(self.unmatched)))
        if self.unmatched:
            log_warn("CRC verification unmatched: " + ", ".join(self.unmatched))
        return self.checked, self.matched, self.unmatched

class SelfTestRunner:
    def __init__(self):
        self.temp_dir = None
        self.ko_path = None
        self.symvers_path = None
        self.saved_env = {}

    def _save_env(self):
        for key in ("KO", "SYMVERS", "OUT", "VERMAGIC", "UNAME_RELEASE",
                    "ALLOW_MISSING", "DRY_RUN", "BACKUP", "VERBOSE",
                    "MODULE_NAME_LEN"):
            self.saved_env[key] = os.environ.get(key)

    def _restore_env(self):
        for key, value in self.saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _write_synthetic_module(self):
        name_len = 64
        entry_size = 8 + name_len
        vermagic_placeholder = b"vermagic=" + b"B" * 58 + b" SMP preempt mod_unload aarch64\x00"
        modinfo = vermagic_placeholder
        sym1 = b"printk" + b"\x00" * (name_len - len("printk"))
        sym2 = b"module_put" + b"\x00" * (name_len - len("module_put"))
        versions = struct.pack("<Q", 0) + sym1 + struct.pack("<Q", 0) + sym2
        shstrtab = b"\x00.shstrtab\x00.modinfo\x00__versions\x00"
        pos = 1
        name_offs = {}
        for n in [b".shstrtab", b".modinfo", b"__versions"]:
            name_offs[n.decode()] = pos
            pos += len(n) + 1
        off_shstr = 64
        off_modinfo = off_shstr + len(shstrtab)
        off_versions = off_modinfo + len(modinfo)
        shdr_offset = off_versions + len(versions)
        while shdr_offset % 8:
            shdr_offset += 1
        buf = bytearray()
        buf += b"\x00" * 64
        buf += b"\x00" * (off_shstr - len(buf))
        buf += shstrtab
        buf += modinfo
        buf += versions
        while len(buf) < shdr_offset:
            buf += b"\x00"
        def shdr(name_off, type_, flags, addr, offset, size, link, info, align, entsize):
            return struct.pack("<IIQQQQIIQQ", name_off, type_, flags, addr, offset, size, link, info, align, entsize)
        buf += b"\x00" * 64
        buf += shdr(name_offs[".shstrtab"], 3, 0, 0, off_shstr, len(shstrtab), 0, 0, 1, 0)
        buf += shdr(name_offs[".modinfo"], 1, 0, 0, off_modinfo, len(modinfo), 0, 0, 1, 0)
        buf += shdr(name_offs["__versions"], 1, 0, 0, off_versions, len(versions), 0, 0, 8, entry_size)
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8,
            1, 183, 1, 0, 0, shdr_offset, 0, 64, 0, 0, 64, 4, 1,
        )
        buf[0:64] = ehdr
        self.ko_path = os.path.join(self.temp_dir, "selftest.ko")
        with open(self.ko_path, "wb") as stream:
            stream.write(buf)

    def _write_symvers(self):
        self.symvers_path = os.path.join(self.temp_dir, "Module.symvers")
        with open(self.symvers_path, "w") as stream:
            stream.write("0x11111111 printk vmlinux EXPORT_SYMBOL\n")
            stream.write("0x22222222 module_put vmlinux EXPORT_SYMBOL\n")

    def run(self):
        import tempfile as _tempfile
        self.temp_dir = _tempfile.mkdtemp(prefix="fix-versions-selftest-")
        self._save_env()
        try:
            self._write_synthetic_module()
            self._write_symvers()
            os.environ["KO"] = self.ko_path
            os.environ["SYMVERS"] = self.symvers_path
            os.environ["OUT"] = self.ko_path
            os.environ["UNAME_RELEASE"] = "selftest-1.2.3"
            os.environ["DRY_RUN"] = "0"
            os.environ["VERBOSE"] = "0"
            os.environ["ALLOW_MISSING"] = "0"
            job = FixVersionsJob()
            job.run()
            data = open(self.ko_path, "rb").read()
            image = Elf64Image(data)
            image.parse()
            section = image.find_section("__versions")
            assert section is not None and section.size == 144
            crcs = [struct.unpack_from("<Q", data, section.offset + i * 72)[0] for i in range(2)]
            assert crcs[0] == 0x11111111, crcs
            assert crcs[1] == 0x22222222, crcs
            assert b"vermagic=selftest-1.2.3" in data
            validator = ElfValidator(image)
            assert validator.validate(), validator.errors
            verifier = CrcVerifier(image, SymversDatabase(self.symvers_path) if False else None) if False else None
            print("self-test: PASS")
            return True
        except Exception as exc:
            print("self-test: FAIL: %r" % (exc,))
            return False
        finally:
            self._restore_env()
            if self.temp_dir and os.path.isdir(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)

def parse_arguments(argv):
    if "--help" in argv or "-h" in argv:
        print("fix-versions: rewrite __versions CRCs and patch vermagic")
        print("Environment variables control all options; see Makefile help.")
        sys.exit(0)
    if "--version" in argv:
        print("fix-versions 1.0")
        sys.exit(0)
    if "--self-test" in argv:
        runner = SelfTestRunner()
        ok = runner.run()
        sys.exit(0 if ok else 1)

class PathResolver:
    def __init__(self, raw_path):
        self.raw_path = raw_path
        self.expanded = os.path.expanduser(os.path.expandvars(raw_path)) if raw_path else ""

    def exists(self):
        return os.path.exists(self.expanded)

    def is_file(self):
        return os.path.isfile(self.expanded)

    def is_dir(self):
        return os.path.isdir(self.expanded)

    def absolute(self):
        return os.path.abspath(self.expanded)

    def directory(self):
        return os.path.dirname(self.absolute())

    def basename(self):
        return os.path.basename(self.absolute())

    def ensure_parent(self):
        parent = self.directory()
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        return parent

class EnvironmentConfig:
    def __init__(self):
        self.ko_path = env_first(["KO", "MODULE", "MODULE_KO", "INPUT", "KMODULE"], "rwbridge.ko")
        self.symvers_path = env_first(
            ["SYMVERS", "MODULE_SYMVERS", "SYMVERS_FILE", "RUNNING_SYMVERS", "KSYMVERS"],
            "/lib/modules/%s/Module.symvers" % os.environ.get("UNAME_RELEASE", os.uname().release))
        self.out_path = env_first(["OUT", "OUTPUT", "DEST", "FIXED_KO", "DEST_KO"], self.ko_path)
        self.vermagic_override = env_first(["VERMAGIC", "TARGET_VERMAGIC", "RUNNING_VERMAGIC"], "")
        self.release = env_first(["UNAME_RELEASE", "KERNEL_RELEASE", "KVER"], os.uname().release)
        self.allow_missing = env_flag("ALLOW_MISSING") or env_flag("ALLOW_MISSING_CRC")
        self.dry_run = env_flag("DRY_RUN")
        self.backup = env_flag("BACKUP")
        self.verbose = env_flag("VERBOSE")
        try:
            self.module_name_len = int(os.environ.get("MODULE_NAME_LEN", str(DEFAULT_MODULE_NAME_LEN)))
        except ValueError:
            fail("invalid MODULE_NAME_LEN: " + os.environ.get("MODULE_NAME_LEN", ""))
        self.self_test = env_flag("SELF_TEST")

    def validate(self):
        if not PathResolver(self.ko_path).is_file():
            fail("input module not found: " + self.ko_path)
        if not PathResolver(self.symvers_path).is_file():
            fail("Module.symvers not found: " + self.symvers_path)
        if self.module_name_len < 1 or self.module_name_len > 256:
            fail("invalid MODULE_NAME_LEN: %d" % self.module_name_len)
        if not self.release:
            fail("kernel release is empty")
        return True

    def print(self):
        log_info("input module: " + self.ko_path)
        log_info("Module.symvers: " + self.symvers_path)
        log_info("output module: " + self.out_path)
        log_info("kernel release: " + self.release)
        log_info("module name length: %d" % self.module_name_len)
        log_info("allow missing: %s" % self.allow_missing)
        log_info("dry run: %s" % self.dry_run)
        log_info("backup: %s" % self.backup)
        log_info("verbose: %s" % self.verbose)

class KernelReleaseNormalizer:
    def __init__(self, release):
        self.release = release

    def normalized(self):
        value = self.release.strip()
        if value.startswith("vermagic="):
            value = value[len("vermagic="):]
        if " " in value:
            value = value.split(" ", 1)[0]
        return value

    def is_plausible(self):
        value = self.normalized()
        if not value:
            return False
        if len(value) > 128:
            return False
        return True

class SymversPathResolver:
    def __init__(self, release):
        self.release = release

    def candidates(self):
        release = self.release
        return [
            "/lib/modules/%s/Module.symvers" % release,
            "/lib/modules/%s/build/Module.symvers" % release,
            "/usr/src/linux-%s/Module.symvers" % release,
            "/boot/Module.symvers-%s" % release,
        ]

    def resolve(self):
        for candidate in self.candidates():
            if os.path.isfile(candidate):
                return candidate
        return self.candidates()[0]

class OutputPathResolver:
    def __init__(self, ko_path, out_path):
        self.ko_path = ko_path
        self.out_path = out_path

    def resolve(self):
        if self.out_path:
            return self.out_path
        return self.ko_path

    def is_in_place(self):
        return os.path.abspath(self.resolve()) == os.path.abspath(self.ko_path)

class BackupManager:
    def __init__(self, ko_path):
        self.ko_path = ko_path

    def backup_path(self):
        return self.ko_path + ".bak"

    def create(self):
        destination = self.backup_path()
        shutil.copy2(self.ko_path, destination)
        log_info("backup written: " + destination)
        return destination

    def exists(self):
        return os.path.isfile(self.backup_path())

class ReportPrinter:
    def __init__(self, job):
        self.job = job

    def print(self):
        print("summary: versions=%d/%d vermagic=%s" % (
            self.job.updated_entries, self.job.total_entries, self.job.new_vermagic))
        if self.job.missing:
            print("summary: missing=%d" % len(self.job.missing))
        print("summary: original_vermagic=%s" % self.job.original_vermagic)
        print("summary: new_vermagic=%s" % self.job.new_vermagic)

class BatchProcessor:
    def __init__(self, directory, symvers_path, release):
        self.directory = directory
        self.symvers_path = symvers_path
        self.release = release
        self.ko_files = []

    def discover(self):
        self.ko_files = []
        if not os.path.isdir(self.directory):
            fail("batch directory not found: " + self.directory)
        for root, dirs, files in os.walk(self.directory):
            for name in files:
                if name.endswith(".ko"):
                    self.ko_files.append(os.path.join(root, name))
        self.ko_files.sort()
        log_info("batch discovered %d .ko files" % len(self.ko_files))
        return self.ko_files

    def run(self):
        self.discover()
        results = []
        for ko_path in self.ko_files:
            saved = dict(os.environ)
            try:
                os.environ["KO"] = ko_path
                os.environ["SYMVERS"] = self.symvers_path
                os.environ["OUT"] = ko_path + ".fixed"
                os.environ["UNAME_RELEASE"] = self.release
                job = FixVersionsJob()
                job.run()
                results.append((ko_path, True))
            except Exception as exc:
                log_error("batch failed for %s: %r" % (ko_path, exc))
                results.append((ko_path, False))
            finally:
                os.environ.clear()
                os.environ.update(saved)
        success = sum(1 for _, ok in results if ok)
        log_info("batch finished: %d/%d succeeded" % (success, len(results)))
        return results

def run_batch_if_requested():
    batch_dir = os.environ.get("BATCH_DIR", "")
    if not batch_dir:
        return False
    processor = BatchProcessor(
        batch_dir,
        env_first(["SYMVERS", "MODULE_SYMVERS"], "/lib/modules/%s/Module.symvers" % os.uname().release),
        os.environ.get("UNAME_RELEASE", os.uname().release))
    processor.run()
    return True

def main():
    if run_batch_if_requested():
        return
    if env_flag("SELF_TEST"):
        runner = SelfTestRunner()
        ok = runner.run()
        sys.exit(0 if ok else 1)
    parse_arguments(sys.argv[1:])
    job = FixVersionsJob()
    try:
        job.run()
    except FixVersionsError as exc:
        log_error(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        log_error("interrupted")
        sys.exit(130)
    except Exception as exc:
        log_error("unexpected failure: %r" % (exc,))
        sys.exit(1)

if __name__ == "__main__":
    main()
endef

FIX_VERSIONS_PY := $(FIX_VERSIONS_PY)
export FIX_VERSIONS_PY

.PHONY: help fix-versions
help:
	@echo "rwbridge kmod targets:"
	@echo "  all               Build module (requires KDIR)"
	@echo "  clean             Remove build artifacts"
	@echo "  check-universal   Static gate on rwbridge.ko"
	@echo "  fix-versions      Rewrite __versions CRCs + patch vermagic"
	@echo "  help              Show this help"
	@echo ""
	@echo "fix-versions variables:"
	@echo "  KO=PATH           input .ko (default rwbridge.ko)"
	@echo "  SYMVERS=PATH      Module.symvers (default /lib/modules/$$(uname -r)/Module.symvers)"
	@echo "  OUT=PATH          output .ko (default: in place)"
	@echo "  VERMAGIC=STR      override vermagic string"
	@echo "  UNAME_RELEASE=STR override kernel release"
	@echo "  ALLOW_MISSING=1   allow symbols without a CRC match"
	@echo "  DRY_RUN=1         parse only, do not write"
	@echo "  BACKUP=1          back up the original when patching in place"
	@echo "  VERBOSE=1         print ELF section details"

fix-versions:
	@KO="$(KO)" SYMVERS="$(SYMVERS)" OUT="$(OUT)" VERMAGIC="$(VERMAGIC)" UNAME_RELEASE="$(UNAME_RELEASE)" ALLOW_MISSING="$(ALLOW_MISSING)" DRY_RUN="$(DRY_RUN)" BACKUP="$(BACKUP)" VERBOSE="$(VERBOSE)" MODULE_NAME_LEN="$(MODULE_NAME_LEN)" python3 -c 'import os; exec(os.environ["FIX_VERSIONS_PY"])'
