# rwbridge — universal memory R/W kernel module (ARM64 Android, 5.10+)

One `.ko`, compiled **once**, loads on **any 5.10+ kernel**. Nothing
kernel-specific is baked in:

- **Kernel layout data ("offsets") arrives per-op as arguments** to the
  `E`/`Y` ops (explicit, stateless — see "Bring-up on a new kernel").
  No per-KMI tables, no blind discovery sweeps in the hot path.
- **vermagic is resolved at runtime**: `run.sh` patches the baked
  placeholder to the running kernel in a temp copy, then `insmod`s it.
  If the kernel rejects the extras guess, dmesg names the exact string
  it wants and `run.sh` re-patches + retries once. No `--force`, ever.
  No per-KMI build matrix.
- **Zero log imports**: the module imports no printk-family symbol at
  all (diagnostics live in an in-module ring, readable via the `log`
  sysfs param). A kernel exporting no printk still loads fine.
- Link-time imports: `module_layout` + compiler `mem*` if emitted,
  `copy_from_kernel_nofault` (linear-map reads, stable forever),
  `param_ops_int` (stability/readonly flags use the kernel's own int
  handlers — zero custom parse code, ABI frozen 15+ years).
- Page-table geometry (4K/16K/64K pages; 36/39/42/47/48-bit VA) is
  explicit per-op too, with refuse-on-mismatch semantics (never
  mis-walks).

## Operations

Via the `rw` sysfs param, plus `status`/`out`/`stage`/`log` diagnostic
params and `stability`/`readonly` session flags (plain kernel int
params, set at insmod or live via sysfs):

```
E,pid,addr,size,pid_off,tasks_off,mm_off,pgd_off,page_off,phys_off[,owner[,pshift,vabits]]
                                  stateless read; hex bytes in `out`
Y,<same>[,owner[,pshift,vabits]],value
                                  stateless write (1..8 bytes, native-LE hex)
V,byteoff,hexval                  verify one u32 at cur_task+off (sync validation)
F,hexaddr                         single guarded read at absolute kernel VA
Q,hihex,lohex,offhex              absolute read via hi/lo halves (32-bit shells)
C,pid,pid_off,tasks_off,mm_off,owner
                                  owner-validated pid→task census (reports base)
D                                 stateless tasks-list proof sweep (report-only)
S,0..7                            single derive steps (legacy path)
R,pid,addr,size / W,...           legacy cached derive path (4K-only)
T                                 bare TTBR0-read probe (hypervisor-trap check)
N / G / K                         retired bisect ops (kept, inert)
P,cmdline-substr                  find PID by process name substring
B,pid,libname                     module base (use /proc/<pid>/maps as root instead)
```

Conventions: `pid`/`size`/shifts dec; addresses and offsets hex
(`5d8` = 1496). Every op reports in `status` (`0` = ok, negative errno
otherwise) with stage breadcrumbs in `stage` and hex/text in `out`.
`Y` (and legacy `W`) in a `readonly=1` session refuse with `-EROFS`.

Strict validation everywhere: `pid>0`, IN-APP-VA gate (target fully
inside user address space — NULL/wrap/kernel-spill refused),
`size` bounds, offset range checks, page-table geometry combo check,
page_off↔VA-size consistency check. Invalid input returns `-EINVAL`
(or the specific errno), never oopses.

## Bring-up on a new kernel

Offsets are per-kernel constants, derived once with safe single reads
(`F`/`V`/`Q` — no sweeps, no walks) plus offline analysis, then passed
explicitly forever after. Proven recipe (see project history):

1. `S,0` → `cur_task` + `ttbr0` for a live writer.
2. `V,<off>,<own-pid-hex>` across `task_struct` to confirm `pid_off`
   (match = offset proven for that writer).
3. Adjacent-equal-pair + pointer-shape analysis (offline) for
   `tasks`/`mm` candidates; `V`-verify each.
4. Walk one `mm_struct` with `F` (batched, single reads): `task_size`,
   `pgd`, `owner` coherence identifies `mm` and `pgd_off`.
5. `phys_off = (ttbr0 & PA-mask) − (pgd_va − page_off)` (offline math).
6. `page_off` from VA high bits (39/48-bit bases; 16K kernels: pass
   explicit geometry).
7. Prove end-to-end: `E` read of a known mapping (ELF magic) +
   `Y` write with `E` readback, both against ground truth.

Bring-up order: plain session (prove load + idle safety) →
`readonly=1` session (validate translation via reads against ground
truth) → full session (writes). `run.sh` takes them as
`RWBRIDGE_STABILITY=1` / `RWBRIDGE_READONLY=1` env passthrough
(translated to `stability=`/`readonly=` insmod args).

## Install

`run.sh` + `rwbridge.ko` side by side (the CI artifact), root required:

```sh
su -c 'sh ./run.sh'
su -c "echo 'R,1234,0x7ff9a00000,8' > /sys/module/rwbridge/parameters/rw"
su -c "cat /sys/module/rwbridge/parameters/out"
su -c "cat /sys/module/rwbridge/parameters/stage"   # breadcrumb on failure
```

Every run also surveys printk-family exports (informational only) and
saves a session log to `/sdcard/MemoryD/<next>.log` (`<next>` = one past
the highest existing number: `0.log`, then `1.log`, ...) containing the
module `log` ring, stage/status, candidates, and dmesg lines. If the
kernel exports no printk at all, this file — not dmesg — is the log.

Per-kernel tables live wherever *you* keep them (a shell associative
array, a JSON file, the backend) — the module takes them per-op, so no
file in this repo pins a kernel. Example session:

```sh
su -c "echo 'E,4123,7f3a9000,16,5d8,4d0,520,40,ffffff8000000000,500000000,70' > /sys/module/rwbridge/parameters/rw"
```

## Build (once)

Against **any** prepared arm64 tree 5.10+ (CI uses 5.10 = oldest, which
proves no newer-only API is used). Tree config must have MODVERSIONS off
(GKI default) so the build emits no `__versions` section:

```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=$LINUX_TREE
make CROSS_COMPILE=aarch64-linux-gnu- check-universal
```

`check-universal` fails the build if the module grew `__versions`,
unexpected imports, or lost its vermagic placeholder. The placeholder
release is baked at exactly 63 chars (UTS cap), so every real target
vermagic fits the in-place runtime patch.

## Explicit NO-GO list (no code fixes these — documented, not silent)

- `CONFIG_MODULES=n` kernels: nothing to insmod. Fail is at `insmod`.
- Module-signature enforcement (`CONFIG_MODULE_SIG_FORCE` + no trusted
  key): load refused by the kernel. Unsigned single build by design.
- Kernels **with** MODVERSIONS enabled: our CRC-less imports are refused.
  (Effectively no Android GKI/vendor kernel — noted for completeness.)
- 16K/64K kernels: supported *only* via explicit E/Y geometry
  (`page_shift` 14/16 + matching `va_bits`); the legacy derive path
  stays 4K-only and refuses anything else cleanly. No 16K runtime
  verification exists yet in this project — the contract is
  build-verified (CI) and refuse-on-mismatch by construction.
- CFI-enforcing kernels (`CONFIG_CFI_CLANG=y` in `/proc/config.gz`):
  every kernel→module sysfs access and `rmmod`/exit trap deterministically
  (each op reboots, not just the first). `run.sh` warns and continues;
  without `pstore`/ramoops the panic string is lost on reboot (dmesg does
  not survive), so the config flag itself is the diagnosis. The source
  needs no change for a future CFI flavor build (flags only).

## Loader-contract map (proven 2026-09-20, `6.1.23-android14-4-...` AVD)

Same kernel, transplant-patched probes (8-byte entry-head rewrites on a
CI-built `.ko` with binutils nm/readelf/objdump + python3 — entry offsets
resolved per-file via nm, never hardcoded; no kernel tree, no extra files):

- `init_module` is NEVER called: spin-init loads instantly, nonzero-init
  still goes Live. Symtab is processed (symbols in kallsyms), params are
  created, state is Live — everything except init execution. Consequence:
  init is best-effort everywhere; all real work (derivation included) must
  be lazy on first op, never eager at init.
- `cleanup_module` / `rmmod` path kills even with a trivial body: the exit
  call path itself is enforced, not the exit code.
- Param show/store kill even with trivial import-free bodies (`stage`
  read: pure copy loop); kernel-only paths (`coresize`, write-only `rw`
  read → `-EACCES`, loaded idle) always survive. Enforcement sits at the
  sysfs caller, not in our code.
- Hand-built (non-kbuild) ELFs are NOT a probe vehicle: identical files
  fail `EPERM` in one boot and `ENOEXEC` in the next (missing kbuild-isms
  such as `__this_module`); transplant-patching the CI artifact is the
  reliable probe method.

## What is possible / not possible on CFI kernels (research-backed)

Mechanism (LLVM KCFI, arm64: `ldur w16,[xN,#-4]; movz/movk w17,#hash;
cmp; b.eq ok; brk#0x8228; blr xN` — AOSP/LPC docs): every indirect call
in kernel code checks the 4 bytes before the target for the expected
type hash. Uninstrumented callees always mismatch → `brk` → `CFI
failure` → panic (non-permissive; permissive mode is prod-forbidden per
AOSP). Consequences, each verified or documented:

- POSSIBLE, standalone: load + Live + params + kernel-only attr reads;
  vermagic patching (`run.sh`); transplant probes (`tools/`);
  uname/config.gz/kallsyms/sysfs/cmdline reads.
- NOT POSSIBLE, standalone: executing any module callback (the check is
  at the kernel caller — no source change can satisfy it; needs a
  CFI-instrumented build from CI, flags only, no logic change).
- NOT POSSIBLE, standalone: reading the panic string (no pstore here;
  reboot clears dmesg — the config flag is the diagnosis); `initcall_debug`
  or cmdline changes (no bootloader control); forcing imports/symbols
  (kernel-owned: `EPERM`/`ENOEXEC`/`Unknown symbol`); printk in the
  product (import doctrine — test builds excepted).
- OPEN: why the init call never arrives here (symbol resolves per
  kallsyms, call missing; cmdline has no blacklist entries). Needs a CFI
  build to bisect (tolerant-skip vs dropped error) — same build that
  fixes operations, so one vehicle answers both.

## Diagnosis

- `cat /sys/module/rwbridge/parameters/status` — `0` / negative errno
- `cat .../parameters/out` — last result (hex)
- `cat .../parameters/stage` — breadcrumb of the last op's failing
  phase (`parse`, `eread`/`ewrite`, `ex-task`, `ex-mm`, `ex-pgd`, `ok`)
- `dmesg | grep rwbridge` — boot lines (empty: zero-import logging;
  use the `log` param instead)
- `cat .../parameters/log` — the in-module ring (primary channel)
- The `kopts` param is retired (always `-EPERM`, get shows last
  rejected string); it is not a diagnostic surface anymore.
