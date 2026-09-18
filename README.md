# rwbridge — universal memory R/W kernel module (ARM64 Android, 5.10+)

One `.ko`, compiled **once**, loads on **any 5.10+ kernel**. Nothing
kernel-specific is baked in:

- **Kernel layout data ("offsets") arrives at runtime** via the `kopts`
  module param (`key=val,...`) at runtime: whatever the
  init-time scanner can't derive, the loader supplies. Absent keys
  self-derive on-device.
- **vermagic is resolved at runtime**: `run.sh` patches the baked
  placeholder to the running kernel in a temp copy, then `insmod`s it.
  If the kernel rejects the extras guess, dmesg names the exact string
  it wants and `run.sh` re-patches + retries once. No `--force`, ever.
  No per-KMI build matrix.
- **Zero log imports**: the module imports no printk-family symbol at
  all (diagnostics live in an in-module ring, readable via the `log`
  sysfs param). A kernel exporting no printk still loads fine.
- The hot path (TTBR0 switch + raw derefs) calls **no** version-drifted
  kernel helpers. Link-time imports: `module_layout` only
  (+ compiler mem* if emitted).

## Operations

Via the `rw` sysfs param (comma-separated; `addr` is a virtual address of
the target process), plus `status`/`out`/`stage`/`log` diagnostic params.
`kopts` carries runtime kernel data (writable live, honored at init):

```
R,pid,addr,size          read user VA; result as hex bytes in `out` (byte0 first)
W,pid,addr,size,value    write value to user VA (native-LE bytes)
P,cmdline-substr         find PID by process name substring
B,pid,libname            module base (use /proc/<pid>/maps as root instead)
```

`kopts` keys (dec or `0x`-hex; invalid values ignored, never fatal):

```
page_offset, phys_offset, va_bits (39|48), page_shift (12 only),
task_pid_off, task_mm_off, mm_pgd_off, task_tasks_off, task_comm_off,
mm_arg_start_off, mm_arg_end_off,
stability (1 = soak: load + idle, no scans),
readonly (1 = refuse all writes with -EROFS; reads fully work)
```

Bring-up order on a new kernel: `stability=1` soak (prove load + idle
safety) → `readonly=1` session (validate PA translation via reads
against ground truth) → full session (writes). `run.sh` takes them as
`RWBRIDGE_STABILITY=1` / `RWBRIDGE_READONLY=1` env passthrough.

Strict validation everywhere: `pid>0`, IN-APP-VA gate (target fully
inside user address space — NULL/wrap/kernel-spill refused), PTR-
PROTECTED-SYS gate (writes never touch kernel/system addresses; app VAs
are hardware-isolated and can at worst crash their own app, never the
system), `size` 1..256 (R) / 1,2,4,8 (W). Invalid input returns `-EINVAL`,
never oopses.
`page_shift != 12` refuses init cleanly (the walker is 4K-hardcoded) —
16K-page kernels are an explicit NO-GO, no panic.

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

Per-kernel kopts without editing the script:

```sh
su -c 'RWBRIDGE_KOPTS="task_pid_off=1400,task_mm_off=1416" sh ./run.sh'
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
- 16K-page kernels: init refuses cleanly (`page_shift` gate).
- CFI-enforcing kernels (`CONFIG_CFI_CLANG=y` in `/proc/config.gz`):
  kernel→module sysfs callbacks *may* trap on first access (single reboot
  worst case — nothing persists, no boot scripts). `run.sh` warns and
  continues; dmesg signature to confirm: `CFI failure`. The source needs
  no change for a future CFI flavor build (flags only).

## Diagnosis

- `cat /sys/module/rwbridge/parameters/status` — `ok` / `read err N` /
  `param err N`
- `cat .../parameters/out` — last read result
- `cat .../parameters/stage` — parse → pid_lookup → read/write → done
- `dmesg | grep rwbridge` — derivation log (`... (kopt)` marks
  runtime-supplied values), kopts state at load
