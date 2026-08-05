# rwbridge — self-contained memory R/W kernel module (ARM64 Android)

A minimal, hard-rule kernel module: the kernel's **only** job is to load it.
No `kallsyms`, no `find_task_by_vpid`/`get_task_mm`/`mmput`/`access_remote_vm`,
no `filp_open`/`kernel_write`, no `current->*` helpers, no page-walk helpers.
Everything is done inside the module:

1. **Find the process:** `arm64 current == sp_el0` (CONFIG_THREAD_INFO_IN_TASK).
   Walk `task_struct.tasks` (circular list) and match `->pid`.
2. **VA→PA:** walk the page table anchored at `mm->pgd`
   (arm64, 4K pages; 3 levels @ 39-bit VA or 4 levels @ 48-bit VA).
3. **Access RAM:** through the linear map (`phys_to_virt(pa) =
   (pa - PHYS_OFFSET) | PAGE_OFFSET`), so no TTBR0 switch is needed and the
   access is cache-coherent. `PHYS_OFFSET` is derived at runtime from the
   current task's own `mm->pgd` (VA) vs `TTBR0_EL1` (PA) — no kallsyms.

Link-time imports: `module_layout`, `_printk` only.

## Universal across kernel majors

GKI does **not** make one `.ko` work across majors: `uname -r`/vermagic
differs between 5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18, and `task_struct`/
`mm_struct` field offsets are **not** part of the GKI stable-KMI surface. So:

- The module resolves **all** layout constants from the target kernel's **own
  headers at build time** — `offsetof(struct task_struct, …)`,
  `offsetof(struct mm_struct, pgd)`, `PAGE_OFFSET`/`TASK_SIZE` from
  `asm/memory.h`, and the pgtable shifts from `asm/pgtable-hwdef.h`. There is
  **no offsets file** and no CI-generated constants: whichever kernel tree you
  build against, you get that kernel's correct layout (3- or 4-level walk).
- CI (`.github/workflows/build.yml`) builds **one `.ko` per kernel major**
  against that kernel's own source/CRCs + **one** additional build for the
  BlueStacks (bst) emulator's vendor kernel (`5.15.137-v5.21.770-optimizations-
  5.21.771.4051`) — the same 5.15.137 base but with the vendor `LOCALVERSION`
  so vermagic matches, and a hand-written `Module.symvers` whose CRCs were
  extracted from the device's own modules' `__versions` sections (a stock
  vmlinux build can't reproduce the vendor config's CRCs).
- `build.sh` bundles every `kmod_bin/rwbridge-*.ko` into `dist/run.sh`.
- `run.sh` extracts them and `insmod`s the one whose **vermagic matches** the
  target device (kernel CRC check refuses mismatches) — no `--force`, no
  vermagic patching, no panic risk. It also **skips** any `.ko` whose module
  name is already loaded, so a user who preloaded their own build is left
  alone.

Do **not** try to force one `.ko` onto a different major.

## Operations

Via the `rw` sysfs param (comma-separated; `addr` is a virtual address of
the target process), plus `status`/`out`/`stage` diagnostic params:

```
R,pid,addr,size          read user VA; result as hex bytes in `out` (byte0 first)
W,pid,addr,size,value    write value to user VA (native-LE bytes)
```

Strict validation: `pid>0`, `addr!=0 && addr<0x8000000000`, no wraparound,
`size` 1..256 (R) / 1,2,4,8 (W). Out-of-window page-table entries are
rejected (`lxgr_safe_virt`) so a stale descriptor can never fault the kernel.

## Build (CI / per-kernel)

Out-of-tree; needs the prepared kernel tree for the target:

```
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=$LINUX_TREE
```

The module reads all layout constants (`offsetof`, `PAGE_OFFSET`, `TASK_SIZE`,
pgtable shifts) from the headers of whatever `KDIR` you point it at, so just
build against the exact kernel your device runs. To build for a device whose
kernel is not one of the 6 stock majors, point `KDIR` at that kernel's source
tree — for the BlueStacks emulator, the `5.15-vendor` CI job does this
automatically (5.15.137 source + the device's own CRCs + matching
`LOCALVERSION`).
