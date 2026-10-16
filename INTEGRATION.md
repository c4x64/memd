# DSU driver contract surface (verified, read-only)

Source of truth: `/client.h` and `/memd.hpp` at the repo root, plus the
matching kernel-side declarations in `kmod/memd/ioctl/memd_ioctl.h` and
`kmod/memd/utils/memd_inject.h` (same structs/macros, LP64-identical by
construction). This file enumerates ONLY what those headers define — no
invented APIs. Sizes are
LP64 (arm64, 8-byte pointers; verified against `memd.hpp` static_asserts
where present and C layout rules otherwise).

Transport (from `client.h` `memd_open`): scan socket families for the
driver's `SEQPACKET -> ENOKEY` marker, then open `RAW` on it. Returns an fd
or `-1` (`errno` set). All ioctls below issue on that fd, except the
`'B'` bindproc ioctls which issue on the anon fd from `BIND_PROC`.

## Ioctl numbers 38/39/40/41/42/43

| nr | Macro | Struct | Size (LP64) | Direction |
|----|-------|--------|-------------|-----------|
| 38 | `MEMD_IOCTL_LOAD_SOTOAPP` `_IOWR('W', 38, struct memd_loadso_cmd)` | `struct memd_loadso_cmd` | 352 | app -> driver -> target |
| 39 | `MEMD_IOCTL_LOAD_SOSUTOAPP` `_IOWR('W', 39, struct memd_loadso_cmd)` | `struct memd_loadso_cmd` | 352 | app -> driver -> target |
| 40 | `MEMD_IOCTL_BOOTSTRAP` `_IOWR('W', 40, struct memd_bootstrap_cmd)` | `struct memd_bootstrap_cmd` | 32 | app -> driver (once per install) |
| 41 | `MEMD_IOCTL_LOADSO_UNLOAD` `_IOWR('W', 41, struct memd_loadso_unload_cmd)` | `struct memd_loadso_unload_cmd` | 24 | app -> driver -> target |
| 42 | `MEMD_IOCTL_VERSION` `_IOWR('W', 42, struct memd_version_cmd)` | `struct memd_version_cmd` | 28 | query |
| 43 | `MEMD_IOCTL_LEARN_STATUS` `_IOWR('W', 43, struct memd_learn_status_cmd)` | `struct memd_learn_status_cmd` | 44 | query |

### `struct memd_loadso_cmd` (352 B) — nr 38/39

```c
struct memd_loadso_cmd {
    pid_t    pid;          /* Input: target process (or thread) ID */
    char     path[256];    /* Input: absolute .so path, NUL-terminated */
    char     entry[64];    /* Input: symbol to call after dlopen ("" = skip) */
    int      flags;        /* Input: MEMD_LOADSO_* bits */
    int      result;       /* Output: 0 ok, else -errno */
    uintptr_t handle;      /* Output: dlopen handle (0 if ephemeral/failed) */
    int      entry_result; /* Output: entry return, truncated to int */
};
#define MEMD_LOADSO_EPHEMERAL 1
```

### `struct memd_bootstrap_cmd` (32 B) — nr 40

```c
struct memd_bootstrap_cmd {
    uint64_t filp_open;   /* Input: kernel address of filp_open */
    uint64_t kernel_read; /* Input: kernel address of kernel_read */
    uint64_t filp_close;  /* Input: kernel address of filp_close */
    int32_t  result;      /* Output: 0 ok, else -errno */
};
```

### `struct memd_loadso_unload_cmd` (24 B) — nr 41

```c
struct memd_loadso_unload_cmd {
    pid_t     pid;     /* Input: target process (or thread) ID */
    uintptr_t handle;  /* Input: dlopen handle; zeroed on success */
    int       result;  /* Output: 0 ok, else -errno */
};
```

### `struct memd_version_cmd` (28 B) — nr 42

```c
#define MEMD_ABI_VERSION 1
#define MEMD_VERSION_MAJOR 1
#define MEMD_VERSION_MINOR 0
#define MEMD_VERSION_PATCH 0
#define MEMD_F_BOOTSTRAP_DONE 1
#define MEMD_F_LEARNED_OFFSETS 2
struct memd_version_cmd {
    uint32_t abi;    /* Input: must equal MEMD_ABI_VERSION */
    uint32_t major;  /* Output: driver version */
    uint32_t minor;  /* Output */
    uint32_t patch;  /* Output */
    uint32_t flags;  /* Output: MEMD_F_* capability/boot-state bits */
    int32_t  gen;    /* Output: learned generation index, or -1 */
    int32_t  result; /* Output: 0 ok, else -errno */
};
```

### `struct memd_learn_status_cmd` (44 B) — nr 43

```c
struct memd_learn_status_cmd {
    int32_t  gen;     /* Output: learned generation index, or -1 */
    int32_t  t_pid;   /* Output: task_struct.pid offset, or -1 */
    int32_t  t_tgid;  /* Output: task_struct.tgid offset, or -1 */
    int32_t  t_mm;    /* Output: task_struct.mm offset, or -1 */
    int32_t  t_cred;  /* Output: task_struct.cred offset, or -1 */
    int32_t  v_start; /* Output: vm_area_struct.vm_start offset, or -1 */
    int32_t  v_end;   /* Output: vm_area_struct.vm_end offset, or -1 */
    int32_t  v_flags; /* Output: vm_area_struct.vm_flags offset, or -1 */
    int32_t  m_pgd;   /* Output: mm_struct.pgd offset, or -1 */
    uint32_t mask;    /* Output: learned-bits, t_pid=bit0 ... m_pgd=bit7 */
    int32_t  result;  /* Output: 0 ok, else -errno */
};
```

## Bootstrap flow (per `client.h`)

1. Probe driver identity FIRST: `memd_get_version(fd, &out)` — fills `abi =
   MEMD_ABI_VERSION`, fails closed on mismatch so old userspace never misreads
   a newer wire format. Check `flags & MEMD_F_BOOTSTRAP_DONE`.
2. Deliver file-helper addresses ONCE per install: `memd_bootstrap(fd,
   filp_open, kernel_read, filp_close)` — all three must be nonzero kernel
   addresses. Userspace reads them from `/proc/kallsyms` (after lowering
   `kptr_restrict`). `result == 0` on success, else `-errno`.
3. `memd_get_learn_status` is the observability snapshot for offset learning
   (`gen`, per-field offsets, `mask` bit i = i-th field learned).

## loadsotoapp vs loadsosutoapp semantics (per `client.h`)

- `loadsotoapp` (nr 38): `dlopen(path)` inside the target, no credential
  changes. Thin wrapper: `memd_load_so(fd, pid, path, entry, su=0, ...)`.
- `loadsosutoapp` (nr 39): same, but uid 0 + all capabilities for the
  duration of the `dlopen` call only (`euid`/`fsuid` untouched — see kmod
  header), then restored. Wrapper: `su != 0`.
- Both validate: `pid > 0`, `path` absolute and `< 256`, `entry` (if given)
  `< 64` and containing no `/`. `entry == ""` means skip the entry call.
- `MEMD_LOADSO_EPHEMERAL` (`ephemeral != 0`): driver `dlclose`s after init so
  the linker itself unloads the library (traceless-by-unload); `handle`
  output is then 0.
- nr 41 unload: remote `dlclose(handle)` in the target; zeroes handle on
  success (hotswap primitive). Hotswap = load new persistent library + run
  entry + `dlclose` old handle (`memd_hotswap_so`).

## `memd.hpp` module entry ABI

- Entry symbol name: `LXGR_ENTRY_NAME "lxgr_main"` (`LXGR_VERSION_* 1.0.0`).
- Signature: `typedef int (*lxgr_entry_fn)(uintptr_t dlopen_handle);`
  defined as `extern "C" inline int lxgr_main(uintptr_t dlopen_handle)`,
  which boots the registered module (`zygisk::detail::boot_module`:
  `onLoad` then back-to-back pre/post specialize with best-effort live args).
- The `entry[64]` field of `memd_loadso_cmd` carries this symbol name for
  MEMD/Zygisk-scheme modules; the injector calls `entry(handle)` with the
  `dlopen` handle in `x0`.
- `REGISTER_MEMD_MODULE(cls)` / `REGISTER_ZYGISK_MODULE(cls)` (aliased)
  install the factory; `onUnload` is reserved and never invoked.

## Hide / install / status / unload call contracts (ops 14/21/22/38/39/40/41/42/43)

Read-only summary of `client.h` at the repo root, `kmod/memd/ioctl/memd_ioctl.h`,
and `kmod/memd/utils/memd_inject.h`. No invented APIs. Sizes are LP64
(arm64: 4-byte `int`/`pid_t`, 8-byte pointers/`uint64_t`; `pid_t` = 4 B).

| nr | Macro (`client.h` / `memd_ioctl.h`) | Struct | Size (LP64) | Direction |
|----|-------------------------------------|--------|-------------|-----------|
| 14 | `MEMD_IOCTL_HIDE_PROCESS` `_IOWR('W', 14, struct memd_hide_proc_cmd)` | `struct memd_hide_proc_cmd` | 8 | app -> driver |
| 21 | `MEMD_IOCTL_HIDE_STATUS` `_IOWR('W', 21, struct memd_hide_status_cmd)` | `struct memd_hide_status_cmd` | 8 | query |
| 22 | `MEMD_IOCTL_HIDE_INSTALL` `_IOWR('W', 22, struct memd_hide_install_cmd)` | `struct memd_hide_install_cmd` | 8 | app -> driver |
| 38 | `MEMD_IOCTL_LOAD_SOTOAPP` `_IOWR('W', 38, struct memd_loadso_cmd)` | `struct memd_loadso_cmd` | 352 | app -> driver -> target |
| 39 | `MEMD_IOCTL_LOAD_SOSUTOAPP` `_IOWR('W', 39, struct memd_loadso_cmd)` | `struct memd_loadso_cmd` | 352 | app -> driver -> target |
| 40 | `MEMD_IOCTL_BOOTSTRAP` `_IOWR('W', 40, struct memd_bootstrap_cmd)` | `struct memd_bootstrap_cmd` | 32 | app -> driver (once per install) |
| 41 | `MEMD_IOCTL_LOADSO_UNLOAD` `_IOWR('W', 41, struct memd_loadso_unload_cmd)` | `struct memd_loadso_unload_cmd` | 24 | app -> driver -> target |
| 42 | `MEMD_IOCTL_VERSION` `_IOWR('W', 42, struct memd_version_cmd)` | `struct memd_version_cmd` | 28 | query |
| 43 | `MEMD_IOCTL_LEARN_STATUS` `_IOWR('W', 43, struct memd_learn_status_cmd)` | `struct memd_learn_status_cmd` | 44 | query |

Number-sharing note (verbatim from `client.h`): "nr 21/22/23 are shared
across features (e.g. HIDE_STATUS and HWBP_INFO are both nr 21), but the
full _IOWR codes differ via the struct-size field — verified mechanically,
no dispatch collision." The app must always use the full `MEMD_IOCTL_*`
macro, never a bare number.

### `struct memd_hide_proc_cmd` (8 B) — nr 14

```c
struct memd_hide_proc_cmd {
    pid_t pid;  /* Input: Process ID */
    int   hide; /* Input: 1 to hide, 0 to unhide */
};
```

Per-header contract: `pid` selects the process, `hide = 1` adds it to the
hidden set, `hide = 0` removes it. `client.h` provides no thin wrapper for
this op — issue `MEMD_IOCTL_HIDE_PROCESS` directly on the driver fd.
App policy (owner override 2026-10-16, see `BLOCKERS.md`): any future UI
wiring MUST be an explicit, visible, user-initiated action with
explanatory copy — never silent, never by default. Not yet bridged in
`native/memd_bridge.c` (five bridged calls only: version, learn-status,
bootstrap, load, unload).

### `struct memd_hide_status_cmd` (8 B) — nr 21

```c
struct memd_hide_status_cmd {
    int active;       /* Output: 1 if the getdents64 filter is installed */
    int hidden_count; /* Output: pids currently in the hidden set */
};
```

Read-only snapshot. No wrapper in `client.h`; issue
`MEMD_IOCTL_HIDE_STATUS` directly.

### `struct memd_hide_install_cmd` (8 B) — nr 22

```c
struct memd_hide_install_cmd {
    int install; /* Input: 1 install, 0 uninstall */
    int result;  /* Output: 0 ok, negative errno on failure */
};
```

Installs/uninstalls the `getdents64` filter the nr-14 hiding relies on.
No wrapper in `client.h`; issue `MEMD_IOCTL_HIDE_INSTALL` directly.
Same explicit-user-action-only policy as nr 14.

### Install / status / unload wrappers (`client.h` thin typed wrappers)

- Install: `memd_load_so(fd, pid, path, entry, su, ephemeral, &handle,
  &entry_result)` → nr 38 (`su == 0`) / nr 39 (`su != 0`). Guards:
  `pid > 0`, `path` absolute and `< 256` (`sizeof(path)`), `entry` (if
  non-empty) `< 64` and containing no `/`; `entry == ""`/NULL skips the
  entry call. `ephemeral != 0` sets `MEMD_LOADSO_EPHEMERAL`. Returns
  `0` ok / `-errno`; `handle` + `entry_result` via out-params
  (`entry_result` valid only when entry was requested). `0` ok with
  `cmd.result < 0` returns `cmd.result`.
- Status (identity): `memd_get_version(fd, &out)` — fills `abi =
  MEMD_ABI_VERSION`, fails closed on mismatch (see VERSION semantics
  below). Status (offsets): `memd_get_learn_status(fd, &out)` — fills
  `gen` + per-field offsets + `mask` (see LEARN_STATUS semantics below).
  Both return `0` ok / `-errno`, and propagate `cmd.result` when negative.
- Unload: `memd_unload_so(fd, pid, handle)` → nr 41. Guards: `fd >= 0`,
  `pid > 0`, `handle != 0`. Returns `0` ok / `-errno`, else `cmd.result`.
  Driver zeroes the handle on success. Hotswap primitive:
  `memd_hotswap_so(fd, pid, old_handle, path, entry, su, &new_handle,
  &entry_result)` = load-new (persistent) + run entry, then `dlclose`
  old handle; on unload failure the new library stays resident and its
  handle is returned.

### VERSION / LEARN_STATUS app semantics (what the app must do)

- Probe FIRST: `memd_get_version` before any install/load/bootstrap.
  Set `abi = MEMD_ABI_VERSION` (1); a mismatch fails closed so old
  userspace never misreads a newer wire format. `isCompatible()` in
  `core/DriverCaps.java` is exactly `abi == 1`.
- `major.minor.patch` = driver version (`1.0.0` constants
  `MEMD_VERSION_MAJOR/MINOR/PATCH` in both headers). Display verbatim;
  never compare as a float.
- `flags`: bit 0 `MEMD_F_BOOTSTRAP_DONE` (1) = file-helper addresses
  already delivered; bit 1 `MEMD_F_LEARNED_OFFSETS` (2) = offset learning
  complete. Unknown bits are preserved and shown numerically (see
  `DriverCaps.describe()`), never dropped. Bootstrap delivery (nr 40,
  `memd_bootstrap(fd, filp_open, kernel_read, filp_close)`, all three
  nonzero) is once per install — skip when `BOOTSTRAP_DONE` is set.
- `gen`: learned generation index, or `-1` = unknown. `-1` is valid data
  (driver not yet learned), not an error.
- LEARN_STATUS: observability snapshot only — `gen`, eight ordered offset
  fields (`t_pid`, `t_tgid`, `t_mm`, `t_cred`, `v_start`, `v_end`,
  `v_flags`, `m_pgd`, each `-1` = unknown), `mask` (bit i = i-th field
  learned, `t_pid` = bit0 … `m_pgd` = bit7), `result` (`0` ok, else
  `-errno`). The app surfaces unknown (`-1` / clear bit) fields as
  "not learned", never as zero offsets.
