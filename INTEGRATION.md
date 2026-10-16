# DSU driver contract surface (verified, read-only)

Source of truth: `/client.h` and `/memd.hpp` at the repo root. This file
enumerates ONLY what those headers define — no invented APIs. Sizes are
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
