# memd — process memory inspection toolkit

Three components for reading/writing process memory on Android, with
increasing levels of stealth:

| Component | File | Access path | Traces |
|-----------|------|-------------|--------|
| **memd_kern** | `memd_kern.c` | direct phys via `/dev/memd` (memremap) | only the ioctl syscall |
| **debugd_unsafe** | `memd_us.c` | `/proc/<pid>/mem` over Unix socket | fd/, strace, audit |
| **memtool** | `memd_dump.c` | auto-selects: /dev/memd or /proc/pid/mem | per read path |

## Kernel module — `/dev/memd`

Reads/writes physical RAM via `memremap()`. No PID, no task_struct,
no ptrace, no kernel log output. The only observable activity is the
`ioctl()` on `/dev/memd`.

```
struct memd_req {
    uint64_t phys_addr;
    uint32_t size;
    uint8_t  write;       // 0 = read, 1 = write
    uint64_t user_buf_ptr;
} __attribute__((packed));

ioctl(fd, MEMD_IOC_XFER, &req);   // returns bytes transferred
write(fd, &req, sizeof(req)+payload);  // alternative for writes
```

## Userspace daemon — `debugd_unsafe`

SYSCALL-MODE FALLBACK. Uses `/proc/<pid>/mem` which leaves traces.
Authenticated via `SO_PEERCRED` (shell UID 2000 only). Section-gated:
only `r-xp` and anonymous mappings readable; writes to code sections
denied.

```
[pid:4LE][address:8LE][size:4LE][mode:1]  →  raw data or error
mode 0 = read, mode 1 = write
```

## CLI tool — `memtool`

```
memtool ps                   list processes
memtool maps <pid>           show memory mappings
memtool libs <pid>           show loaded libraries
memtool va2pa <pid> <vaddr>  virtual → physical
memtool phys <paddr> <len>   read physical memory (needs /dev/memd)
memtool read <pid> <addr> <len>     read via best available path
memtool offset <pid> <lib> <off> <len>  read at library+offset
```

## Build locally

```
./build.sh                  # builds debugd_unsafe + memtool for aarch64
```

## CI builds

The GitHub Action builds `memd_kern.ko` for three GKI branches:

- `android14-5.15`
- `android14-6.1`
- `android15-6.6`

Artifacts: `memd_kern-<branch>.ko`, `debugd_unsafe`, `memtool`.
