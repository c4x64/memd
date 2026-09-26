# rwbridge — per-KMI memory R/W driver (ARM64 Android, 5.10+)

One packed deliverable (`rwbridge-spx`) carrying **8 per-generation
artifacts**; the loader matches `uname -r` numerically and installs the
right one. Driver core derived from fuqiuluo/android-wuwa (socket
transport, page-table walk, phys R/W, kallsyms resolution, CFI-disable);
inline hooks are never used, hide paths are compiled out, procfs/dmabuf
transports are excluded. Process-hide is a tracked TODO, not present.

- **8 builds, 1 deliverable.** DDK matrix
  (`android12-5.10`, `android13-5.10`, `android13-5.15`,
  `android14-5.15`, `android14-6.1`, `android14-6.1-dbg`,
  `android15-6.6`, `android16-6.12`); each artifact matches its own
  generation's headers. The `-dbg` variant is a forensics build of the
  6.1 artifact (debug info kept): never auto-selected, loaded only by
  explicit `--ko a14-6.1-dbg` (SPX) or explicit path (run.sh).
  Vendor variance inside a generation (UTS suffixes) is absorbed by the
  vermagic placeholder + install-time patch (dmesg-feedback retry).
  Cross-generation attempts are refused outright (wrong structs would
  mis-walk — strictly worse than not loading). No `--force`, ever.
- **CFI is handled at runtime**: `cfi_bypass()` patches the CFI check
  functions after load (kallsyms-resolved, RET fill). No separate CFI
  artifact, no flavor switch, no dispatch-slot surgery (matched builds
  need none).
- **5.10/5.15 builds carry no kprobe trick** (`WUWA_NO_KPROBE_TRICK`):
  vendor 5.x kernels neither export kprobes nor tolerate the weak
  references (their loaders reject GOT-page relocs 311/312 outright —
  proven on Samsung 5.15: `unsupported RELA relocation`). Plain R/W
  needs no kallsyms and init fails soft per-op, so these load Live
  where resolution is impossible. 6.x keeps the trick (GKI exports
  kprobes; upstream loaders tolerate weak refs).
- **Enforcing + 5.x is refused, never trapped**: SPX and run.sh read
  `/proc/config.gz`; `CONFIG_CFI_CLANG=y` with a 5.x flavor is a NO-GO
  (the bypass could never run there — a load would trap on first use).
  Unknown config proceeds as before.
- **OEM struct-module skew is fixed at install time**: some OEM kernels
  (proven: Samsung 5.15) ship a modified `struct module` whose .init/.exit
  sit at different offsets than upstream (Samsung +0x170/+0x348 vs
  upstream +0x178/+0x378). With upstream offsets the loader reads a NULL
  .init, skips init, yet reports Live — a silent, socketless module (this
  cost a full investigation: file, loader, relocs, versions, objcopy,
  codegen, and name were all eliminated first). SPX and run.sh learn the
  target offsets from an on-device vendor `.ko` (ELF-parsed,
  symbol-matched to `init_module`/`cleanup_module`, never hardcoded) and
  rewrite the artifact's this_module relocs before insmod. No vendor
  reference on device -> upstream offsets (GKI/Pixel need no shift).
- **Symbols resolve at runtime** (kprobe trick on
  `kallsyms_lookup_name`); unresolvable kernels fail closed at init
  (return code, never half-alive).
- **Init is load-bearing** (socket server + resolution + CFI patch must
  run): unlike the previous sysfs design, there is no useful
  degraded state, so init failure refuses the load instead of going
  silent-Live.
- **Logging via printk** (`wuwa_info/err`): GKI trees always export it
  and each artifact is verified against its own generation's System.map
  by the gate. Kernels without the import surface are an explicit
  NO-GO (below), never a silent break.

## Client contract (product path: socket)

No device node, no sysfs params. The driver registers a socket family
(first free from `AF_DECnet`); discover it by probing families with
`SOCK_SEQPACKET` (driver answers `-ENOKEY`) then opening `SOCK_RAW`.
All commands are `ioctl()`s on that fd (see `kmod/wuwa/ioctl/`):

```
WUWA_IOCTL_READ_MEMORY / WRITE_MEMORY (phys, arbitrary size)
WUWA_IOCTL_ADDR_TRANSLATE / AT_S1E0R  (VA translation)
WUWA_IOCTL_DEBUG_INFO                 (TTBR0/task/mm/pgd — bring-up)
WUWA_IOCTL_GET_MODULE_BASE / FIND_PROCESS / IS_PROCESS_ALIVE
WUWA_IOCTL_PAGE_INFO / PAGE_TABLE_WALK / PTE_MAPPING
WUWA_IOCTL_BIND_PROC / COPY_PROCESS
WUWA_IOCTL_HIDE_PROCESS               (present, unused — see TO DO)
WUWA_IOCTL_GIVE_ROOT                  (present, NEVER used by product)
WUWA_IOCTL_*_IOREMAP / DMA_BUF_CREATE (present, unused by product)
```

Strict validation everywhere: `pid>0`, user-VA gates, size bounds.
Invalid input returns errno, never oopses.

## Install

Preferred: `su -c './rwbridge-spx'` (`--dry-run` previews, `--ko PATH`
tests one file, `--extract-runsh` prints the shell fallback). Journal to
`/sdcard/MemoryD/J*.log` (+`N.log` session dump), attempt counts in
`/data/local/tmp/rwbridge.spx` (each artifact at most twice, then
NO-GO). Fallback: `su -c 'sh ./run.sh [ko]'` with the shell bundle
(8 `.ko` + `run.sh`). Verify = `/proc/modules` entry + socket-proto
probe (SEQPACKET→ENOKEY then RAW opens). Nothing persists
(no boot scripts); worst case is one reboot.

## Build (8 × DDK)

`kmod/Makefile` takes `KDIR` (one prepared tree) + `KMI` (target name).
CI builds the matrix in DDK containers (pinned release), forces
MODVERSIONS off (CRCs would pin past the KMI), pads UTS toward the
63-char cap, runs `check-universal` per artifact (imports ⊆ that
generation's System.map, no CRCs, BTI pads, placeholder present), then
packs all 8 + `run.sh` into `blobs.c` and links `rwbridge-spx`
(static-PIE). Local installs are for TESTING a staged build only.

## Inline hooks (allowed by explicit owner override)
Passive R/W remains the default surface. Inline hooks are permitted ONLY
for the kernel display facility (overlay-plane programming + vsync):
- RKP/hypervisor text-protection risk is accepted by the owner; hook
  install must fail closed per-site (verify-before-patch, original-bytes
  check, no partial hooks) and never wedge boot.
- No hook may alter game behavior, hide state, or touch dispatch paths.
- Each hook site is per-SoC backend code with its own NO-GO (unknown
  controller -> site disabled, never guessed).

## Explicit NO-GO list

`CONFIG_MODULES=n`, module-sig enforcement, kernels not exporting the
checked import surface, kprobe-blocked kernels (symbol resolution fails
closed at init), unparseable `uname -r`. A new NO-GO must be explicit,
never silent. 16K/64K pages are SUPPORTED (explicit geometry in the
address path); CFI-enforcing kernels are SUPPORTED (runtime bypass).

## Deviations from the previous generation (owner-ordered)

The old laws assumed one universal build; the merged driver is
per-generation by construction. What changed and why: (1) 8-target
matrix replaces single-artifact (deliverable stays single SPX);
(2) printk import allowed (GKI-universal, per-target verified);
(3) kprobe-trick kallsyms allowed (no import; fail-closed);
(4) eager init (socket server must exist before any client);
(5) hook/proc/dmabuf sources excluded from the build (present upstream
only); `hijack_arm64.c` stays linked SOLELY for `hook_write_range`
(CFI path) — call-redirection is never installed.

## TO DO

- Process hide: wire `do_hide_process` (task `PF_INVISIBLE` flag infra
  already in tree: `wuwa_proc.c`, ioctl cmd 14) behind an explicit
  product op with allowlist semantics. NOT active: no call sites ship.
- Re-verify the loader-contract map per release (the old 6.1 map
  described the previous driver; same method, new numbers).
- 16K-page live proof (geometry path exercised on-device, not just CI).

## Diagnosis

Journal first (`/sdcard/MemoryD/`), then dmesg (vermagic exact-want),
then `uname -r` vs matrix (selection log names the match passes), then
the socket probe (SEQPACKET→ENOKEY?). A wedge inside exactly one phase
convicts it; report phase + kernel string, never theory alone.
