# rwbridge — universal memory R/W driver (ARM64 Android, 5.10+)

One packed deliverable (`rwbridge-spx`) carrying **one universal image
first, 8 per-generation artifacts as fallback**; the loader tries the
universal image on every 5.10–6.12 kernel and falls back to the
numerically matched per-KMI artifact. Driver core derived from
fuqiuluo/android-memd (socket transport, page-table walk, phys R/W,
kallsyms resolution, CFI-disable); inline hooks are permitted ONLY for
the kernel display facility and process hiding (owner override, see
below); procfs/dmabuf transports are excluded.

**PROVEN LIVE (universal image, Samsung 5.15, non-CFI):** load Live +
socket open/close with zero crashes; ioctl struct round-trips; R/W with
byte-exact data integrity (`0xdeadbeefcafebabe` write→read MATCH);
hide install/hide/unhide/uninstall with shell-blind + root-sees +
`/proc` fully restored; display install refused cleanly (`-ENODEV` on
dummy-virt, no controller guessed). No panics across the full suite.

- **1 universal image, 8 fallback builds, 1 deliverable.** The universal
  image is a 5.10-baseline build with zero version-conditional behavior:
  no kprobe imports of any kind (vendor loaders reject GOT-page relocs
  311/312 outright — the universal image has 0 such relocs by
  construction), kallsyms via `/proc/kallsyms` self-parse, VMA walks via
  `find_vma`, and the int/bool `filldir` ABIs coinciding. The DDK matrix
  (`android12-5.10` … `android16-6.12`) builds the identical source per
  generation — proving header-agnosticity on all 8 — and stays as
  fallback. The `-dbg` variant is a forensics build of the 6.1 artifact
  (debug info kept): never auto-selected, loaded only by explicit
  `--ko a14-6.1-dbg` (SPX) or explicit path (run.sh).
  Vendor variance inside a generation (UTS suffixes) is absorbed by the
  vermagic placeholder + install-time patch (dmesg-feedback retry), with
  finit_module version-magic override as last resort (universal + exact
  matches only; signatures never overridable; Live+proto verify gates).
  Cross-generation forced loads are refused outright (wrong structs
  would mis-walk — strictly worse than not loading).
- **CFI is handled at runtime**: `cfi_bypass()` patches the CFI check
  functions after load (/proc-resolved, RET fill). No separate CFI
  artifact, no flavor switch, no dispatch-slot surgery (matched builds
  need none).
- **Enforcing + 5.x is refused, never trapped**: SPX and run.sh read
  `/proc/config.gz`; `CONFIG_CFI_CLANG=y` with a 5.x kernel is a NO-GO
  (the bypass writes kernel text: unverified on 5.x, panics under
  RKP/KDP). Unknown config proceeds as before.
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
- **OEMs strip exports the DDK keeps**: Samsung 5.15.137 lacks
  `probe_kernel_read` (present in DDK/GKI System.map, so CI cannot catch
  the gap) and `init_mm` was never exported anywhere upstream. Rules
  learned: fault-safe kernel reads use extable-guarded loads (no
  imports), swapper walks use TTBR1_EL1 (no structs — task/mm layouts
  skew too), and every NEW import must be load-tested on-device (CI
  proves DDK compatibility only). Cross-check technique: our undef list
  must be a subset of proven on-device vendor undefs + core exports.
- **Symbols resolve at runtime** (`/proc/kallsyms` self-parse — no
  kprobe imports of any kind; vendor loaders reject GOT-page relocs
  against even weak kprobe references, so the trick can never be in a
  universal image); unresolvable kernels fail closed per-op (kptr_restrict
  hides addresses → callers degrade to "not found", R/W + hide +
  display-probe need no kallsyms at all).
- **Init is load-bearing** (socket server + resolution + CFI patch must
  run): unlike the previous sysfs design, there is no useful
  degraded state, so init failure refuses the load instead of going
  silent-Live.
- **Logging via printk** (`memd_info/err`): the universal image pins
  `_printk` (5.10 headers emit `printk`, some vendors export only
  `_printk` — proven on Samsung 5.15; CI-gated present in baseline map).
  Boot lines only + errors; no per-op spam.

## Client contract (product path: socket)

No device node, no sysfs params. The driver registers a socket family
(first free from `AF_DECnet`); discover it by probing families with
`SOCK_SEQPACKET` (driver answers `-ENOKEY`) then opening `SOCK_RAW`.
All commands are `ioctl()`s on that fd (see `kmod/memd/ioctl/`):

```
MEMD_IOCTL_READ_MEMORY / WRITE_MEMORY (phys, arbitrary size)
MEMD_IOCTL_ADDR_TRANSLATE / AT_S1E0R  (VA translation)
MEMD_IOCTL_DEBUG_INFO                 (TTBR0/task/mm/pgd — bring-up)
MEMD_IOCTL_GET_MODULE_BASE / FIND_PROCESS / IS_PROCESS_ALIVE
MEMD_IOCTL_PAGE_INFO / PAGE_TABLE_WALK / PTE_MAPPING
MEMD_IOCTL_BIND_PROC / COPY_PROCESS
MEMD_IOCTL_HIDE_PROCESS               (present, unused — see TO DO)
MEMD_IOCTL_GIVE_ROOT                  (present, NEVER used by product)
MEMD_IOCTL_*_IOREMAP / DMA_BUF_CREATE (present, unused by product)
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
for the kernel display facility (overlay-plane programming + vsync) and
process hiding (VFS `iterate_shared` swap on the live `/proc` file):
- RKP/hypervisor text-protection risk is accepted by the owner; hook
  install must fail closed per-site (verify-before-patch, original-bytes
  check, no partial hooks) and never wedge boot. The hide hook swaps a
  function pointer in a live `file_operations` reached via `filp_open`
  (no kernel-text writes, ever); display hooks follow the same rule
  where possible. Hard-won rules, all proven on-device: kernel text may
  be execute-only (XOM) so table identification is metadata-only; PTE
  AP flips use Break-Before-Make (invalidate/TLBI/make/TLBI) or stale RO
  TLBs survive; the RO bit is AP[1]=bit 7 (table/block/page alike);
  `tlbi vaae1` takes the full VA (HW uses bits[55:12]); every diagnostic
  `return` sits inside its braces.
- No hook may alter game behavior or touch dispatch paths. Hiding covers
  OUR pids only (explicit ioctl set, never compiled in); target tasks are
  never touched (the old PF_INVISIBLE flag stub is removed).
- Each hook site is per-SoC backend code with its own NO-GO (unknown
  controller -> site disabled, never guessed).

## Display facility (opcodes 26/27/28)

Core is backend-agnostic: double-buffered CPU raster (clear/rect/line/
8x8-glyph, numeric ops only) + dirty-rectangle tracking + submit mutex.
Frames draw to BACK, flip, then the backend presents FRONT's dirty
region (stable snapshot under lock). All size math uses
`check_mul_overflow`; shadows are `vmalloc` (no device, no DMA).
Route order is DRM client → simplefb → DECON raw probe; first success
wins, nothing retained on failure. Status reports the active backend.

**Pixel-proven (TEST RAM backend, opcode 29 readback, dummy-virt):**
clear + border + diagonal + "OK" glyphs submitted as numeric ops and
read back byte-exact (4 colors, geometry matches). TEST-only backend
(`soc_ram.c`) + opcode, gated by `DISP_TEST=1` (own CI job
`universal-test`, shell-bundle only, never SPX, never auto-selected);
product surface stays 26/27/28.

**Live viewing without a panel (TEST-only kernel VNC).**
`memd_vnc.c` (same `DISP_TEST` gate, never shipped) serves the stable
core front as RAW RFB on loopback TCP 5901 — started on display
install, stopped on uninstall/rmmod alongside the refresh thread, one
viewer at a time, unknown messages drop the client. The kernel still
owns the frame; the stream is a read-only tap (lock → copy → unlock,
byte-swap + send from the streamer's own buffer, never under the core
lock). All sockets are created/used/released by the serving thread
itself (non-blocking accept/recv + `should_stop` polls — no
cross-thread close); bind failure logs once and the display is
unaffected. View it: `adb forward tcp:5901 tcp:5901`, then any VNC
viewer at `localhost:5901` (macOS: `open vnc://localhost:5901`).
Stable ksocket APIs only (CI-verified 5.10–6.12).

- **DRM client (primary, generic).** exynos-drm already owns clocks,
  power, SysMMU, shadow update and vsync — a second register driver
  would conflict with it, so the generic path goes through the DRM
  core (CPU raster into a dumb buffer, atomic commit, real vsync).
  No per-SoC code, no winmap, no vsync TODO. Discovery (drm_class +
  card* match, stable core APIs only, zero DRM struct access) is live;
  modeset/commit lands next with CI header-verified signatures +
  Exynos+DRM hardware proof. Until then open refuses (status ENODEV).
- **simplefb fallback (safest pixels).** Bootloader-lit panel via the
  standard simple-framebuffer node (address/size/stride/format — zero
  programming, no clocks, no power, no registers). Strict format gate
  (`x8r8g8b8`/`a8r8g8b8` direct copy; anything else refuses — wrong
  colors are worse than none) + overflow-checked geometry (panel must
  fit the UI; top-left blit, rest of panel untouched). Continuous
  refresh: a `memd_disp` kernel thread re-presents the stable front at
  10 Hz (`MEMD_DISP_REFRESH_MS`), repainting over fbcon/splash writers
  behind our back. Kernel thread = immune to LMK and force-stop,
  outlives userspace death; only uninstall/rmmod stops it (stop outside
  the core lock — `kthread_stop` sleeps — then teardown under lock).
  Present-on-submit stays immediate; the heartbeat only guards
  persistence. DRM needs no refresh (atomic commit latches), RAM none
  (readback reads the core front directly). Uninstall unmaps
  only (last frame persists, harmless — simplefb keeps scanning out).
- **DECON raw (probe-only, last resort).** Only matters without the DRM
  stack. Hazard-fixed probe: availability → resource claim (bound
  exynos-drm fails here, nothing touched) → clocks by index + power
  domains → map → readback → full cleanup on every path (retains
  nothing; install re-probes statelessly). Zero clocks acquired refuses
  the readback outright (a gated-block read can hang the bus — never
  risk it). DMA alloc (when reachable) uses the DECON device with a
  checked mask (IOVA, not phys; per-SoC mask arrives with the winmap).
- **Window maps (DECON raw only).** Seeded from documentation (Linux
  exynos-drm DECON driver + vendor TRM: WINCON, buffer start, size,
  position) and CONFIRMED on hardware — never discovered by probing.
  Each entry carries a silicon revision gate (compatible + version
  register offset/value: right string on wrong silicon refuses) and,
  when programming lands, shadow-update latch + frame-done IRQ
  completion (stage all window regs, latch atomically; TRM bit/IRQ
  names confirmed for the part at verification). Table stays EMPTY
  until then: every controller NO-GO, plane code unreachable.

## Universal runtime techniques (proven on Samsung 5.15)

- **Learned credentials.** `capable()` inlines `task->cred` from build
  headers — wrong on foreign layouts = crash on first socket (proven:
  instant kill). Privilege checks read cred via a runtime-learned offset
  (adjacent equal cred pointers with root usage/uid anchor) + stable
  `struct cred` layout (usage@0, uid@4, cap_effective@56, CI-asserted).
  Fail closed (deny) when unlearned.
- **GUP-free user copies.** `copy_to/from_user` are arm64 inlines (PAN/UAO
  sequences from build headers): 5.10-built copies fail on 5.15 (proven:
  8-byte stack copy returns all-remaining). All user copies go through
  `access_process_vm` (stable out-of-line MM API, chunked) — same
  semantics, every generation. Target data additionally bypasses the
  page walk via `access_process_vm` on the target task (KPTI-safe; the
  walk stays for the phys diagnostic only, best-effort).
- **Runtime-built socket tables.** A 5.10-built `struct proto` hangs
  newer kernels in `proto_register` (proven: `obj_size` alone moved
  256→272; init wedged spinning). Registration structs are built at
  init for the RUNNING generation from CI-proved offset tables
  (every matrix job re-asserts its own headers; drift fails the build).
- **No `sock_orphan`.** It takes `sk_callback_lock`, whose offset moves
  with `struct sock` (proven panic: BRK in `queued_spin_lock_slowpath`
  on close). Our socket carries no callbacks/timers/packets, so there
  is nothing to detach — release frees privates + drops the ref.
- **No `mmap_lock`.** Its offset moves with `mm_struct` (proven panic
  in `down_read` on first R/W). mm is pinned via `get_task_mm`; walks
  are fail-closed (guarded reads + entry validation + pgd shape gate).
- **KPTI-aware pgd.** TTBR0 (user tables) need not equal `mm->pgd`, so
  pgd is learned by table shape (zeros + valid DRAM descriptors,
  guarded reads), never by value match. Data path does not depend on
  it (see above).
- **Hide hook without symbols.** `/proc` `file_operations` reached via
  live `filp_open` (per-generation `f_op`/`iterate_shared` slots from
  CI tables); the table write uses Break-Before-Make + full-VA TLBI +
  AP[1]=bit7 (all proven on-device) with bounded internal retry (first
  entry-store can fault transiently on a stale TLB; retry succeeds,
  still fail-closed after 3). Install/uninstall verify every write by
  readback and never clear state on failure (failure keeps hooked +
  active + retryable — clearing into an unverified `f_op` would dangle
  `/proc` empty for non-root; proven by incident, fixed by design).
- **Denylist for stripped vendors.** The universal image must not import
  what vendors strip even when GKI exports it (proven on Samsung 5.15:
  `printk`, `pfn_valid`, traced MMIO, `mmap_lock` inlines). CI denies
  these imports for the universal job; runtime chains replace them
  (`_printk` pin, `memd_pfn_ok`, volatile MMIO, no mmap_lock).

## Explicit NO-GO list

`CONFIG_MODULES=n`, module-sig enforcement, kernels not exporting the
checked import surface, unparseable `uname -r`. A new NO-GO
must be explicit, never silent. 16K/64K pages are SUPPORTED (explicit
geometry in the address path); CFI-enforcing kernels are SUPPORTED
(runtime bypass). Hiding adds its own: `/proc` non-VFS or missing
`iterate_shared`, CFI-enforcing kernels (install refused by policy —
userspace gates first). Display adds its own: no DTB DECON node, failed
register readback, no verified window map for the compatible (all refuse
with -ENODEV; proven on dummy-virt: active=0 errno=19).

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

- Re-verify the loader-contract map per release (the old 6.1 map
  described the previous driver; same method, new numbers).
- 16K-page live proof (geometry path exercised on-device, not just CI).
- Hide status surfacing in the overlay client (opcodes 21/22 in the
  product client header; warn user when hiding is unavailable).
- Cross-generation live proofs (5.10 / 6.1 / 6.6 / 6.12 devices +
  CFI-enforcing + non-Samsung SoCs); 5.10/6.x user-pgd sourcing for the
  phys diagnostic (data already KPTI-safe via the kernel copy).

## Diagnosis

Journal first (`/sdcard/MemoryD/`), then dmesg (vermagic exact-want),
then `uname -r` vs matrix (selection log names the match passes), then
the socket probe (SEQPACKET→ENOKEY?). A wedge inside exactly one phase
convicts it; report phase + kernel string, never theory alone.
