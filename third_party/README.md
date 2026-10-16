# third_party — pinned upstream aliases (reference only)

`pins.json` is the machine-readable mirror of the `UPSTREAM.md` pin table.
`upstream/` (created by `tools/sync-upstream.py`, gitignored) holds exact
pinned trees for reviewers to diff during pin-update reviews.

Hard boundaries (binding, per `UPSTREAM.md`):
- Nothing here is compiled into the app. `build.sh` never reads it.
- DirtyFrag files are unlicensed (all rights reserved): read and learn,
  never copy into this repo — not `lkm/dfroot.c`, not app sources.
- KernelSU (GPL-3.0) is vendored at the pinned SHA under `ksu/` with
  `ksu/LICENSE` + `ksu/kernel/LICENSE` intact — terms in `UPSTREAM.md`
  (derivative stays GPL-3.0). DirtyFrag stays never-copy.
- Core reference paths reviewers care about:
  - DirtyFrag: `lkm/dfroot.c`, `lkm/Makefile`,
    `app/src/main/java/df/root/ExploitRunner.java`,
    `app/src/main/java/df/root/BootReceiver.java`,
    `app/src/main/java/df/root/MainActivity.java`
  - KernelSU: `kernel/`, `userspace/ksud/src/module.rs`,
    `userspace/ksud/src/init_event.rs`, `manager/app/src/main/` Kotlin,
    `manager/app/src/main/cpp/ksu.cc`
