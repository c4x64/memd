# Upstream pins — DSU app

Date recorded: 2026-10-16 (UTC). All facts below were read from the
live repositories on this date; nothing is vendored into this repo.

## Pinned revisions (immutable — do not float)

| Upstream | URL | Branch | Commit (full SHA) |
|---|---|---|---|
| DirtyFrag (mitschud fork) | https://github.com/mitschud/DirtyFrag | `master` | `639fddf808c6e3e320560589418916c1f694d3e2` |
| KernelSU (diabl0w fork) | https://github.com/diabl0w/KernelSU | `main` | `b38f4096f33632ad5871dc3fff0ec426e23c9358` |

Rules per `Userspace App/AGENTS.md` ("CI and upstream dependencies"):
- Never move these pins without a dedicated, reviewed change.
- A pin update = update this file + review release notes/compat + run the
  full app test suite + CI before merging. No silent or automatic updates.
- Machine-readable mirror: `third_party/pins.json` (same SHAs; change both
  together). `tools/sync-upstream.py` materializes the pinned trees under
  gitignored `third_party/upstream/` for review diffing only — never compiled.

## Licenses and attribution (binding)

- **diabl0w/KernelSU: GPL-3.0** (`LICENSE` file at repo root).
  Consequence: do NOT vendor KernelSU code (app, kernel, userspace,
  scripts) into this repository. Derivative-work and distribution terms
  apply. Interoperability stays at arm's length: documented intents,
  out-of-process shell calls, and user-installed manager APKs. No static
  or source linkage. Preserve attribution in user-visible About text if
  the integration ever names the upstream.
  Upstream lineage (per their docs): KernelSU project; manager app under
  `manager/`, kernel under `kernel/`, `userspace/ksud` + `userspace/ksuinit`,
  `uapi/`, multilingual `docs/`, `website/`, `repack_apk.py`.
- **mitschud/DirtyFrag: NO license file found** in the repo root listing
  (root holds `.gitignore`, `CHANGELOG.md`, `Makefile`, `README.md`,
  `build.gradle.kts`, `gradle*`, `settings.gradle.kts`, `app/`, `docs/`,
  `lkm/`, `tools/` — no `LICENSE`/`COPYING`), and the GitHub API reports
  no SPDX identifier. Treat as **all rights reserved** until the owner
  states otherwise.
  Consequence: do NOT vendor DirtyFrag code either — not the app, not
  `lkm/dfroot.c`, not the exploit chain, not UI copy. Interop is limited
  to *behavioral* compatibility (same user gestures, same on-device
  artifacts our driver already understands) and to reading their docs.
  Upstream lineage (per their README): fork of `diabl0w/DFRoot`;
  exploit chain from `diabl0w/DFRoot`, PoC/code from `lsposed/lspromise`,
  `polygraphene/DFReroot`, unprivileged XFRM method from
  `combeng6th/DirtyInit`. If we ever reference these, attribute them.
- **Rule of thumb for this repo:** nothing under `Userspace App/` may be
  copied from either upstream. UX *patterns* (a manager picker, an
  opt-in boot toggle with a failed-run interlock, a modules on/off
  switch, a savable log) are ideas, freely re-implementable; code,
  strings, layouts, and binaries are not.

## What each upstream is (for scoping our work)

**DirtyFrag** — ephemeral root via the CVE-2026-43284 page-cache
exploit. App (`app/`: Gradle APK with java/jni/res, built with
`./gradlew assembleRelease`, release keystore gitignored) + kernel
module (`lkm/dfroot.c`, per-KMI builds in their CI; prebuilt `.ko`
files committed under `app/src/main/jni/ko/`). Flow, per their README:
pick SU manager in the SU Manager card (manager must ship
`libksud.so`; staged from the *installed manager's* library, not
bundled) → Run exploit → module loads via crafted page-cache write →
bootstrap reads the app's device-protected settings, adopts the zygote
environment, sets partitions read-only, optionally disables modules →
launches the SU daemon from the installed manager. Root is ephemeral
(reboot = clean). Relevant product behaviors we may mirror (not copy):
SU-manager picker card; Autorun on boot gated behind expert mode with
a failed-run interlock that disables itself so a bad run cannot
boot-loop the device; soft-reboot handling; KernelSU-Modules on/off
switch that works WITHOUT root (applied by the kernel module before
ksud starts); advanced log with one-tap save; explicit recovery
guidance (Safe Mode, `adb uninstall`, module-disable escape hatch).

**KernelSU (diabl0w fork)** — "a Kernel based root solution for
Android" (GPL-3.0). Manager app under `manager/` (Gradle, `app/src`
`main` + `test`); `libksud.so` ships inside the manager APK (this is
the library DirtyFrag stages). Our app must never assume it can read
another app's native libraries directly; staging is the installed
manager's job, selected by the user.

## Integration surface status (honest ledger)

| Need (per AGENTS.md) | Status |
|---|---|
| DirtyFrag root/bootstrap behavior | DOCUMENTED ONLY (README + flow above). No code vendored (unlicensed). Our `RootShell` transport + `BootManager` validation replicate the *contract shape* (explicit opt-in, validated scripts, fail-closed errors), not their implementation. |
| Installed root manager (libksud.so staging) | EXTERNAL, user-provided. Picker UI must list candidates but cannot verify `libksud.so` presence itself; states "unverified — provided by your installed manager". |
| KSU modules page + MEMD Modules tab | NOT VENDORED. Our tabs are original UI over our own `ModuleRegistry`/driver ioctls. Do not claim KernelSU compatibility. |
| Zygisk integration | NOT STARTED. Only via a documented Zygisk integration once understood; none is vendored or referenced. |
| Hide/self-integrity ("hide everything", owner override 2026-10-16) | Implemented ONLY as explicit user-gated action (`HideManager`: request → verify count increased → visible confirmation; never at boot, never silent). The AGENTS.md no-stealth rule is otherwise intact; this file records the named exception with its date. No concealment of the app's own presence beyond the explicit user action. |
| Example module | OUT OF SCOPE for the app build (built last, on `ExampleModule`). |

## Open items (need owner or upstream input — do not guess)

1. DirtyFrag license confirmation (ask upstream or pick only documented behavior; current stance: no vendoring).
2. Whether DSU should *detect* (read-only, via package manager) an installed DirtyFrag/KernelSU manager to pre-fill the picker vs. asking the user to choose blindly. Detection is read-only and safe; keep selection explicit either way.
3. Runtime device + CI E2E (tracked in BLOCKERS.md).
4. Example module content (built last; needs the module ABI finalized).
