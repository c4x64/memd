# DSU — Android userspace app (stub scaffold)

Product name: **DSU**. Single version source: `VERSION` in this directory,
currently `RD-20261016-0652` (format `RD-YYYYMMDD-HHMM`, UTC 24h; see
`AGENTS.md` product-identity section). Do not hardcode other versions in
code or docs — `AndroidManifest.xml` `versionName` mirrors `VERSION`.

## What this is

Minimal, reviewable Android scaffold (`com.lxgr.dsu`) that will integrate
with the MEMD (`rwbridge`) driver. Tabs:

- **MEMD Modules** (`MemdModulesFragment.java`) — stub list UI, wired to
  nothing yet. Shows the "no driver connection" state.
- **KSU Modules** — UNSUPPORTED placeholder (inside `MainActivity.java`).
  There is **no existing KSU modules page in this repo** (greenfield), so we
  built our own tabs. KernelSU / DirtyFrag upstreams are **NOT vendored**
  here and no KSU integration exists — the tab says so explicitly.
- **Settings** (`SettingsFragment.java`) — explicit opt-in boot-load toggle,
  default OFF, with explanatory copy. No silent persistence.

Hard rules (from `AGENTS.md`, binding): every privileged action is
user-initiated, visible, and explained in UI copy. No stealth, concealment,
security-control bypasses, or undocumented persistence.

## What works vs explicitly stubbed / unavailable

Works (offline-verifiable):

- `MainActivity` with the three tabs above; compiles with `javac +
  android.jar` (see Build).
- `MemdModulesFragment` renders the no-driver-connection state.
- `SettingsFragment` toggle defaults OFF and holds in-memory state.

Explicitly stubbed / unavailable (do NOT treat as working):

- No driver channel (`memd_open` / ioctl calls) — not implemented in Java yet.
- No `loadsotoapp` / `loadsosutoapp` module install, no unload/hotswap.
- No bootstrap delivery, no VERSION/learn-status probe from the app.
- No boot-load mechanism (no root-manager hookup); toggle is in-memory only.
- No KernelSU / DirtyFrag root or installation flow — upstreams not vendored.
- No Zygisk integration beyond documenting the `memd.hpp` entry ABI.
- No hide-pid feature — requested by `AGENTS.md` "Post-install integrity
  checks" but it CONFLICTS with the no-stealth rule; NOT implemented, flagged
  in `BLOCKERS.md` for owner decision.

## Build (no network, no gradle)

```sh
cd "Userspace App"
./build.sh
```

`build.sh` finds `android.jar` under `~/Library/Android/sdk/platforms`
(highest `android-*`), then compiles all sources with:

```sh
javac -source 8 -target 8 -bootclasspath <android.jar> -d build/classes <sources>
```

and reports `COMPILE OK` or errors. Requires a local Android SDK platform
and a JDK that still accepts `-source 8`. No dependencies are fetched.

## Version scheme

`RD-YYYYMMDD-HHMM` (UTC, 24h); multiple releases in one minute append `-2`,
`-3`, … Single source: `VERSION`. See `AGENTS.md`.

## License / attribution

No upstream code is vendored in `Userspace App/`: no KernelSU, no DirtyFrag,
no Zygisk, no `client.h`/`memd.hpp` copies. The driver contract in
`INTEGRATION.md` is a read-only summary of `/client.h` and `/memd.hpp` at the
repo root (facts only, no invented APIs). If DirtyFrag/KernelSU sources are
added later, pin the upstream URL + reviewed commit SHA/tag, preserve license
notices, and record local patches per `AGENTS.md`.
