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
security-control bypasses, or undocumented persistence — with ONE named
exception: the `AGENTS.md` "Post-install integrity checks" hide requirement
is RESOLVED per explicit owner override 2026-10-16 (see `BLOCKERS.md`).
Hiding is permitted ONLY via an explicit user action (visible toggle/button
with explanatory copy), never silently or by default.

## What works WITHOUT a device vs what needs one

Works WITHOUT a device (offline-verifiable on a dev host):

- `MainActivity` with the three tabs above; compiles with `javac +
  android.jar` (see Build from scratch).
- `MemdModulesFragment` renders the no-driver-connection state.
- `SettingsFragment` toggle defaults OFF and holds in-memory state.
- `core/` pure-Java logic (`RdVersion`, `DriverCaps`, `LoadState`,
  `HotswapPlan`) compiles with plain `javac` and its `RunAll` harness
  passes (see `core/README.md`).
- `native/memd_bridge.c` compile-only build passes with `-Wall -Wextra`,
  zero warnings; `-shared` link yields an ARM aarch64 `.so` with all five
  `Java_com_lxgr_dsu_MemdDriver_*` symbols exported (see
  `native/README.md`). No runtime behavior is verified by this.

Needs an authorized device with the driver installed (NOT runnable here):

- Any driver-channel call (`memd_open` + ioctls 14/21/22/38/39/40/41/42/43):
  VERSION/learn-status probe, bootstrap delivery, `loadsotoapp` /
  `loadsosutoapp`, unload/hotswap, hide install/status/process.
- `UnsatisfiedLinkError` / permission-denied / timeout / partial-install
  UI paths end-to-end.
- Boot-load enable/disable through a root manager (no hookup exists yet;
  toggle is in-memory only).
- KernelSU / DirtyFrag root or installation flows — upstreams not vendored.
- Zygisk runtime loading beyond the documented `memd.hpp` entry ABI.

Explicitly stubbed / unavailable (do NOT treat as working):

- No driver channel (`memd_open` / ioctl calls) — not implemented in Java yet.
- No `loadsotoapp` / `loadsosutoapp` module install, no unload/hotswap.
- No bootstrap delivery, no VERSION/learn-status probe from the app.
- No boot-load mechanism (no root-manager hookup); toggle is in-memory only.
- No KernelSU / DirtyFrag root or installation flow — upstreams not vendored.
- No Zygisk integration beyond documenting the `memd.hpp` entry ABI.
- No hide UI wired yet. The hide call contracts (ops 14/21/22) are
  documented read-only in `INTEGRATION.md`; per the owner override
  2026-10-16 (see `BLOCKERS.md`), any future wiring MUST be an explicit,
  visible, user-initiated action — never silent, never by default.

## Build from scratch (no network, no gradle)

Prerequisites on the dev host: a JDK that still accepts `-source 8`, an
Android SDK platform (`android.jar`), and (bridge only) an NDK with the
`aarch64-linux-android24-clang` toolchain.

### Java app (`javac` path via `build.sh`)

```sh
cd "Userspace App"
./build.sh
```

`build.sh` finds `android.jar` under `~/Library/Android/sdk/platforms`
(highest `android-*`), then compiles every `.java` source under
`app/src/main/java` with:

```sh
javac -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -d build/classes <sources>
```

and reports `COMPILE OK` or errors. Requires a local Android SDK platform
and a JDK that still accepts `-source 8`. No dependencies are fetched.
Output goes to `Userspace App/build/classes/` (generated, not committed).
This verifies compilation only — it does NOT install, run, or connect to
a driver. For the pure-Java `core/` harness (no `android.jar` needed), see
`core/README.md`. For the JNI bridge compile (NDK, no device), see below
and `native/README.md`.

### JNI bridge (NDK path, compile-only on host)

Single C file: `native/memd_bridge.c` (+ `native/memd_bridge.h`), includes
repo-root `client.h` by relative path (`../../client.h`), never copied.
Exact command used (see `native/README.md`):

```sh
NDK="$HOME/Library/Android/sdk/ndk/27.0.11902837"
CC="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
"$CC" -c "Userspace App/native/memd_bridge.c" -o memd_bridge.o -fPIC -Wall -Wextra
"$CC" -shared -o libmemd_bridge.so memd_bridge.o
```

Note: NDK `28.2.13676358` under `~/Library/Android/sdk/ndk/` is an
incomplete install (no toolchains); the build uses `27.0.11902837`.
Gradle `externalNativeBuild` wiring does not exist yet in this directory.

### What needs a device

Compiling the app and the bridge (above) works on a plain dev host. The
following need an authorized device with the driver installed and are NOT
runnable here: opening the driver channel, issuing any ioctl, loading /
unloading modules, bootstrap delivery, hide install/status/process,
boot-load via a root manager, and all runtime permission/ failure UI paths.

## Version scheme

`RD-YYYYMMDD-HHMM` (UTC, 24h); multiple releases in one minute append `-2`,
`-3`, … Single source: the `VERSION` file in this directory (currently
`RD-20261016-0652`). `AndroidManifest.xml` `versionName` mirrors `VERSION`.
Do not hardcode other versions in code or docs. See `AGENTS.md`
product-identity section.

## License / attribution

No upstream code is vendored in `Userspace App/`: no KernelSU, no DirtyFrag,
no Zygisk, no `client.h`/`memd.hpp` copies. The driver contract in
`INTEGRATION.md` is a read-only summary of `/client.h`, `/memd.hpp`, and
the matching `kmod/memd/ioctl/memd_ioctl.h` + `kmod/memd/utils/memd_inject.h`
declarations (facts only, no invented APIs). If DirtyFrag/KernelSU sources are
added later, pin the upstream URL + reviewed commit SHA/tag, preserve license
notices, and record local patches per `AGENTS.md`.
