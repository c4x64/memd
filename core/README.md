# DSU Userspace App — Core Logic

Pure-Java (no Android framework imports) core for the DSU userspace app.
Package `com.lxgr.dsu.core`. Compiles with plain `javac` on any JVM so the
logic is unit-testable without `android.jar`.

## Classes

- **`RdVersion.java`** — Parses, validates, and compares release versions of
  the form `RD-YYYYMMDD-HHMM[-seq]` (Userspace App/AGENTS.md: UTC, 24-hour
  clock; `-seq >= 2` only for extra releases within the same minute, e.g.
  `RD-20261016-0614-2`). Day-of-month is calendar-checked incl. leap years.
  `parse(String)` never throws: it returns `ParseResult` (`ok` + `value`, or
  `ok == false` + `error`). `compareTo` orders by timestamp, then sequence
  (absent sorts before any `-seq`); `compareResult(other)` is the
  null-safe explicit-error variant.
- **`DriverCaps.java`** — Models the `MEMD_IOCTL_VERSION` surface
  (`struct memd_version_cmd` in `client.h` /
  `kmod/memd/ioctl/memd_ioctl.h`): `abi`, version triple
  (`major.minor.patch`), `flags` (`BOOTSTRAP_DONE = 1`,
  `LEARNED_OFFSETS = 2`), `gen` (`-1` = unknown). `create(...)` validates
  (rejects negatives and `gen < -1`) and returns `CapsResult`, never throws.
  `isCompatible()` is `abi == 1`. `describe()` returns a one-line
  human-readable summary for UI display (compat verdict, flag names with
  unknown bits shown numerically, generation).
- **`LoadState.java`** — Immutable install/boot-load state machine:
  `UNKNOWN` → `NOT_INSTALLED` → `INSTALLED_STOPPED` → `RUNNING`, with
  `FAILED` (carries a `reason()`) reachable from any non-terminal state and
  terminal once entered (only `reset()` back to `UNKNOWN` is accepted).
  Failure terminals: `failPermissionDenied`, `failTimeout`,
  `failUnsupportedDevice` (plus generic `fail`); each requires a non-blank
  detail message. Every transition returns a `Transition` (`ok` + `value`,
  or explicit `error`); nothing throws for expected failures.
- **`HotswapPlan.java`** — Builds the ordered hotswap step list mirroring
  `tools/lxgr_load.py` `cmd_hotswap` semantics (load new first, then unload
  old): `LOAD_NEW` → `RUN_ENTRY` (only when `entry` non-empty; `""`/null
  means skip, as the driver treats empty entry as "skip") → `UNLOAD_OLD`
  (only when `oldHandle != 0`, where 0 = no previous install). Validates the
  driver's `ioctl_load`/`ioctl_unload` guards: path absolute, NUL-free,
  ≤ 255 UTF-8 bytes; entry NUL-free, no `/`, ≤ 63 UTF-8 bytes; handle 0 or
  positive. Returns `PlanResult`, never throws. `su` selects the
  `loadsosutoapp` (su-window) variant vs `loadsotoapp`.

All public entry points validate inputs and return explicit result types
(`ParseResult` / `CapsResult` / `Transition` / `PlanResult`); no exceptions
for expected failures, no silent fallbacks. (`Comparable.compareTo` keeps
its standard null contract for programming errors; use `compareResult`
for the explicit-error path.)

## Compile + test (exact commands)

Run from the repository root (`/Users/prabhas/memd`):

```sh
rm -rf /tmp/dsu-core-out && mkdir -p /tmp/dsu-core-out
javac -d /tmp/dsu-core-out \
  "Userspace App/core/RdVersion.java" \
  "Userspace App/core/DriverCaps.java" \
  "Userspace App/core/LoadState.java" \
  "Userspace App/core/HotswapPlan.java" \
  "Userspace App/tests/RunAll.java"
java -cp /tmp/dsu-core-out com.lxgr.dsu.core.RunAll
```

`RunAll` is a plain-`main` harness (no JUnit dependency). It prints
`PASS`/`FAIL` per case plus a `passed=N failed=M` summary and exits nonzero
if any case fails. Current status: **94 passed, 0 failed**.
