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
- **`HotswapPlan.java`** — Builds the ordered hotswap step list mirroring  `tools/lxgr_load.py` `cmd_hotswap` semantics (load new first, then unload
  old): `LOAD_NEW` → `RUN_ENTRY` (only when `entry` non-empty; `""`/null
  means skip, as the driver treats empty entry as "skip") → `UNLOAD_OLD`
  (only when `oldHandle != 0`, where 0 = no previous install). Validates the
  driver's `ioctl_load`/`ioctl_unload` guards: path absolute, NUL-free,
  ≤ 255 UTF-8 bytes; entry NUL-free, no `/`, ≤ 63 UTF-8 bytes; handle 0 or
  positive. Returns `PlanResult`, never throws. `su` selects the
  `loadsosutoapp` (su-window) variant vs `loadsotoapp`.
- **`BootManager.java`** — Explicit opt-in boot-loading model: states
  `DISABLED` (initial, no boot-time action) / `ENABLED` (validated script
  stored). Enabling requires all three preconditions in order: explicit
  user confirmation (`userConfirmed == true`), driver-present precondition
  (caller-supplied boolean, no live probing here), and a valid load script
  (`validateScript`: non-empty, NUL-free, ≤ 4096 chars, absolute paths
  only — every `/`-containing token must start with `/` — and only the
  whitelist `[A-Za-z0-9 / . - _ : = " ' # ,]` plus space/tab, so shell
  metacharacters `; | & $ ( ) \`` and friends are rejected by name).
  Comment lines (`#...`) pass through uninspected. Double-enable rule:
  re-enabling with byte-identical script text is an idempotent no-op,
  while enabling with a different script is rejected (`disable()` first).
  `disable()` clears the stored script and is idempotent.
  `generateScript()` emits the exact shell lines (shebang + opt-in header
  comment + stored lines, trailing newline) or an explicit error when
  `DISABLED`. Returns `BootResult` / `ScriptResult`, never throws.

All public entry points validate inputs and return explicit result types
(`ParseResult` / `CapsResult` / `Transition` / `PlanResult` / `BootResult` /
`ScriptResult`); no exceptions
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
  "Userspace App/core/BootManager.java" \
  "Userspace App/tests/RunAll.java"
java -cp /tmp/dsu-core-out com.lxgr.dsu.core.RunAll
```

`RunAll` is a plain-`main` harness (no JUnit dependency). It prints
`PASS`/`FAIL` per case plus a `passed=N failed=M` summary and exits nonzero
if any case fails. Pre-existing status at time of writing: **94 passed,
0 failed**; `BootManagerTests` (`bootEnableDisable`, `bootValidateRejects`,
`bootGenerateShape`, `bootDoubleEnable`) adds 39 checks, all passing
(verified: 219 passed, 0 failed including parallel workstreams' tests;
registry tests were still landing, run again for the final total).

## HideManager (appended)

- **`HideManager.java`** — Explicit user-gated hide state machine:
  `IDLE` (visible, initial; never hidden at boot) → `HIDE_REQUESTED`
  (user tapped "Hide app" via `requestHide(pid)`, `pid > 0`) →
  `HIDDEN` (driver confirmed via `confirmHidden(before, after)` only when
  `after > before`; flat/decreased counts are rejected, never silent
  success) or `FAILED` (via `fail(detail)` with non-blank reason).
  `HIDDEN`/`HIDE_REQUESTED`/`FAILED` return to `IDLE` only via
  `requestUnhide(pid)` (user tapped unhide, `pid > 0`); calling from
  `IDLE` is idempotent success (unhide-absent-is-success, matching driver
  semantics). Every transition takes an explicit user-action token as a
  method argument — there is no boot hook, no automatic path, and no
  no-arg hide method. `describe()` gives the one-line visible
  confirmation for UI display. All transitions return `Transition`
  (`ok` + `value`, or explicit `error`); nothing throws for expected
  failures. Pure Java, no Android imports.

  Compile (add the new file to the existing command):

```sh
rm -rf /tmp/dsu-core-out && mkdir -p /tmp/dsu-core-out
javac -d /tmp/dsu-core-out \
  "Userspace App/core/RdVersion.java" \
  "Userspace App/core/DriverCaps.java" \
  "Userspace App/core/LoadState.java" \
  "Userspace App/core/HotswapPlan.java" \
  "Userspace App/core/HideManager.java" \
  "Userspace App/tests/RunAll.java"
java -cp /tmp/dsu-core-out com.lxgr.dsu.core.RunAll
```

## MemdDriver (appended)

- **`MemdDriver.java`** — Single transport decision point plus driver call
  specs as data (grounded in repo-root `client.h` via
  `Userspace App/INTEGRATION.md` and `native/memd_bridge.c`):
  `Transport {JNI_DIRECT, ROOT_SHELL, UNAVAILABLE}` with
  `selectTransport(jniAvailable, rootAvailable)` (JNI preferred whenever
  available, else root shell, else `UNAVAILABLE` with a reason naming both
  missing pieces) and `requireTransport(...)` (same choice as an explicit
  `TransportResult`, never throws). `callSpec(opName)` pins the six
  UI-reachable ops and their argument shapes for form building:
  `version` / `learnStatus` (no fields; the driver fd is
  transport-supplied), `hide` / `unhide` (`pid`),
  `loadso` (`pid`, `path`, plus optional `entry`, `su`, `ephemeral`),
  `unload` (`pid`, `handle`); unknown/null/blank names yield an explicit
  `SpecResult` failure listing `knownOps()`, never throw. `describe()`
  renders one-line UI summaries (`transport=...`, `op(fields, [optionals])`).
  Specs describe shapes only; they perform no driver I/O. Pure Java, no
  Android imports.

  Compile (add the new file to the existing command):

```sh
rm -rf /tmp/dsu-core-out && mkdir -p /tmp/dsu-core-out
javac -d /tmp/dsu-core-out \
  "Userspace App/core/RdVersion.java" \
  "Userspace App/core/DriverCaps.java" \
  "Userspace App/core/LoadState.java" \
  "Userspace App/core/HotswapPlan.java" \
  "Userspace App/core/MemdDriver.java" \
  "Userspace App/tests/RunAll.java"
java -cp /tmp/dsu-core-out com.lxgr.dsu.core.RunAll
```

  Verified: 29 new `driver:*` cases pass; full-tree run at append time:
  **219 passed, 0 failed** (all pre-existing plus all landed sibling
  suites; only 4 not-yet-landed `registry*` calls excluded — re-run
  `RunAll` once every suite has landed).

## RootShell (appended)

- **`RootShell.java`** — Privileged command transport: `Executor`
  interface (single method `ExecResult exec(String[] argv, long timeoutMs)`)
  so production (`ProcessExecutor`, which runs `su -c "<joined command>"`
  via `ProcessBuilder` — the only place that creates OS processes) and tests
  (fakes) share one contract; the testable path
  `runAsRoot(argv, timeoutMs, logSink, executor)` never calls `Runtime.exec`
  directly. Contract: validates (non-empty `argv`, absolute binary path in
  `argv[0]`, timeout 1000..300000 ms), echoes the exact shell-quoted command
  line (`joinCommand`) to the caller-supplied `LogSink` *before* executing,
  enforces the deadline independently (a task running past `timeoutMs` is
  cancelled/interrupted and reported `TIMEOUT`, even if the transport hangs),
  and maps outcomes to `OK` (exit 0) / `TIMEOUT` (caller- or
  executor-reported kill) / `DENIED` (exit 126/127/255, or non-zero exit plus
  a denial output fragment such as "permission denied") / `FAILED` (other
  non-zero exits) / `ERROR` (validation or transport exception — never a
  silent fallback). Rejected input never reaches the executor and logs
  nothing. Pure Java, no Android imports.

  Compile (add the new file to the existing command):

```sh
rm -rf /tmp/dsu-core-out && mkdir -p /tmp/dsu-core-out
javac -d /tmp/dsu-core-out \
  "Userspace App/core/RdVersion.java" \
  "Userspace App/core/DriverCaps.java" \
  "Userspace App/core/LoadState.java" \
  "Userspace App/core/HotswapPlan.java" \
  "Userspace App/core/HideManager.java" \
  "Userspace App/core/RootShell.java" \
  "Userspace App/tests/RunAll.java"
java -cp /tmp/dsu-core-out com.lxgr.dsu.core.RunAll
```

## ModuleRegistry (appended)

- **`ModuleRegistry.java`** — Pure-logic in-memory module registry over
  caller-supplied records (no file IO inside — callers list directories /
  parse `module.prop` themselves and hand `Record`s to `upsert`).
  `Record {id, name, version, versionCode(string), handle, resident:bool}`
  is immutable; `Record.create(...)` validates and returns `RecordResult`
  (never throws): id must be filesystem-safe `[A-Za-z0-9._-]+` mirroring
  `tools/lxgr_load.py check_module_id` (plus strict-superset rejection of
  bare `.` / `..` traversal ids), `versionCode` is required non-blank
  mirroring `parse_module_prop` (`module.prop has no versionCode=`), handle
  must be 0 (none) or positive. `name`/`version` are optional (null becomes
  `""`). Operations: `upsert` (last-write-wins full replace by id — no
  version gate on write; null record rejected), `remove` (returns the stored
  record; invalid/unknown id rejected), `list` (unmodifiable snapshot sorted
  by id), `findByHandle` (negative handle rejected; unknown handle explicit
  failure; smallest-id holder wins on duplicates). `compareVersionCode(a, b)`
  orders versionCode strings numerically via `Long.parseLong` when both
  parse (so `9 < 10`), else lexically (`1.2a`, `beta`, long-overflow fall
  back); null normalizes to `""`, never throws. All results explicit
  (`RecordResult` / `WriteResult` / `FindResult`); no exceptions for
  expected failures, no silent fallbacks. Pure Java, no Android imports.

  Compile (wildcard covers all landed core files):

```sh
rm -rf /tmp/dsu-core-out && mkdir -p /tmp/dsu-core-out
javac -d /tmp/dsu-core-out "Userspace App/core/"*.java "Userspace App/tests/RunAll.java"
java -cp /tmp/dsu-core-out com.lxgr.dsu.core.RunAll
```

  Verified: 65 new `registry:*` cases pass
  (`registryUpsertListRemove`, `registryIdValidation`,
  `registryVersionOrdering`, `registryFindReplace` — covering
  upsert/remove/list/find, id rejects for traversal/absolute/empty,
  version ordering incl. non-numeric fallback, and documented
  last-write-wins duplicate replace semantics); full-tree run at append
  time: **284 passed, 0 failed** (all pre-existing plus all landed sibling
  suites).
