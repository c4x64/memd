# DSU open blockers

1. **No device / CI runtime.** There is no Android device, emulator, or CI
   runner in this environment. The scaffold compiles (`./build.sh` → javac +
   `android.jar`), but install, driver-channel, boot-load, and permission
   paths cannot be executed. No E2E possible.

2. **No KernelSU / DirtyFrag upstream vendored.** Neither upstream source nor
   a pinned revision exists anywhere in this repo (verified by inspection:
   no KSU/DirtyFrag tree, no existing KSU modules page — greenfield). The
   KSU Modules tab is therefore an explicit UNSUPPORTED placeholder. Do not
   implement root/bootstrap flows until an upstream is vendored with URL +
   pinned SHA/tag, licenses, and attribution per `AGENTS.md`.

3. **No E2E possible.** Without (1) and (2): no manual MEMD load, no
   boot-load verification (enable/disable), no permission-denied / failure
   UI exercise, no KSU-module regression check. `AGENTS.md` completion checks
   are recorded here as NOT run.

4. **hide-pid — RESOLVED per explicit owner override 2026-10-16.**
   `AGENTS.md` "Post-install integrity checks" requires hiding the app via
   the memd hide API, which conflicts with the same file's no-stealth /
   no-concealment purpose clause. Owner decision (2026-10-16): hiding IS
   required, but ONLY via an explicit user action — a visible toggle/button
   with explanatory UI copy — never silently, never by default, never as an
   undocumented side effect. This is a NAMED exception to the `AGENTS.md`
   no-stealth rule, not a repeal of it: every other privileged action stays
   under the original user-initiated / visible / explained constraint.
   Status: call contracts for ops 14/21/22 documented read-only in
   `INTEGRATION.md`; NOT yet wired to app UI or the JNI bridge
   (`native/memd_bridge.c` covers version/learn/bootstrap/load/unload
   only). Any future wiring must follow the explicit-action-only rule and
   update `README.md` + UI copy together.

5. **Example Module intentionally untouched.** No example / sample MEMD
   module is added or modified in this change until the module architecture
   (entry ABI usage, packaging, load/unload UX) is settled. Greenfield
   scaffolding only; do not treat any sample as an integration target.
