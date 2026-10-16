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

4. **hide-pid CONFLICT — DO NOT IMPLEMENT.** `AGENTS.md` "Post-install
   integrity checks" asks to hide the app's pid via the memd hide API, but
   the same file's binding purpose clause forbids stealth, concealment,
   security-control bypasses, and undocumented persistence. Hiding a pid from
   userspace detectors is concealment. Per the task's binding hard rules
   (no-stealth wins), pid-hiding is NOT implemented anywhere in this scaffold
   and no `HIDE_PROCESS`/`HIDE_INSTALL` call exists in the app. Owner
   decision required: either remove the hide-pid line from `AGENTS.md` or
   grant an explicit, documented exception with user-visible disclosure —
   until then, the no-stealth rule governs.
