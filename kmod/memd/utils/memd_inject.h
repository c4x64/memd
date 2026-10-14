#ifndef MEMD_INJECT_H
#define MEMD_INJECT_H

#include <linux/types.h>

/* Remote .so injection (loadsotoapp / loadsosutoapp).
 *
 * loadsotoapp: dlopen(path) executed inside the target process via a
 * briefly-hijacked stopped thread. No credentials are touched.
 *
 * loadsosutoapp: same, but the target's uid/capabilities are elevated
 * for the duration of the dlopen call only (uid 0 + all capabilities,
 * using proven cred offsets), then restored verbatim before resume.
 * Elevation applies to the library's constructor execution, never
 * persistently to the app. euid/fsuid numeric identity is deliberately
 * NOT rewritten (offsets unproven) — documented, not guessed.
 *
 * Tracelessness: MEMD_LOADSO_EPHEMERAL dlcloses after init returns, so
 * the linker itself unmaps the library and drops it from its lists
 * (no maps entries, no solist entry — removed by the linker, not by
 * us). Resident mode leaves normal linker traces; hiding /proc maps
 * content needs a seq_file show hook (explicit follow-up, not here).
 *
 * The .so path must be absolute and visible in the TARGET's mount
 * namespace (/data/local/tmp paths work everywhere). Every stage is
 * verified before proceeding; any failure restores saved state
 * (regs, creds) and SIGCONTs before returning -errno. Nothing
 * succeeds partially.
 */
struct memd_loadso_cmd {
    pid_t pid;           /* Input: target process (or thread) ID */
    char path[256];      /* Input: absolute .so path, NUL-terminated */
    int flags;           /* Input: MEMD_LOADSO_* bits */
    int result;          /* Output: 0 ok, else -errno */
    uintptr_t handle;    /* Output: dlopen handle (0 if ephemeral/failed) */
};

/* dlclose right after the constructor returns: linker unloads the
 * library itself (see above). Omit for a resident injection. */
#define MEMD_LOADSO_EPHEMERAL 1

#endif /* MEMD_INJECT_H */
