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
 * After a successful dlopen, a named ENTRY symbol may be executed in
 * the target (same hijack machinery, handle passed in x0): constructors
 * already ran inside dlopen, so entry is for explicit payload startup.
 * In ephemeral mode the order is dlopen -> entry -> dlclose, all inside
 * one su window when requested.
 *
 * Stealth hygiene: the below-sp scratch (stub, path, flags) is wiped
 * before the final SIGCONT, so no payload bytes linger in target stack
 * memory (readable via /proc/pid/mem or core dumps).
 *
 * Concurrency: inject/unload serialize on one global mutex (interruptible
 * wait). Same-target inject-vs-unload is sequential (unload sees the
 * inject's completed state); different-target injects queue for up to the
 * ~35s worst-case hold — bounded, admin-only, abortable with -ERESTARTSYS
 * (ioctl return, mirrored in result).
 * Only one thread per target is hijacked; siblings group-stop and resume
 * untouched, so single-thread selection is sound for multithreaded apps.
 *
 * Timeout: a call (dlopen/entry/dlclose) that never sets its done flag
 * is re-STOPped and register-restored, returning -ETIMEDOUT with the
 * target alive (an infinite-loop entry does NOT kill); SIGKILL happens
 * only when recapture/restore itself fails. A timed-out entry leaves the
 * dlopen handle installed for a later unload.
 *
 * The .so path must be absolute and visible in the TARGET's mount
 * namespace (/data/local/tmp paths work everywhere). The entry lookup
 * matches the library by BASENAME, so it must be unique in the target.
 * Every stage is verified before proceeding; any failure restores saved
 * state (regs, creds) and SIGCONTs before returning -errno. Nothing
 * succeeds partially.
 */
struct memd_loadso_cmd {
    pid_t pid;           /* Input: target process (or thread) ID */
    char path[256];      /* Input: absolute .so path, NUL-terminated */
    char entry[64];      /* Input: symbol to call after dlopen ("" = skip) */
    int flags;           /* Input: MEMD_LOADSO_* bits */
    int result;          /* Output: 0 ok, else -errno */
    uintptr_t handle;    /* Output: dlopen handle (0 if ephemeral/failed) */
    int entry_result;    /* Output: entry return, truncated to int */
};

/* dlclose right after the constructor returns: linker unloads the
 * library itself (see above). Omit for a resident injection. */
#define MEMD_LOADSO_EPHEMERAL 1

/* Hotswap unload command (MEMD_IOCTL_LOADSO_UNLOAD): remote
 * dlclose(handle) in the target. On success the library is gone and
 * handle is zeroed; on failure the handle is preserved for retry. */
struct memd_loadso_unload_cmd {
    pid_t pid;           /* Input: target process (or thread) ID */
    uintptr_t handle;    /* Input: dlopen handle; zeroed on success */
    int result;          /* Output: 0 ok, else -errno */
};

#endif /* MEMD_INJECT_H */
/* kmod/memd/utils/memd_inject.h[∂] */
