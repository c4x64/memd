#ifndef MEMD_HIJACK_X86_H
#define MEMD_HIJACK_X86_H

#include <linux/types.h>
#include <linux/kernel.h>

/* x86_64 inline hooking: patch function entry with a 5-byte relative
 * jump (E9 xx xx xx xx) or 14-byte absolute jump for targets beyond
 * ±2GB. No BTI landing pads required (x86 has no BTI). */

/* Maximum number of tracked hooks for cleanup. */
#define MEMD_X86_MAX_HOOKS 64

struct memd_x86_hook {
    void     *target;       /* original function entry */
    void     *replacement;  /* replacement function */
    void     *trampoline;   /* allocated trampoline (original + jump back) */
    u8        original[14];  /* saved original bytes */
    size_t    patch_len;    /* 5 or 14 */
    int       active;       /* 1 if hook is installed */
};

/* Initialize the x86 hook framework. */
int memd_x86_hook_init(void);

/* Install a hook: patch target to jump to replacement. */
int memd_x86_hook_install(void *target, void *replacement);

/* Remove a hook: restore original bytes. */
int memd_x86_hook_remove(void *target);

/* Remove all hooks. Called from module_exit. */
void memd_x86_hook_remove_all(void);

/* Check if a target is hooked. */
int memd_x86_hook_is_installed(void *target);

/* Get hook count. */
int memd_x86_hook_count(void);

/* x86 page permission helpers (CR0 WP bit). */
int memd_x86_make_rw(void *addr, size_t len);
int memd_x86_make_ro(void *addr, size_t len);

/* x86 cache flush (unified cache, no-op for instruction cache). */
void memd_x86_cache_flush(void *addr, size_t len);

/* x86 KASLR slide detection. */
unsigned long memd_x86_kaslr_slide(void);

/* Translate compile-time address to runtime. */
void *memd_x86_runtime_addr(void *compile_addr);

#endif /* MEMD_HIJACK_X86_H */
/* linux/x86/kmod/memd/inlinehook/hijack_x86.h[∂] */