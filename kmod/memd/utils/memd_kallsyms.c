/* /proc/kallsyms self-parse resolver. See header for the universality
 * argument. File access itself arrives via MEMD_IOCTL_BOOTSTRAP; no
 * file helper is directly imported. */
#include "memd_kallsyms.h"

#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

/* Fixed wanted list: every kallsyms consumer in the tree resolves through
 * here. Exact names, no prefixes (a prefix match on "get_vm_area" would
 * also hit "get_vm_area_caller" — wrong). */
static const char *memd_wanted[] = {
    "aarch64_insn_write",
    "caches_clean_inval_pou",
    "__flush_icache_range",
    "filp_open",
    "filp_close",
    "kprobe_blacklist",
    "get_cmdline",
    "prepare_creds",
    "commit_creds",
    "ioremap_page_range",
    "free_vm_area",
    "__get_vm_area_caller",
    "get_vm_area_caller",
    "__cfi_slowpath",
    "__cfi_slowpath_diag",
    "_cfi_slowpath",
    "__cfi_check_fail",
    "__ubsan_handle_cfi_check_fail_abort",
    "__ubsan_handle_cfi_check_fail",
    /* CFI-bypass patch targets (utils/memd_utils.c cfi_bypass): every
     * literal passed to cfi_patch_ret/cfi_bypass_* must be listed —
     * unlisted names fail closed to 0 and silently skip patching. */
    "report_cfi_failure",
    "cfi_slowpath",
    "__cfi_verify",
    "__kcfi_check_fail",
    "__ubsan_handle_type_mismatch_v1",
    "__ubsan_handle_type_mismatch",
    "__ubsan_handle_builtin_unreachable",
    "__ubsan_handle_pointer_overflow",
    "__ubsan_handle_load_invalid_value",
    "__ubsan_handle_out_of_bounds",
    "__ubsan_handle_shift_out_of_bounds",
    "__ubsan_handle_divrem_overflow",
    "__ubsan_handle_mul_overflow",
    "__ubsan_handle_negate_overflow",
    "__ubsan_handle_float_cast_overflow",
    "__ubsan_handle_invalid_builtin",
    "__ubsan_handle_cfi_bad_type",
    "kcfi_failure",
    "kcfi_type_mismatch",
    "kcfi_check_fail_diag",
    "kallsyms_lookup_name",
    "pfn_valid",
    "max_pfn",
    "find_vma",
    "__find_vma",
    /* Page table allocation (ioctl/memd_ioctl.c) */
    "__pmd_alloc",
    "__pte_alloc",
    /* CFI bypass symbols (utils/memd_utils.c) */
    "__kcfi_check",
    "kcfi_typeid",
    "kcfi_verify",
    "kcfi_check_fail",
    "kcfi_diag",
    /* PAN/UAO symbols (utils/memd_utils.c) */
    "__uaccess_begin_pan",
    "__uaccess_end_pan",
    "__uaccess_begin_uao",
    "__uaccess_end_uao",
    "user_access_begin",
    "user_access_end",
    /* PAC symbols (utils/memd_utils.c) */
    "__pacia_el0",
    "__pacib_el0",
    "__pacda_el0",
    "__pacdb_el0",
    "pac_generic",
    "strip_pac",
    /* KPTI symbols (utils/memd_utils.c) */
    "kpti_init",
    "kpti_enable",
    "kpti_disable",
    "kpti_isolate_kernel",
    "kpti_unmap_user",
    "swapper_pg_dir",
    /* MTE symbols (utils/memd_utils.c) */
    "mte_check_sync_fault",
    "mte_check_async_fault",
    "mte_set_tag",
    "mte_exclude_range",
    /* BTI symbols (utils/memd_utils.c) */
    "bti_exception",
    "bti_pad_check",
    /* Credential override symbols (utils/memd_utils.c) */
    "override_creds",
    "revert_creds",
    /* Commented-out but reserved for future use (ioctl/memd_ioctl.c) */
    "wake_up_new_task",
    "copy_process",
    /* Remote-call engine (inject/memd_inject.c): stop/wait + icache */
    "wait_task_inactive",
    "flush_dcache_page",
    /* Indirect-call wrappers (utils/memd_utils.c): resolved, never
     * imported, so trimmed/GKI-protected kernels still load. */
    "kernel_read",
    "vprintk",
    "__put_cred",
    "send_signal",
    "do_send_sig_info",
    "set_memory_x",
    /* Display DRM probe (display/soc_drm.c via memd_kallsyms) */
    "drm_class",
    "drm_client_init",
    "drm_client_release",
    "drm_client_framebuffer_create",
    "drm_client_buffer_vmap",
    "drm_client_buffer_vunmap",
    "drm_client_modeset_commit",
};

#define MEMD_NWANT (sizeof(memd_wanted) / sizeof(memd_wanted[0]))

static unsigned long memd_addrs[sizeof(memd_wanted) / sizeof(memd_wanted[0])];
static bool memd_parsed;
static bool memd_unavailable;

/* Bootstrap epoch: incremented under memd_klock on every bootstrap.
 * Parses snapshot it with the helper triple and publish only when it
 * still matches, so a pre-bootstrap (stale) parse can never clobber a
 * post-bootstrap table, and the unavailable retry below runs once per
 * epoch instead of once per lookup. memd_parsed_gen is the epoch of
 * the currently published table. Both live under memd_klock. */
static unsigned long memd_gen;
static unsigned long memd_parsed_gen;

/* Publish lock: lookups may run on any CPU/context while the
 * bootstrap ioctl re-arms on another. Parsing itself uses only a
 * stack-local table plus file IO (may sleep), so the lock is held
 * purely for the flag/table flip — never across IO. */
static DEFINE_SPINLOCK(memd_klock);

/* Bootstrap file access. GKI kernels protect filp_open/kernel_read
 * from unsigned modules, so direct imports would refuse the load.
 * Userspace (which can read /proc/kallsyms after lowering
 * kptr_restrict) delivers the real addresses via MEMD_IOCTL_BOOTSTRAP
 * once, right after install. Zero means unset: file-backed resolution
 * stays unavailable and every consumer fails closed. */
static struct file *(*my_filp_open)(const char *, int, umode_t);
static ssize_t (*my_kernel_read)(struct file *, void *, size_t, loff_t *);
static void (*my_filp_close)(struct file *, fl_owner_t);

int memd_kallsyms_bootstrap(unsigned long fo, unsigned long kr, unsigned long fc)
 {
    unsigned long flags;
    if ((fo & 0xffff000000000000UL) != 0xffff000000000000UL ||
        (kr & 0xffff000000000000UL) != 0xffff000000000000UL ||
        (fc & 0xffff000000000000UL) != 0xffff000000000000UL)
        return -EINVAL;
    spin_lock_irqsave(&memd_klock, flags);
    /* Triple + epoch under one lock hold: a concurrent parse snapshots
     * an atomic triple and an epoch, never a mix of two bootstraps. */
    WRITE_ONCE(my_filp_open, (void *)fo);
    WRITE_ONCE(my_kernel_read, (void *)kr);
    WRITE_ONCE(my_filp_close, (void *)fc);
    memd_gen++;
    /* Re-arm: an earlier attempt may have parsed (and failed) already.
     * WRITE_ONCE: memd_parsed also has a lock-free READ_ONCE fast path
     * in memd_kallsyms(), so the publishing stores must not be plain
     * (plain-under-lock + lock-free-READ_ONCE is a mixed discipline —
     * torn/stale reads on weak memory). */
    WRITE_ONCE(memd_parsed, false);
    WRITE_ONCE(memd_unavailable, false);
    memset(memd_addrs, 0, sizeof(memd_addrs));
    spin_unlock_irqrestore(&memd_klock, flags);
    return 0;
}

static int memd_want_index(const char *name)
 {
    unsigned long i;
    for (i = 0; i < MEMD_NWANT; i++) {
        if (!strcmp(name, memd_wanted[i]))
            return (int)i;
    }
    return -1;
}

/* Parse one "addr type name" line. Returns 1 when it filled an entry. */
static int memd_parse_line(const char *line, size_t len, unsigned long *addrs)
 {
    unsigned long addr = 0;
    size_t i = 0, j;
    int idx;
    char name[128];
    size_t nlen;

    /* hex address */
    while (i < len) {
        char c = line[i];
        unsigned v;
        if (c >= '0' && c <= '9')
            v = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v = (unsigned)(c - 'A' + 10);
        else
            break;
        addr = (addr << 4) | v;
        i++;
    }
    if (i == 0 || i >= len || line[i] != ' ')
        return 0;
    i++;
    if (i >= len)
        return 0;
    /* type char (any) */
    i++;
    if (i >= len || line[i] != ' ')
        return 0;
    i++;
    /* name to space/EOL */
    j = i;
    while (j < len && line[j] != ' ' && line[j] != '\n' &&
           line[j] != '\r' && line[j] != '\t')
        j++;
    nlen = j - i;
    if (nlen == 0 || nlen >= sizeof(name))
        return 0;
    memcpy(name, line + i, nlen);
    name[nlen] = '\0';
    idx = memd_want_index(name);
    if (idx < 0 || addrs[idx] != 0)
        return 0;
    addrs[idx] = addr;
    return 1;
}

/* Publish a fully parsed table only when it belongs to the current
 * epoch: single locked flip so concurrent lookups never observe a
 * half-zeroed (bootstrap) or half-filled (double parse) table, and a
 * stale pre-bootstrap parse can never clobber a post-bootstrap table.
 * Returns 1 on publish, 0 when stale (caller discards; the next
 * lookup re-parses at the new epoch). Fail closed either way. */
static int memd_publish_if_current(unsigned long *tmp, unsigned long gen)
 {
    unsigned long flags;
    unsigned long i;
    unsigned long nonzero = 0;
    for (i = 0; i < MEMD_NWANT; i++)
        nonzero += tmp[i] ? 1 : 0;
    spin_lock_irqsave(&memd_klock, flags);
    if (gen != memd_gen) {
        spin_unlock_irqrestore(&memd_klock, flags);
        return 0;
    }
    memcpy(memd_addrs, tmp, sizeof(memd_addrs));
    /* WRITE_ONCE (see bootstrap re-arm): lock-free READ_ONCE fast path
     * outside this lock must pair with a marked store. */
    WRITE_ONCE(memd_parsed, true);
    /* kptr_restrict renders every address 0: detect and mark so callers
     * fail soft once instead of per-call. A zero table with successful
     * reads means hidden, not absent. */
    WRITE_ONCE(memd_unavailable, (nonzero == 0));
    memd_parsed_gen = gen;
    spin_unlock_irqrestore(&memd_klock, flags);
    return 1;
}

static void memd_do_parse(void)
 {
    struct file *f;
    char *buf;
    loff_t pos = 0;
    ssize_t n;
    size_t carry = 0;
    size_t req = 0;
    int found = 0;
    unsigned long tmp[MEMD_NWANT];
    struct file *(*open_fn)(const char *, int, umode_t);
    ssize_t (*read_fn)(struct file *, void *, size_t, loff_t *);
    void (*close_fn)(struct file *, fl_owner_t);
    unsigned long gen;
    unsigned long flags;

    memset(tmp, 0, sizeof(tmp));
    /* Snapshot triple + epoch under the lock: the bootstrap may re-arm
     * under us; a torn triple or a stale publish must not corrupt the
     * walk or clobber a newer table. File IO itself stays outside the
     * lock (it may sleep). */
    spin_lock_irqsave(&memd_klock, flags);
    open_fn = READ_ONCE(my_filp_open);
    read_fn = READ_ONCE(my_kernel_read);
    close_fn = READ_ONCE(my_filp_close);
    gen = memd_gen;
    spin_unlock_irqrestore(&memd_klock, flags);
    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) {
        (void)memd_publish_if_current(tmp, gen);
        return;
    }
    if (!open_fn || !read_fn || !close_fn) {
        /* No bootstrap table yet (see MEMD_IOCTL_BOOTSTRAP). */
        kfree(buf);
        (void)memd_publish_if_current(tmp, gen);
        return;
    }
    f = open_fn("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f)) {
        (void)memd_publish_if_current(tmp, gen);
        kfree(buf);
        return;
    }
    while (1) {
        size_t avail;
        size_t start = 0, eol;
        req = 4096 - carry - 1;
        n = read_fn(f, buf + carry, req, &pos);
        if (n <= 0) {
            /* Trailing bytes without '\n' still form a line. */
            if (carry > 0)
                found += memd_parse_line(buf, carry, tmp);
            break;
        }
        avail = carry + (size_t)n;
        buf[avail] = '\0';
        /* process complete lines; keep the tail carry */
        while (start < avail) {
            eol = start;
            while (eol < avail && buf[eol] != '\n')
                eol++;
            if (eol >= avail)
                break;
            found += memd_parse_line(buf + start, eol - start, tmp);
            start = eol + 1;
            if ((unsigned long)found >= MEMD_NWANT)
                break;
        }
        if ((unsigned long)found >= MEMD_NWANT)
            break;
        carry = avail - start;
        if (carry >= 2048) {
            /* absurd single line: drop it rather than overflow */
            carry = 0;
        } else if (carry > 0 && start > 0) {
            memmove(buf, buf + start, carry);
        }
        if (n < (ssize_t)req) {
            /* EOF: a tail without '\n' is still a line. */
            if (carry > 0)
                found += memd_parse_line(buf, carry, tmp);
            break; /* EOF */
        }
    }
    close_fn(f, NULL);
    kfree(buf);
    (void)memd_publish_if_current(tmp, gen);
}

unsigned long memd_kallsyms(const char *name)
 {
    int idx;
    unsigned long addr;
    unsigned long flags;
    int helpers;
    if (!name)
        return 0;
    if (!READ_ONCE(memd_parsed))
        memd_do_parse();
    spin_lock_irqsave(&memd_klock, flags);
    if (memd_unavailable) {
        helpers = READ_ONCE(my_filp_open) && READ_ONCE(my_kernel_read) &&
                  READ_ONCE(my_filp_close);
        if (helpers && memd_parsed_gen != memd_gen) {
            spin_unlock_irqrestore(&memd_klock, flags);
            /* Bootstrap armed mid-parse, or re-armed after a hidden
             * (all-zero) parse: our snapshot predates the helpers, so
             * re-parse once at the new epoch (outside the lock: file
             * IO may sleep) instead of wedging. Latched per epoch
             * below, so a persistently hidden kallsyms costs one
             * parse per bootstrap, not one per lookup. */
            memd_do_parse();
            spin_lock_irqsave(&memd_klock, flags);
            if (memd_unavailable) {
                spin_unlock_irqrestore(&memd_klock, flags);
                return 0;
            }
        } else {
            spin_unlock_irqrestore(&memd_klock, flags);
            return 0;
        }
    }
    idx = memd_want_index(name);
    addr = (idx < 0) ? 0 : memd_addrs[idx];
    spin_unlock_irqrestore(&memd_klock, flags);
    return addr;
}
/* kmod/memd/utils/memd_kallsyms.c[∂] */
