/* Remote .so injection (loadsotoapp / loadsosutoapp).
 *
 * Mechanism (parasite, fail-closed at every stage):
 *  1. validate args + resolve target task/mm (refs held throughout).
 *  2. libc base via get_module_base; dlopen/dlclose via a read-only
 *     ELF64 parser over memd_copy_from_task (bounded reads, all checked).
 *  3. SIGSTOP the group + wait_task_inactive(TASK_STOPPED) with timeout.
 *  4. locate the stopped thread's user pt_regs: stack base from learned
 *     t_stack, size from memd_thread_size(), regs at top-272; exactly
 *     one sane candidate (pc/sp/pstate checks) or abort.
 *  5. write stub + path + flag words into below-sp scratch with
 *     memd_copy_to_task (writes verified by return code), flush each
 *     touched page for icache coherence, save regs, set pc/x0/x19/lr
 *     (readback-verified), SIGCONT, poll the flag with timeout.
 *  6. re-STOP, restore saved regs (verified), optional dlclose round
 *     (ephemeral), su restore, final SIGCONT, drop refs.
 * Any failure restores what it changed and SIGCONTs before returning
 * -errno. Nothing succeeds partially; the target never resumes with
 * hijacked regs (restore always precedes the final SIGCONT).
 *
 * su variant: uid@4 -> 0 plus cap_effective/cap_permitted -> all-ones,
 * using proven/learned cred offsets only (euid/fsuid untouched —
 * offsets unproven — documented in memd_inject.h). Cred object pinned
 * with a manual refcount bump (usage@0, stable) so a concurrent
 * SIGKILL cannot free it mid-window; __put_cred drops it at the end.
 * (Deliberately NOT get_cred()/put_cred(): their validate path trusts
 * build-header magic offset and would BUG on foreign layouts.)
 */
#include "memd_inject.h"

#include "memd_common.h"
#include "memd_ioctl.h"
#include "memd_learn.h"
#include "memd_uaccess.h"
#include "memd_utils.h"

#include <asm/page.h>
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/signal.h>
#include <linux/string.h>

/* Timing budget vs mutex hold (DoS lens). Every remote_call runs under
 * memd_inj_mutex because the seize/hijack/restore sequence must be atomic
 * against a concurrent inject/unload on the SAME target (shared below-SP
 * scratch and saved-regs window per thread). Different targets use
 * disjoint scratch, so a per-target lock could allow parallelism — and is
 * deliberately NOT used: it needs a dynamic per-pid lock table with
 * lifetime/GFP races in kernel context for no privilege gain (callers
 * are CAP_SYS_ADMIN-only; an unprivileged target cannot weaponize the
 * wait). A worst-case inject holds the mutex ~5s (seize) + 3x10s
 * (dlopen, entry, dlclose) ~= 35s. The 10s per-call budget stands: real
 * constructors (relocations, dex work on low-end parts) take seconds
 * and a shorter fuse would turn slow targets into spurious
 * recapture-kills. The hog is bounded, fail-closed (timeout always
 * recaptures or kills, never leaks a hijacked thread), and the wait is
 * interruptible (mutex_lock_interruptible), so a second admin ioctl can
 * abort with -ERESTARTSYS as the ioctl return (mirrored in result)
 * instead of hanging unkillably. Do not shorten
 * without measuring slow-device init. */
#define MEMD_INJ_SEIZE_TRIES 250   /* 250 x 20ms = 5s to reach STOPPED */
#define MEMD_INJ_CALL_TRIES  500   /* 500 x 20ms = 10s for dlopen return */
#define MEMD_INJ_POLL_MS     20
#define MEMD_INJ_SCRATCH_BELOW 1024 /* below-sp scratch window (bytes) */
#define MEMD_INJ_STUB_WORDS  11 /* movz/movk x4 + blr + str + dmb + movz + str + b. */
#define MEMD_INJ_RTLD_NOW    2     /* RTLD_NOW, stable dlopen ABI */
#define MEMD_INJ_ELF_MAX_PHDR 32
#define MEMD_INJ_ELF_MAX_DYN  48
#define MEMD_INJ_SYM_WALK_MAX 100000
#define MEMD_INJ_NAME_MAX    128
#define MEMD_INJ_STRSZ_MAX   (16UL << 20)
/* DT_GNU_HASH is absent from linux/elf.h; stable dynamic-tag ABI. */
#define MEMD_DT_GNU_HASH 0x6ffffef5u

/* arm64 instruction encoders (exact; consistent with the masks already
 * used in hijack_arm64.c). */
#define MEMD_MOVZ(rd, imm16, hw) \
    (0xD2800000u | ((unsigned int)(hw) << 21) | ((unsigned int)(imm16) << 5) | (unsigned int)(rd))
#define MEMD_MOVK(rd, imm16, hw) \
    (0xF2800000u | ((unsigned int)(hw) << 21) | ((unsigned int)(imm16) << 5) | (unsigned int)(rd))
#define MEMD_BLR(rn) (0xD63F0000u | ((unsigned int)(rn) << 5))
#define MEMD_STR_X_X8(rt, rn) (0xF9000000u | (1u << 10) | ((unsigned int)(rn) << 5) | (unsigned int)(rt))
#define MEMD_STR_X_X(rt, rn) (0xF9000000u | ((unsigned int)(rn) << 5) | (unsigned int)(rt))
#define MEMD_B_DOT 0x14000000u
#define MEMD_DMB_ISH 0xD5033BBFu /* DMB ISH: order retval before done flag */

/* user_pt_regs layout (arm64 UAPI, immutable): x0..x30, sp, pc, pstate. */
#define MEMD_PT_SP     31
#define MEMD_PT_PC     32
#define MEMD_PT_PSTATE 33
#define MEMD_PT_NREGS  34

/* Proven struct cred head layout (same basis as memd_capable/mem..._uid):
 * usage counter at +0, uid value at +memd_cred_uid_off() (compiled 4,
 * learned t_cred_uid when known). cap offsets come from the
 * learned t_cred_cap_* (fallback: cap_effective at +56). */
#define MEMD_CRED_USAGE_MAX 100000u

static int (*my_wait_task_inactive)(struct task_struct *, unsigned int);
static bool wait_probed;
static void (*my_flush_dcache_page)(struct page *);
static bool flush_probed;

static int memd_task_copy_ok(struct task_struct *t, int to_task,
                             unsigned long user_va, void *kbuf, size_t len)
 {
    unsigned long rem;
    if (!t || !kbuf || !len)
        return -EFAULT;
    if (to_task)
        rem = memd_copy_to_task(t, user_va, kbuf, len);
    else
        rem = memd_copy_from_task(t, kbuf, user_va, len);
    return rem == 0 ? 0 : -EFAULT;
}

static int resolve_runtime_helpers(void)
 {
    if (!wait_probed) {
        wait_probed = true;
        my_wait_task_inactive =
            (void *)kallsyms_lookup_name_ex("wait_task_inactive");
    }
    if (!flush_probed) {
        flush_probed = true;
        my_flush_dcache_page =
            (void *)kallsyms_lookup_name_ex("flush_dcache_page");
    }
    if (!my_wait_task_inactive || !my_flush_dcache_page)
        return -ENODEV;
    return 0;
}

/* ---- ELF64 dlopen/dlclose resolver (read-only, fully bounded) ---- */
struct memd_elf_addrs {
    uintptr_t dlopen_va;
    uintptr_t dlclose_va;
};

static unsigned long memd_elf_hash(const char *s)
 {
    unsigned long h = 0, g;
    while (*s) {
        h = (h << 4) + (unsigned long)(unsigned char)*s++;
        g = h & 0xf0000000UL;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

static unsigned long memd_gnu_hash(const char *s)
 {
    unsigned long h = 5381;
    while (*s)
        h = h * 33 + (unsigned long)(unsigned char)*s++;
    return h;
}

static int memd_elf_sym(struct task_struct *t, uintptr_t symtab,
                        uintptr_t strtab, unsigned long strsz,
                        unsigned long idx, const char *want, size_t wantlen,
                        uintptr_t bias, uintptr_t *out)
 {
    Elf64_Sym sym;
    char name[MEMD_INJ_NAME_MAX];
    unsigned long u;
    /* Zero so a short tail copy (near end of strsz) cannot leave
     * uninitialized bytes inside the memcmp window. */
    memset(name, 0, sizeof(name));
    if (idx > (unsigned long)MEMD_INJ_SYM_WALK_MAX)
        return -1;
    if (memd_task_copy_ok(t, 0, symtab + idx * sizeof(sym), &sym, sizeof(sym)))
        return -1;
    if (sym.st_shndx == SHN_UNDEF || sym.st_value == 0)
        return -1;
    if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC)
        return -1;
    if ((unsigned long)sym.st_name >= strsz)
        return -1;
    u = strsz - (unsigned long)sym.st_name;
    if (u > sizeof(name))
        u = sizeof(name);
    if (memd_task_copy_ok(t, 0, strtab + (unsigned long)sym.st_name, name, (size_t)u))
        return -1;
    name[sizeof(name) - 1] = '\0';
    if (memcmp(name, want, wantlen + 1))
        return -1;
    *out = bias + (uintptr_t)sym.st_value;
    return 0;
}

static int memd_elf_lookup(struct task_struct *t, uintptr_t symtab,
                            uintptr_t strtab, unsigned long strsz,
                            uintptr_t hashtab, uintptr_t gnuhash,
                            const char *want, uintptr_t bias, uintptr_t *out)
 {
    size_t wantlen;
    unsigned long h, i, n, nbucket, nchain, bkt, symoff;
    unsigned long w;
    u32 w32;
    wantlen = strlen(want);
    if (wantlen == 0 || wantlen + 1 >= MEMD_INJ_NAME_MAX)
        return -ENOENT;
    /* GNU hash first (what modern Bionic emits), then SYSV. */
    if (gnuhash) {
        /* ELF64 GNU-hash header is four u32 words (nbuckets, symoffset,
         * bloom_size, bloom_shift); bloom words follow at +16. */
        unsigned long nbuckets, bloom_size;
        u32 nbuckets32 = 0, symoff32 = 0, bloom32 = 0, shift32 = 0;
        if (memd_task_copy_ok(t, 0, gnuhash, &nbuckets32, 4))
            return -EFAULT;
        if (memd_task_copy_ok(t, 0, gnuhash + 4, &symoff32, 4))
            return -EFAULT;
        if (memd_task_copy_ok(t, 0, gnuhash + 8, &bloom32, 4))
            return -EFAULT;
        if (memd_task_copy_ok(t, 0, gnuhash + 12, &shift32, 4))
            return -EFAULT;
        (void)shift32;
        nbuckets = nbuckets32;
        symoff = symoff32;
        bloom_size = bloom32;
        if (nbuckets == 0 || nbuckets > 100000 || bloom_size == 0 ||
            bloom_size > 1024)
            return -ENOENT;
        /* symoff is a symtab index: anything past SYM_WALK_MAX can
         * never resolve (memd_elf_sym rejects it), so reject a
         * hostile table early instead of walking it. */
        if (symoff > (unsigned long)MEMD_INJ_SYM_WALK_MAX)
            return -ENOENT;
        h = memd_gnu_hash(want);
        if (memd_task_copy_ok(t, 0, gnuhash + 16 + (h / 64 % bloom_size) * 8, &w, 8))
            return -EFAULT;
        if (!((w >> (h % 64)) & 1))
            return -ENOENT;
        if (memd_task_copy_ok(t, 0,
                              gnuhash + 16 + bloom_size * 8 + (h % nbuckets) * 4,
                              &w32, 4))
            return -EFAULT;
        bkt = w32;
        /* Bucket is a symtab index with the same ceiling: past
         * SYM_WALK_MAX no chain element can resolve, so fail fast
         * on a hostile bucket instead of walking to the cap. */
        if (bkt > (unsigned long)MEMD_INJ_SYM_WALK_MAX)
            return -ENOENT;
        if (bkt < symoff)
            return -ENOENT;
        for (i = bkt, n = 0; n < (unsigned long)MEMD_INJ_SYM_WALK_MAX; i++, n++) {
            unsigned long cw;
            w32 = 0;
            if (memd_task_copy_ok(t, 0,
                                  gnuhash + 16 + bloom_size * 8 +
                                  nbuckets * 4 + (i - symoff) * 4,
                                  &w32, 4))
                return -EFAULT;
            cw = w32;
            if ((cw & ~1UL) == (h & ~1UL)) {
                if (!memd_elf_sym(t, symtab, strtab, strsz, i, want,
                                  wantlen, bias, out))
                    return 0;
            }
            if (cw & 1)
                break;
        }
        return -ENOENT;
    }
    if (hashtab) {
        /* 4-byte table fields: read into a u32 first so the upper half
         * of the 8-byte locals cannot retain stack garbage (arm64 LE). */
        w32 = 0;
        if (memd_task_copy_ok(t, 0, hashtab, &w32, 4))
            return -EFAULT;
        nbucket = w32;
        w32 = 0;
        if (memd_task_copy_ok(t, 0, hashtab + 4, &w32, 4))
            return -EFAULT;
        nchain = w32;
        if (nbucket == 0 || nbucket > 100000 || nchain == 0 ||
            nchain > (unsigned long)MEMD_INJ_SYM_WALK_MAX)
            return -ENOENT;
        h = memd_elf_hash(want);
        w32 = 0;
        if (memd_task_copy_ok(t, 0, hashtab + 8 + (h % nbucket) * 4, &w32, 4))
            return -EFAULT;
        bkt = w32;
        for (i = bkt, n = 0;
             i != 0 && n < (unsigned long)MEMD_INJ_SYM_WALK_MAX;
             n++) {
            unsigned long nx;
            if (i >= nchain)
                return -ENOENT;
            if (!memd_elf_sym(t, symtab, strtab, strsz, i, want,
                              wantlen, bias, out))
                return 0;
            w32 = 0;
            if (memd_task_copy_ok(t, 0,
                                  hashtab + 8 + nbucket * 4 + i * 4, &w32, 4))
                return -EFAULT;
            nx = w32;
            i = nx;
        }
        return -ENOENT;
    }
    return -ENOENT;
}

struct memd_elf_dyn {
    uintptr_t bias;
    uintptr_t strtab;
    uintptr_t symtab;
    unsigned long strsz;
    uintptr_t hash;
    uintptr_t ghash;
};

/* Parse headers + dynamic section of a loaded ET_DYN (path lookup shared
 * by libc symbol resolution and payload entry resolution). */
static int parse_dynamic(struct task_struct *t, uintptr_t base,
                          struct memd_elf_dyn *di)
 {
    Elf64_Ehdr eh;
    Elf64_Phdr ph;
    Elf64_Dyn dyn;
    unsigned long min_vaddr, dyn_rva;
    int i, np;
    memset(di, 0, sizeof(*di));
    if (!t || !base)
        return -EFAULT;
    if (memd_task_copy_ok(t, 0, base, &eh, sizeof(eh)))
        return -EFAULT;
    if (eh.e_ident[EI_MAG0] != ELFMAG0 || eh.e_ident[EI_MAG1] != ELFMAG1 ||
        eh.e_ident[EI_MAG2] != ELFMAG2 || eh.e_ident[EI_MAG3] != ELFMAG3 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_type != ET_DYN || eh.e_machine != EM_AARCH64 ||
        eh.e_phentsize != sizeof(ph) || eh.e_phnum == 0 ||
        eh.e_phnum > MEMD_INJ_ELF_MAX_PHDR || eh.e_phoff >= (1UL << 20))
        return -ENOEXEC;
    /* File offset -> runtime via the LOAD walk (never assume LOAD #0). */
    min_vaddr = (unsigned long)-1;
    dyn_rva = 0;
    for (i = 0, np = eh.e_phnum; i < np; i++) {
        if (memd_task_copy_ok(t, 0,
                              base + (unsigned long)eh.e_phoff +
                              (unsigned long)i * sizeof(ph),
                              &ph, sizeof(ph)))
            return -EFAULT;
        if (ph.p_type == PT_LOAD && (unsigned long)ph.p_vaddr < min_vaddr)
            min_vaddr = (unsigned long)ph.p_vaddr;
        if (ph.p_type == PT_DYNAMIC && !dyn_rva)
            dyn_rva = (unsigned long)ph.p_vaddr;
    }
    if (min_vaddr == (unsigned long)-1 || !dyn_rva)
        return -ENOEXEC;
    di->bias = base - min_vaddr;
    for (i = 0; i < MEMD_INJ_ELF_MAX_DYN; i++) {
        unsigned long syment = sizeof(Elf64_Sym);
        if (memd_task_copy_ok(t, 0, di->bias + dyn_rva + (unsigned long)i * sizeof(dyn),
                              &dyn, sizeof(dyn)))
            return -EFAULT;
        if (dyn.d_tag == DT_NULL)
            break;
        switch (dyn.d_tag) {
        case DT_STRTAB:
            di->strtab = di->bias + (unsigned long)dyn.d_un.d_ptr;
            break;
        case DT_SYMTAB:
            di->symtab = di->bias + (unsigned long)dyn.d_un.d_ptr;
            break;
        case DT_STRSZ:
            di->strsz = (unsigned long)dyn.d_un.d_val;
            break;
        case DT_SYMENT:
            syment = (unsigned long)dyn.d_un.d_val;
            break;
        case DT_HASH:
            di->hash = di->bias + (unsigned long)dyn.d_un.d_ptr;
            break;
        case MEMD_DT_GNU_HASH:
            di->ghash = di->bias + (unsigned long)dyn.d_un.d_ptr;
            break;
        default:
            break;
        }
        if (dyn.d_tag == DT_SYMENT && syment != sizeof(Elf64_Sym))
            return -ENOEXEC;
    }
    if (!di->strtab || !di->symtab || !di->strsz ||
        di->strsz > MEMD_INJ_STRSZ_MAX)
        return -ENOEXEC;
    return 0;
}

static int resolve_libc_syms(struct task_struct *t, uintptr_t base,
                              struct memd_elf_addrs *addrs, int need_dlclose)
 {
    struct memd_elf_dyn di;
    int ret;
    memset(addrs, 0, sizeof(*addrs));
    ret = parse_dynamic(t, base, &di);
    if (ret)
        return ret;
    if (memd_elf_lookup(t, di.symtab, di.strtab, di.strsz, di.hash,
                        di.ghash, "dlopen", di.bias, &addrs->dlopen_va))
        return -ENOENT;
    if (!addrs->dlopen_va)
        return -ENOENT;
    if (need_dlclose) {
        if (memd_elf_lookup(t, di.symtab, di.strtab, di.strsz, di.hash,
                            di.ghash, "dlclose", di.bias,
                            &addrs->dlclose_va) ||
            !addrs->dlclose_va)
            return -ENOENT;
    }
    return 0;
}

/* Resolve any exported symbol in an already-loaded library (payload
 * entry points). Same bounded machinery as the libc resolver. */
static int resolve_lib_sym(struct task_struct *t, uintptr_t base,
                            const char *name, uintptr_t *va)
 {
    struct memd_elf_dyn di;
    int ret;
    if (!t || !base || !name || !name[0] || !va)
        return -EFAULT;
    *va = 0;
    ret = parse_dynamic(t, base, &di);
    if (ret)
        return ret;
    if (memd_elf_lookup(t, di.symtab, di.strtab, di.strsz, di.hash,
                        di.ghash, name, di.bias, va))
        return -ENOENT;
    if (!*va)
        return -ENOENT;
    return 0;
}

/* ---- seize / release (SIGSTOP + wait_task_inactive, SIGCONT) ----
 * All entry points below serialize on memd_inj_mutex: concurrent
 * inject/unload calls on one target would otherwise share the same
 * below-SP scratch and clobber each other's stub/regs. Serialization is
 * global (not per-target) by design — see the timing-budget note above.
 * The mutex wait is interruptible so concurrent DIFFERENT-target injects
 * queue instead of corrupting, and a waiter can abort with -ERESTARTSYS
 * (ioctl return, mirrored in result).
 * A serialized inject-then-unload pair is therefore sequential: the
 * unload observes the inject's completed state (handle installed or
 * zero on failure/ephemeral), never a half-hijacked thread. Sleepable
 * (ioctl process context; remote_call sleeps), never held across
 * anything but one inject/unload operation.
 * D-state note: a thread in uninterruptible sleep is inactive but never
 * TASK_STOPPED, so the seize loop intentionally burns the full 5s: the
 * I/O may complete and the group-stop may still land. Failing fast on
 * D-state would turn slow-I/O targets into spurious -ETIMEDOUTs.
 * SIGCONT guarantee: seize_task SIGCONTs on every path where it sent
 * SIGSTOP and then failed (timeout or wait error); the pre-STOP resolve
 * failure path sent nothing so nothing is owed. Callers therefore release
 * exactly once on success paths and zero times on failed-seize paths. */
static DEFINE_MUTEX(memd_inj_mutex);

static int send_task_sig(struct task_struct *task, int sig)
 {
    struct siginfo info;
    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code = SI_KERNEL;
    info.si_pid = task_pid_vnr(current);
    info.si_uid = memd_uid();
    return memd_send_signal(sig, &info, task, PIDTYPE_PID);
}

static int seize_task(struct task_struct *task)
 {
    int tries, r;
    if (!task)
        return -ESRCH;
    if (resolve_runtime_helpers())
        return -ENODEV;
    r = send_task_sig(task, SIGSTOP);
    if (r < 0)
        return r;
    for (tries = 0; tries < MEMD_INJ_SEIZE_TRIES; tries++) {
        r = my_wait_task_inactive(task, TASK_STOPPED);
        if (r < 0)
            break;
        if (r > 0)
            return 0;
        msleep(MEMD_INJ_POLL_MS);
    }
    send_task_sig(task, SIGCONT);
    return -ETIMEDOUT;
}

static void memd_inj_release(struct task_struct *task)
 {
    if (task)
        send_task_sig(task, SIGCONT);
}

/* ---- user-pt_regs location + sanity ---- */
static int regs_sane(unsigned long *r)
 {
    unsigned long pc = r[MEMD_PT_PC], sp = r[MEMD_PT_SP], ps = r[MEMD_PT_PSTATE];
    if (pc < 0x1000 || pc >= TASK_SIZE_64)
        return 0;
    if (sp == 0 || (sp & 0xf) || sp >= TASK_SIZE_64)
        return 0;
    if ((ps & 0xf) != 0)
        return 0;
    return 1;
}

static int locate_user_regs(struct task_struct *task, uintptr_t *regs_va,
                             unsigned long *regs)
 {
    void *stack;
    unsigned long size, base, va;
    int i;
    unsigned long v;
    if (!task || !regs_va || !regs)
        return -EFAULT;
    stack = memd_t_stack(task);
    if (!stack)
        return -ESRCH;
    size = memd_thread_size();
    if (size != 16384 && size != 65536)
        return -ENODEV;
    base = (unsigned long)stack;
    va = base + size - (unsigned long)MEMD_PT_NREGS * 8UL;
    for (i = 0; i < MEMD_PT_NREGS; i++) {
        if (memd_safe_read64((void *)(va + (unsigned long)i * 8), &v))
            return -EFAULT;
        regs[i] = v;
    }
    if (!regs_sane(regs))
        return -EFAULT;
    *regs_va = va;
    return 0;
}

static int write_regs(struct task_struct *task, uintptr_t regs_va,
                       unsigned long *regs)
 {
    int i;
    unsigned long v;
    (void)task;
    for (i = 0; i < MEMD_PT_NREGS; i++) {
        if (memd_safe_write64((void *)(regs_va + (unsigned long)i * 8), regs[i]))
            return -EFAULT;
        /* Readback: a half-hijacked thread must never resume. */
        if (memd_safe_read64((void *)(regs_va + (unsigned long)i * 8), &v) ||
            v != regs[i])
            return -EFAULT;
    }
    return 0;
}

/* ---- icache coherence for target-written code ---- */
static int flush_user_range(struct mm_struct *mm, uintptr_t start, size_t len)
 {
    uintptr_t va, end;
    if (!mm || !len)
        return -EFAULT;
    if (resolve_runtime_helpers())
        return -ENODEV;
    end = start + len;
    for (va = start & PAGE_MASK; va < end; va += PAGE_SIZE) {
        struct page *pg = vaddr_to_page(mm, va);
        if (!pg)
            continue;
        my_flush_dcache_page(pg);
    }
    return 0;
}

/* ---- su elevation (proven offsets only; bounded window) ---- */
struct memd_su_saved {
    struct cred *cred;
    u32 uid;
    unsigned long cap_eff;
    unsigned long cap_perm;
    bool have_perm;
    bool active;
};

static unsigned long cred_cap_eff_off(void)
 {
    if (memd_learned_ext.t_cred_cap_eff >= 0)
        return (unsigned long)memd_learned_ext.t_cred_cap_eff;
    return 56; /* cap_effective low word: stable, CI-asserted per generation */
}

static int su_stage(struct task_struct *task, struct memd_su_saved *s)
 {
    unsigned long c, w, usage;
    unsigned long uid_off;
    u32 uid;
    memset(s, 0, sizeof(*s));
    if (!task)
        return -ESRCH;
    uid_off = memd_cred_uid_off();
    c = (unsigned long)memd_t_cred(task);
    if (c < TASK_SIZE_64)
        return -ESRCH;
    if (memd_safe_read64((void *)c, &w))
        return -EFAULT;
    usage = (u32)(w & 0xffffffffU);
    if (usage < 1 || usage > MEMD_CRED_USAGE_MAX)
        return -ESRCH;
    if (memd_safe_read32((void *)(c + uid_off), &uid))
        return -EFAULT;
    {
        atomic_t *cnt = (atomic_t *)(void *)c;
        if (!atomic_inc_not_zero(cnt))
            return -ESRCH;
    }
    s->cred = (struct cred *)c;
    s->uid = uid;
    if (memd_safe_read64((void *)(c + cred_cap_eff_off()), &s->cap_eff))
        goto fail_read;
    if (memd_learned_ext.t_cred_cap_perm >= 0) {
        if (memd_safe_read64((void *)(c + (unsigned long)memd_learned_ext.t_cred_cap_perm),
                             &s->cap_perm))
            goto fail_read;
        s->have_perm = true;
    }
    if (memd_safe_write32((void *)(c + uid_off), 0))
        goto fail;
    if (memd_safe_write64((void *)(c + cred_cap_eff_off()), ~0UL))
        goto fail;
    if (s->have_perm &&
        memd_safe_write64((void *)(c + (unsigned long)memd_learned_ext.t_cred_cap_perm), ~0UL))
        goto fail;
    s->active = true;
    return 0;
fail:
    /* A write clobbered state: restore every saved field before the
     * target can resume elevated. All saved values are valid here
     * (reads complete before the first write). Restore writes are
     * checked: if the cred page went bad under us the target must not
     * resume elevated, so SIGKILL here (the caller's out_release still
     * SIGCONTs once, delivering the kill instead of a live resume). */
    {
        int rerr = 0;
        if (memd_safe_write32((void *)(c + uid_off), s->uid))
            rerr = -EFAULT;
        if (memd_safe_write64((void *)(c + cred_cap_eff_off()), s->cap_eff))
            rerr = -EFAULT;
        if (s->have_perm &&
            memd_safe_write64((void *)(c + (unsigned long)memd_learned_ext.t_cred_cap_perm),
                              s->cap_perm))
            rerr = -EFAULT;
        if (rerr)
            send_task_sig(task, SIGKILL);
    }
fail_read:
    /* Manual drop (NOT put_cred: see above); __put_cred only if last. */
    {
        atomic_t *cnt = (atomic_t *)(void *)c;
        if (atomic_dec_and_test(cnt))
            memd_put_cred(s->cred);
    }
    memset(s, 0, sizeof(*s));
    return -EFAULT;
}

static int su_unstage(struct task_struct *task, struct memd_su_saved *s,
                      bool *killed_out)
 {
    int err = 0;
    unsigned long uid_off;
    if (!s->active || !s->cred)
        return 0;
    uid_off = memd_cred_uid_off();
    /* Object pinned throughout by our ref; restore verbatim. If the
     * task replaced its creds under us, or any restore write faults,
     * the live cred may stay elevated: kill instead of resuming. */
    if (!task || (unsigned long)memd_t_cred(task) != (unsigned long)s->cred ||
        memd_safe_write32((void *)((unsigned long)s->cred + uid_off), s->uid) ||
        memd_safe_write64((void *)((unsigned long)s->cred + cred_cap_eff_off()),
                          s->cap_eff) ||
        (s->have_perm &&
         memd_safe_write64((void *)((unsigned long)s->cred +
                                    (unsigned long)memd_learned_ext.t_cred_cap_perm),
                           s->cap_perm))) {
        memd_err("su_unstage: restore impossible; killing target\n");
        if (task)
            send_task_sig(task, SIGKILL);
        if (killed_out)
            *killed_out = true;
        err = -EFAULT;
    }
    {
        atomic_t *cnt = (atomic_t *)(void *)s->cred;
        if (atomic_dec_and_test(cnt))
            memd_put_cred(s->cred);
    }
    s->active = false;
    s->cred = NULL;
    return err;
}

/* ---- generic remote call: fn(a0), flag protocol, restore ----
 * Entry: task STOPPED (caller seized). extra/extralen (e.g. the .so
 * path) is written at path_va and x0 gets path_va; with NULL extra,
 * x0 gets a0 directly (e.g. dlclose handle). Exit: task STOPPED;
 * on success/timeout the original regs are restored (caller SIGCONTs
 * exactly once at the end). On kill paths (torn hijack write, resume
 * during hijack, recapture/restore failure) regs are NOT restored:
 * SIGKILL is sent and the caller's single SIGCONT delivers it, so the
 * target never resumes live with hijacked regs.
 * Multithread soundness: SIGSTOP is group-wide, so siblings stop too,
 * but only THIS task's regs are rewritten to point at the stub and only
 * this task's below-SP flag word is polled. A second stopped thread
 * never runs the stub (its pc is untouched); it simply resumes its saved
 * state at the final SIGCONT. One hijacked thread per call is therefore
 * sufficient for multithreaded targets.
 * Timeout semantics (incl. an entry that never returns): a poll timeout
 * re-STOPs and restores saved regs, returning -ETIMEDOUT with the target
 * ALIVE and unhijacked — kill happens only when recapture or restore
 * itself fails (*killed_out set, SIGKILL sent here, the caller's
 * single SIGCONT delivers it so the kill is not left stopped). Callers preserve the dlopen handle on an
 * entry timeout so unload can still drop the resident library. */
static int remote_call(struct task_struct *task, struct mm_struct *mm,
                       uintptr_t fn, uintptr_t a0, const void *extra,
                       size_t extralen, uintptr_t *retval, int timeout_ms,
                       bool *killed_out)
 {
    unsigned long saved[MEMD_PT_NREGS], regs[MEMD_PT_NREGS];
    uintptr_t regs_va, sp, base, flag_va, path_va, stub_va;
    u32 stub[MEMD_INJ_STUB_WORDS];
    u64 flag[2];
    size_t i;
    int tries, ret;
    if (!task || !mm || !fn || !retval || timeout_ms <= 0)
        return -EINVAL;
    if (extralen > 256 || (extralen && !extra))
        return -EINVAL;
    if (locate_user_regs(task, &regs_va, saved))
        return -EFAULT;
    for (i = 0; i < MEMD_PT_NREGS; i++)
        regs[i] = saved[i];
    sp = regs[MEMD_PT_SP];
    if (sp < MEMD_INJ_SCRATCH_BELOW + 512)
        return -EFAULT;
    base = (sp - MEMD_INJ_SCRATCH_BELOW) & ~15UL;
    /* Scratch map (all offsets from the 16-aligned base; base + 1024
     * <= sp, so the window sits wholly below the live stack, and SP is
     * dropped to base during the call so pushes/frames land below it):
     *  stub [base, base + 44): 11 words x 4 = 44 bytes; 44 < 64 so the
     *   stub never reaches the flag (20 bytes of padding).
     *  flag [base + 64, base + 80): 2 x u64 (done + retval), 16 bytes,
     *   u64-aligned, ending exactly where the path begins.
     *  path [base + 80, base + 336): at most 256 bytes (extralen <= 256
     *   enforced above, NUL included); 80 + 256 = 336 <= 1024, so even
     *   the longest path ends 688 bytes inside the window.
     * In short: 0 < 44 <= 64 < 80 < 336 <= 1024; regions disjoint, base
     * stays 16-aligned and flag/path offsets stay 16-aligned. */
    stub_va = base;
    flag_va = base + 64;
    path_va = base + 80;
    stub[0] = MEMD_MOVZ(1, MEMD_INJ_RTLD_NOW, 0);
    stub[1] = MEMD_MOVZ(3, (unsigned int)(fn & 0xffffUL), 0);
    stub[2] = MEMD_MOVK(3, (unsigned int)((fn >> 16) & 0xffffUL), 1);
    stub[3] = MEMD_MOVK(3, (unsigned int)((fn >> 32) & 0xffffUL), 2);
    stub[4] = MEMD_MOVK(3, (unsigned int)((fn >> 48) & 0xffffUL), 3);
    stub[5] = MEMD_BLR(3);
    /* Flag via x19 (callee-saved: dlopen may clobber x0-x7/x9-x18, but
     * must preserve x19, so the post-call stores cannot miss). DMB
     * orders retval before the done word for the polling reader
     * (reader order done-then-out pairs with this store order). */
    stub[6] = MEMD_STR_X_X8(0, 19);
    stub[7] = MEMD_DMB_ISH;
    stub[8] = MEMD_MOVZ(1, 1, 0);
    stub[9] = MEMD_STR_X_X(1, 19);
    stub[10] = MEMD_B_DOT;
    flag[0] = 0;
    flag[1] = 0;
    if (extralen && memd_task_copy_ok(task, 1, path_va, (void *)extra, extralen))
        return -EFAULT;
    if (memd_task_copy_ok(task, 1, flag_va, flag, sizeof(flag)))
        return -EFAULT;
    if (memd_task_copy_ok(task, 1, stub_va, stub, sizeof(stub)))
        return -EFAULT;
    if (flush_user_range(mm, stub_va, sizeof(stub) + 1024))
        return -EFAULT;
    regs[0] = extralen ? (uint64_t)path_va : (uint64_t)a0;
    regs[19] = (uint64_t)flag_va;
    regs[MEMD_PT_PC] = (uint64_t)stub_va;
    /* x30 preset: clobbered by the stub's BLR before the call, so it
     * never steers execution (the stub ends in B ., never RET). Kept as
     * a crash breadcrumb: LR inside our scratch identifies the hijack
     * window post-mortem. x2 is deliberately NOT set (dead store
     * removed): the stub takes the flag via x19 only; x1/x3 are rebuilt
     * in-stub and x0 carries path/handle. */
    regs[30] = (uint64_t)(stub_va + 40);
    /* Run with SP below the scratch: dlopen pushes frames and signal
     * frames land below SP, so leaving SP above the stub would let the
     * call clobber stub/path/flags. Restored verbatim afterwards. */
    regs[MEMD_PT_SP] = (uint64_t)base;
    /* A killed target must not be wiped (stub may be executing) but
     * still gets SIGCONT so the pending SIGKILL is delivered instead
     * of leaking a stopped thread. Callers check *killed_out. */
    if (write_regs(task, regs_va, regs)) {
        /* Still STOPPED but regs torn: never resume, fail closed. */
        send_task_sig(task, SIGKILL);
        if (killed_out)
            *killed_out = true;
        return -EFAULT;
    }
    /* Fail closed: an external SIGCONT between the hijack write and now
     * would have resumed torn regs; confirm still stopped first. */
    if (my_wait_task_inactive(task, TASK_STOPPED) <= 0) {
        memd_err("remote_call: target %d resumed during hijack; killing\n", task->pid);
        send_task_sig(task, SIGKILL);
        if (killed_out)
            *killed_out = true;
        return -EFAULT;
    }
    memd_inj_release(task);
    ret = -ETIMEDOUT;
    for (tries = 0; tries * MEMD_INJ_POLL_MS < timeout_ms; tries++) {
        u64 done = 0, out = 0;
        /* Dead target can never set the flag: stop waiting early and
         * fall through to the fail-closed recapture path. */
        if (!is_pid_alive(task->pid))
            break;
        msleep(MEMD_INJ_POLL_MS);
        if (memd_task_copy_ok(task, 0, flag_va, &done, 8))
            continue;
        if (done != 1)
            continue;
        /* Pair with the stub's DMB ISH (message passing): order the
         * done load before the out load so a 1 cannot pair with a
         * stale retval word. Control dependency alone does not order
         * ARM loads; ISHLD does. No include needed (inline asm). */
        __asm__ __volatile__("dmb ishld" ::: "memory");
        if (memd_task_copy_ok(task, 0, flag_va + 8, &out, 8))
            break;
        *retval = (uintptr_t)out;
        ret = 0;
        break;
    }
    /* Re-stop whatever state it is in, then restore original regs. */
    if (seize_task(task)) {
        /* Cannot safely recapture a running, hijacked thread. */
        memd_err("remote_call: target %d cannot be recaptured; killing\n", task->pid);
        send_task_sig(task, SIGKILL);
        if (killed_out)
            *killed_out = true;
        return -ETIMEDOUT;
    }
    if (write_regs(task, regs_va, saved)) {
        memd_err("remote_call: register restore failed for target %d\n", task->pid);
        send_task_sig(task, SIGKILL);
        if (killed_out)
            *killed_out = true;
        return -EFAULT;
    }
    return ret;
}

/* Best-effort scratch wipe (stub, path, flags) before the final SIGCONT,
 * so no payload bytes linger in target stack memory. Failure is silent
 * and never fails the inject itself: the payload already ran or was
 * never installed. */
static void wipe_scratch(struct task_struct *task)
 {
    unsigned long regs[MEMD_PT_NREGS];
    uintptr_t regs_va, sp, base, i;
    unsigned long zero = 0;
    if (!task)
        return;
    if (locate_user_regs(task, &regs_va, regs))
        return;
    sp = regs[MEMD_PT_SP];
    if (sp < MEMD_INJ_SCRATCH_BELOW + 512)
        return;
    base = (sp - MEMD_INJ_SCRATCH_BELOW) & ~15UL;
    for (i = 0; i < MEMD_INJ_SCRATCH_BELOW; i += 8) {
        if (memd_task_copy_ok(task, 1, base + i, &zero, 8))
            return;
    }
}

static const char *memd_basename(const char *path)
 {
    const char *b = path, *p = path;
    while (*p) {
        if (*p == '/')
            b = p + 1;
        p++;
    }
    return b;
}

/* ---- top-level inject ---- */
static int inject_so(pid_t pid, const char *path, const char *entry, int su,
                      int flags, uintptr_t *handle_out, int *entry_out)
 {
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    uintptr_t libc_base, retval, lib_base, entry_va;
    struct memd_elf_addrs addrs;
    struct memd_su_saved su_state;
    size_t pathlen, entrylen;
    const char *base;
    int ret, ephemeral;
    bool killed = false;
    bool touched = false;
    if (!path || !handle_out)
        return -EFAULT;
    *handle_out = 0;
    if (entry_out)
        *entry_out = 0;
    memset(&su_state, 0, sizeof(su_state));
    pathlen = strnlen(path, 256);
    if (pathlen == 0 || pathlen >= 256 || path[0] != '/' ||
        (flags & ~MEMD_LOADSO_EPHEMERAL))
        return -EINVAL;
    entrylen = entry ? strnlen(entry, 64) : 0;
    if (entry && (entrylen == 0 || entrylen >= 64 || strchr(entry, '/')))
        return -EINVAL;
    ephemeral = (flags & MEMD_LOADSO_EPHEMERAL) != 0;
    if (pid == task_pid_vnr(current))
        return -EINVAL;
    if (mutex_lock_interruptible(&memd_inj_mutex))
        return -ERESTARTSYS;
    if (!is_pid_alive(pid)) {
        ret = -ESRCH;
        goto out_lock;
    }
    task = get_target_task(pid);
    if (!task) {
        ret = -ESRCH;
        goto out_lock;
    }
    mm = get_task_mm(task);
    if (!mm) {
        ret = -ESRCH;
        goto out_task;
    }
    /* Refuse same-mm targets (sibling thread or self via another TID):
     * hijacking our own address space below-SP scratch corrupts us. */
    if (mm == current->mm) {
        ret = -EINVAL;
        goto out_mm;
    }
    memd_learn_task_stack_once();
    /* Remote reg restore depends on a usable, learned kernel stack
     * geometry; refuse before seizing the target if any generation
     * left this unlearnable. */
    if (memd_thread_size() != 16384u && memd_thread_size() != 65536u) {
        ret = -ENODEV;
        goto out_mm;
    }
    libc_base = get_module_base(pid, "libc.so", 0);
    if (!libc_base) {
        ret = -ENOENT;
        goto out_mm;
    }
    if (resolve_libc_syms(task, libc_base, &addrs, ephemeral)) {
        ret = -ENOENT;
        goto out_mm;
    }
    if (seize_task(task)) {
        ret = -ETIMEDOUT;
        goto out_mm;
    }
    /* Close the resolve-vs-seize TOCTOU. Pre-seize reads are read-only
     * and bounded (access_process_vm pins per page under the target's
     * own mmap lock; every short read aborts), so a racing exec/remap
     * can only yield stale bytes, never a kernel fault — but a stale
     * decode could still point at the wrong fn even when the base is
     * unchanged. Re-read while stopped and re-decode: the stopped-time
     * values below are authoritative and the only ones ever executed.
     * The pre-seize pass is just a fail-fast probe so we never STOP a
     * target we cannot call into. */
    {
        uintptr_t fresh;
        struct memd_elf_addrs fresh_addrs;
        fresh = get_module_base(pid, "libc.so", 0);
        if (!fresh || fresh != libc_base) {
            ret = -ENOENT;
            goto out_release;
        }
        if (resolve_libc_syms(task, fresh, &fresh_addrs, ephemeral)) {
            ret = -ENOENT;
            goto out_release;
        }
        addrs = fresh_addrs;
        /* addrs is now wholly stopped-time: the dlopen call below uses
         * addrs.dlopen_va and the ephemeral dlclose uses
         * addrs.dlclose_va, both from this fresh decode; the entry call
         * uses entry_va resolved separately after dlopen, never this
         * struct. No later remote_call observes pre-seize bytes. */
    }
    if (su && su_stage(task, &su_state)) {
        ret = -EACCES;
        goto out_release;
    }
    ret = remote_call(task, mm, addrs.dlopen_va, 0, path, pathlen + 1,
                      &retval, MEMD_INJ_CALL_TRIES * MEMD_INJ_POLL_MS,
                      &killed);
    touched = true;
    if (ret) {
        if (su && su_unstage(task, &su_state, &killed))
            ret = -EFAULT;
        goto out_release;
    }
    if (!retval) {
        /* dlopen returned NULL (bad path/arch mismatch): fail closed. */
        ret = -ELIBBAD;
        if (su && su_unstage(task, &su_state, &killed))
            ret = -EFAULT;
        goto out_release;
    }
    *handle_out = retval;
    if (entrylen) {
        /* Run the payload entry with the dlopen handle in x0. The
         * library is located by basename (must be unique in target);
         * su still covers this call. */
        base = memd_basename(path);
        if (!*base) {
            ret = -EINVAL;
            if (su && su_unstage(task, &su_state, &killed))
                ret = -EFAULT;
            goto out_release;
        }
        lib_base = get_module_base(pid, (char *)base, 0);
        if (!lib_base) {
            ret = -ENOENT;
            if (su && su_unstage(task, &su_state, &killed))
                ret = -EFAULT;
            goto out_release;
        }
        if (resolve_lib_sym(task, lib_base, entry, &entry_va)) {
            ret = -ENOENT;
            if (su && su_unstage(task, &su_state, &killed))
                ret = -EFAULT;
            goto out_release;
        }
        retval = 0;
        ret = remote_call(task, mm, entry_va, *handle_out, NULL, 0,
                          &retval, MEMD_INJ_CALL_TRIES * MEMD_INJ_POLL_MS,
                          &killed);
        touched = true;
        if (entry_out)
            *entry_out = (int)retval;
        if (ret) {
            if (su && su_unstage(task, &su_state, &killed))
                ret = -EFAULT;
            goto out_release;
        }
    }
    if (ephemeral) {
        /* Linker unloads itself: maps/solist cleaned by the target's own
         * dynamic linker; no knowledge of the layout is required here. */
        retval = 0;
        touched = true;
        if (remote_call(task, mm, addrs.dlclose_va, *handle_out, NULL, 0,
                        &retval, MEMD_INJ_CALL_TRIES * MEMD_INJ_POLL_MS,
                        &killed) ||
            retval) {
            ret = -EIO;
            if (su && su_unstage(task, &su_state, &killed))
                ret = -EFAULT;
            goto out_release;
        }
        *handle_out = 0;
    }
    if (su && su_unstage(task, &su_state, &killed))
        ret = -EFAULT;
    else
        ret = 0;
out_release:
    /* Wipe our scratch before resume (still stopped here on all paths
     * that passed the seize phase; best-effort, and not fatal to
     * the injection). Skipped after a kill: the stub may be executing
     * and SIGCONT must go through to deliver the pending SIGKILL.
     * Skipped when no remote_call ever ran (early aborts): nothing was
     * written, matching unload_so which never wipes pre-call paths. */
    if (!killed && touched)
        wipe_scratch(task);
    memd_inj_release(task);
out_mm:
    mmput(mm);
out_task:
    put_task_struct(task);
out_lock:
    mutex_unlock(&memd_inj_mutex);
    return ret;
}

int do_load_sotoapp(struct socket* sock, void __user* arg)
 {
    struct memd_loadso_cmd cmd;
    uintptr_t handle;
    int entry_result, ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    handle = 0;
    entry_result = 0;
    ret = inject_so(cmd.pid, cmd.path, cmd.entry[0] ? cmd.entry : NULL,
                    0, cmd.flags, &handle, &entry_result);
    cmd.result = ret;
    cmd.handle = handle;
    cmd.entry_result = entry_result;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    /* Mutex-interrupt abort: surface -ERESTARTSYS as the ioctl return
     * (restart/EINTR semantics) as well as in result, so a queued admin
     * ioctl does not look like success-zero with a 512 hidden in the
     * payload. Nothing changed on this path, so this is fail-closed. */
    if (ret == -ERESTARTSYS)
        return -ERESTARTSYS;
    return 0;
}

int do_load_sosutoapp(struct socket* sock, void __user* arg)
 {
    struct memd_loadso_cmd cmd;
    uintptr_t handle;
    int entry_result, ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    handle = 0;
    entry_result = 0;
    ret = inject_so(cmd.pid, cmd.path, cmd.entry[0] ? cmd.entry : NULL,
                    1, cmd.flags, &handle, &entry_result);
    cmd.result = ret;
    cmd.handle = handle;
    cmd.entry_result = entry_result;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    /* Same -ERESTARTSYS propagation as above: ioctl return carries
     * restart semantics, result mirrors it; nothing changed. */
    if (ret == -ERESTARTSYS)
        return -ERESTARTSYS;
    return 0;
}

/* ---- top-level unload: remote dlclose(handle) ----
 * Hotswap primitive (see LXGR.hpp): drops a resident library the same
 * way the ephemeral path does — the target's own linker unmaps it and
 * cleans its lists, so no maps/solist residue remains. Same seize/
 * remote-call/restore/wipe discipline as inject_so (identical timeouts,
 * recapture-kill, and wipe rules via the shared remote_call path);
 * only su/path/entry handling differs. Error codes differ by domain
 * (ELIBBAD on dlopen-NULL vs EIO on dlclose-nonzero), not by policy. */
static int unload_so(pid_t pid, uintptr_t handle)
 {
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    uintptr_t libc_base, retval;
    struct memd_elf_addrs addrs;
    bool killed = false;
    int ret;
    if (!handle)
        return -EINVAL;
    if (pid == task_pid_vnr(current))
        return -EINVAL;
    if (mutex_lock_interruptible(&memd_inj_mutex))
        return -ERESTARTSYS;
    if (!is_pid_alive(pid)) {
        ret = -ESRCH;
        goto out_lock;
    }
    task = get_target_task(pid);
    if (!task) {
        ret = -ESRCH;
        goto out_lock;
    }
    mm = get_task_mm(task);
    if (!mm) {
        ret = -ESRCH;
        goto out_task;
    }
    /* Refuse same-mm targets (sibling thread or self via another TID):
     * hijacking our own address space below-SP scratch corrupts us. */
    if (mm == current->mm) {
        ret = -EINVAL;
        goto out_mm;
    }
    memd_learn_task_stack_once();
    if (memd_thread_size() != 16384u && memd_thread_size() != 65536u) {
        ret = -ENODEV;
        goto out_mm;
    }
    libc_base = get_module_base(pid, "libc.so", 0);
    if (!libc_base) {
        ret = -ENOENT;
        goto out_mm;
    }
    if (resolve_libc_syms(task, libc_base, &addrs, 1)) {
        ret = -ENOENT;
        goto out_mm;
    }
    if (seize_task(task)) {
        ret = -ETIMEDOUT;
        goto out_mm;
    }
    /* Same resolve-vs-seize TOCTOU as inject_so: re-read while stopped
     * and re-decode (see above); the stopped-time addrs are the only
     * ones ever executed. */
    {
        uintptr_t fresh;
        struct memd_elf_addrs fresh_addrs;
        fresh = get_module_base(pid, "libc.so", 0);
        if (!fresh || fresh != libc_base) {
            memd_inj_release(task);
            ret = -ENOENT;
            goto out_mm;
        }
        if (resolve_libc_syms(task, fresh, &fresh_addrs, 1)) {
            memd_inj_release(task);
            ret = -ENOENT;
            goto out_mm;
        }
        addrs = fresh_addrs;
        /* addrs is now wholly stopped-time; the single dlclose below
         * uses addrs.dlclose_va from this fresh decode. No later
         * remote_call observes pre-seize bytes. */
    }
    retval = 0;
    ret = remote_call(task, mm, addrs.dlclose_va, handle, NULL, 0,
                      &retval, MEMD_INJ_CALL_TRIES * MEMD_INJ_POLL_MS,
                      &killed);
    if (!ret && retval)
        ret = -EIO;
    if (!killed)
        wipe_scratch(task);
    memd_inj_release(task);
out_mm:
    mmput(mm);
out_task:
    put_task_struct(task);
out_lock:
    mutex_unlock(&memd_inj_mutex);
    return ret;
}

int do_loadso_unload(struct socket* sock, void __user* arg)
 {
    struct memd_loadso_unload_cmd cmd;
    int ret;
    (void)sock;
    if (!memd_capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (memd_copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    ret = unload_so(cmd.pid, cmd.handle);
    cmd.result = ret;
    if (!ret)
        cmd.handle = 0;
    if (memd_copy_to_user(arg, &cmd, sizeof(cmd)))
        return -EFAULT;
    /* Same -ERESTARTSYS propagation as the load paths: ioctl return
     * carries restart semantics, result mirrors it; nothing changed. */
    if (ret == -ERESTARTSYS)
        return -ERESTARTSYS;
    return 0;
}
/* kmod/memd/utils/memd_inject.c[∂] */
