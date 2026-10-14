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
 *     touched page for icache coherence, save regs, set pc/x0/x2/lr
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
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/signal.h>
#include <linux/string.h>

#define MEMD_INJ_SEIZE_TRIES 250   /* 250 x 20ms = 5s to reach STOPPED */
#define MEMD_INJ_CALL_TRIES  500   /* 500 x 20ms = 10s for dlopen return */
#define MEMD_INJ_POLL_MS     20
#define MEMD_INJ_SCRATCH_BELOW 1024 /* below-sp scratch window (bytes) */
#define MEMD_INJ_STUB_WORDS  10
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

/* user_pt_regs layout (arm64 UAPI, immutable): x0..x30, sp, pc, pstate. */
#define MEMD_PT_SP     31
#define MEMD_PT_PC     32
#define MEMD_PT_PSTATE 33
#define MEMD_PT_NREGS  34

/* Proven struct cred head layout (same basis as memd_capable/mem..._uid):
 * usage counter at +0, uid value at +4. cap offsets come from the
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
    wantlen = strlen(want);
    if (wantlen == 0 || wantlen + 1 >= MEMD_INJ_NAME_MAX)
        return -ENOENT;
    /* GNU hash first (what modern Bionic emits), then SYSV. */
    if (gnuhash) {
        unsigned long nbuckets, bloom_size, bloom_shift;
        if (memd_task_copy_ok(t, 0, gnuhash, &nbuckets, 8))
            return -EFAULT;
        if (memd_task_copy_ok(t, 0, gnuhash + 8, &symoff, 8))
            return -EFAULT;
        if (memd_task_copy_ok(t, 0, gnuhash + 16, &bloom_size, 8))
            return -EFAULT;
        if (memd_task_copy_ok(t, 0, gnuhash + 24, &bloom_shift, 8))
            return -EFAULT;
        (void)bloom_shift;
        if (nbuckets == 0 || nbuckets > 100000 || bloom_size > 1024)
            return -ENOENT;
        h = memd_gnu_hash(want);
        if (memd_task_copy_ok(t, 0, gnuhash + 32 + (h / 64 % bloom_size) * 8, &w, 8))
            return -EFAULT;
        if (!((w >> (h % 64)) & 1))
            return -ENOENT;
        if (memd_task_copy_ok(t, 0,
                              gnuhash + 32 + bloom_size * 8 + (h % nbuckets) * 4,
                              &bkt, 4))
            return -EFAULT;
        if (bkt < symoff)
            return -ENOENT;
        for (i = bkt, n = 0; n < (unsigned long)MEMD_INJ_SYM_WALK_MAX; i++, n++) {
            unsigned long cw;
            if (memd_task_copy_ok(t, 0,
                                  gnuhash + 32 + bloom_size * 8 +
                                  nbuckets * 4 + (i - symoff) * 4,
                                  &cw, 4))
                return -EFAULT;
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
        if (memd_task_copy_ok(t, 0, hashtab, &nbucket, 4))
            return -EFAULT;
        if (memd_task_copy_ok(t, 0, hashtab + 4, &nchain, 4))
            return -EFAULT;
        if (nbucket == 0 || nbucket > 100000 || nchain == 0 ||
            nchain > (unsigned long)MEMD_INJ_SYM_WALK_MAX)
            return -ENOENT;
        h = memd_elf_hash(want);
        if (memd_task_copy_ok(t, 0, hashtab + 8 + (h % nbucket) * 4, &bkt, 4))
            return -EFAULT;
        for (i = bkt, n = 0;
             i != 0 && n < (unsigned long)MEMD_INJ_SYM_WALK_MAX;
             n++) {
            unsigned long nx;
            if (i >= nchain)
                return -ENOENT;
            if (!memd_elf_sym(t, symtab, strtab, strsz, i, want,
                              wantlen, bias, out))
                return 0;
            if (memd_task_copy_ok(t, 0,
                                  hashtab + 8 + nbucket * 4 + i * 4, &nx, 4))
                return -EFAULT;
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

/* ---- seize / release (SIGSTOP + wait_task_inactive, SIGCONT) ---- */
static int send_task_sig(struct task_struct *task, int sig)
 {
    struct siginfo info;
    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code = SI_KERNEL;
    info.si_pid = task_pid_vnr(current);
    info.si_uid = memd_uid();
    return send_signal(sig, &info, task, PIDTYPE_PID);
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
            return -EFAULT;
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
    u32 uid;
    memset(s, 0, sizeof(*s));
    if (!task)
        return -ESRCH;
    c = (unsigned long)memd_t_cred(task);
    if (c < TASK_SIZE_64)
        return -ESRCH;
    if (memd_safe_read64((void *)c, &w))
        return -EFAULT;
    usage = (u32)(w & 0xffffffffU);
    if (usage < 1 || usage > MEMD_CRED_USAGE_MAX)
        return -ESRCH;
    if (memd_safe_read32((void *)(c + 4), &uid))
        return -EFAULT;
    {
        atomic_t *cnt = (atomic_t *)(void *)c;
        if (!atomic_inc_not_zero(cnt))
            return -ESRCH;
    }
    s->cred = (struct cred *)c;
    s->uid = uid;
    if (memd_safe_read64((void *)(c + cred_cap_eff_off()), &s->cap_eff))
        goto fail;
    if (memd_learned_ext.t_cred_cap_perm >= 0) {
        if (memd_safe_read64((void *)(c + (unsigned long)memd_learned_ext.t_cred_cap_perm),
                             &s->cap_perm))
            goto fail;
        s->have_perm = true;
    }
    if (memd_safe_write32((void *)(c + 4), 0))
        goto fail;
    if (memd_safe_write64((void *)(c + cred_cap_eff_off()), ~0UL))
        goto fail;
    if (s->have_perm &&
        memd_safe_write64((void *)(c + (unsigned long)memd_learned_ext.t_cred_cap_perm), ~0UL))
        goto fail;
    s->active = true;
    return 0;
fail:
    /* Manual drop (NOT put_cred: see above); __put_cred only if last. */
    {
        atomic_t *cnt = (atomic_t *)(void *)c;
        if (atomic_dec_and_test(cnt))
            __put_cred(s->cred);
    }
    memset(s, 0, sizeof(*s));
    return -EFAULT;
}

static void su_unstage(struct task_struct *task, struct memd_su_saved *s)
 {
    (void)task;
    if (!s->active || !s->cred)
        return;
    /* Object pinned throughout by our ref; restore verbatim. */
    memd_safe_write32((void *)((unsigned long)s->cred + 4), s->uid);
    memd_safe_write64((void *)((unsigned long)s->cred + cred_cap_eff_off()),
                      s->cap_eff);
    if (s->have_perm)
        memd_safe_write64((void *)((unsigned long)s->cred +
                                   (unsigned long)memd_learned_ext.t_cred_cap_perm),
                          s->cap_perm);
    {
        atomic_t *cnt = (atomic_t *)(void *)s->cred;
        if (atomic_dec_and_test(cnt))
            __put_cred(s->cred);
    }
    s->active = false;
    s->cred = NULL;
}

/* ---- generic remote call: fn(a0), flag protocol, restore ----
 * Entry: task STOPPED (caller seized). extra/extralen (e.g. the .so
 * path) is written at path_va and x0 gets path_va; with NULL extra,
 * x0 gets a0 directly (e.g. dlclose handle). Exit: task STOPPED with
 * original regs restored (caller SIGCONTs exactly once at the end). */
static int remote_call(struct task_struct *task, struct mm_struct *mm,
                       uintptr_t fn, uintptr_t a0, const void *extra,
                       size_t extralen, uintptr_t *retval, int timeout_ms)
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
    stub_va = base;
    flag_va = base + 64;
    path_va = base + 80;
    stub[0] = MEMD_MOVZ(1, MEMD_INJ_RTLD_NOW, 0);
    stub[1] = MEMD_MOVZ(3, (unsigned int)(fn & 0xffffUL), 0);
    stub[2] = MEMD_MOVK(3, (unsigned int)((fn >> 16) & 0xffffUL), 1);
    stub[3] = MEMD_MOVK(3, (unsigned int)((fn >> 32) & 0xffffUL), 2);
    stub[4] = MEMD_MOVK(3, (unsigned int)((fn >> 48) & 0xffffUL), 3);
    stub[5] = MEMD_BLR(3);
    stub[6] = MEMD_STR_X_X8(0, 2);
    stub[7] = MEMD_MOVZ(1, 1, 0);
    stub[8] = MEMD_STR_X_X(1, 2);
    stub[9] = MEMD_B_DOT;
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
    regs[2] = (uint64_t)flag_va;
    regs[MEMD_PT_PC] = (uint64_t)stub_va;
    regs[30] = (uint64_t)(stub_va + 36);
    if (write_regs(task, regs_va, regs))
        return -EFAULT;
    memd_inj_release(task);
    ret = -ETIMEDOUT;
    for (tries = 0; tries * MEMD_INJ_POLL_MS < timeout_ms; tries++) {
        u64 done = 0, out = 0;
        msleep(MEMD_INJ_POLL_MS);
        if (memd_task_copy_ok(task, 0, flag_va, &done, 8))
            continue;
        if (done != 1)
            continue;
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
        return -ETIMEDOUT;
    }
    if (write_regs(task, regs_va, saved)) {
        memd_err("remote_call: register restore failed for target %d\n", task->pid);
        send_task_sig(task, SIGKILL);
        return -EFAULT;
    }
    return ret;
}

/* Best-effort scratch wipe (stub, path, flags) before the final SIGCONT,
 * so no payload bytes linger in target stack memory. Failure is logged
 * by the caller path but never fails the inject itself: the payload
 * already ran or was never installed. */
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
    if (!is_pid_alive(pid))
        return -ESRCH;
    task = get_target_task(pid);
    if (!task)
        return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) {
        ret = -ESRCH;
        goto out_task;
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
    if (su && su_stage(task, &su_state)) {
        ret = -EACCES;
        goto out_release;
    }
    ret = remote_call(task, mm, addrs.dlopen_va, 0, path, pathlen + 1,
                      &retval, MEMD_INJ_CALL_TRIES * MEMD_INJ_POLL_MS);
    if (ret) {
        if (su)
            su_unstage(task, &su_state);
        goto out_release;
    }
    if (!retval) {
        /* dlopen returned NULL (bad path/arch mismatch): fail closed. */
        if (su)
            su_unstage(task, &su_state);
        ret = -ELIBBAD;
        goto out_release;
    }
    *handle_out = retval;
    if (entrylen) {
        /* Run the payload entry with the dlopen handle in x0. The
         * library is located by basename (must be unique in target);
         * su still covers this call. */
        base = memd_basename(path);
        if (!*base) {
            if (su)
                su_unstage(task, &su_state);
            ret = -EINVAL;
            goto out_release;
        }
        lib_base = get_module_base(pid, (char *)base, 0);
        if (!lib_base) {
            if (su)
                su_unstage(task, &su_state);
            ret = -ENOENT;
            goto out_release;
        }
        if (resolve_lib_sym(task, lib_base, entry, &entry_va)) {
            if (su)
                su_unstage(task, &su_state);
            ret = -ENOENT;
            goto out_release;
        }
        retval = 0;
        ret = remote_call(task, mm, entry_va, *handle_out, NULL, 0,
                          &retval, MEMD_INJ_CALL_TRIES * MEMD_INJ_POLL_MS);
        if (entry_out)
            *entry_out = (int)retval;
        if (ret) {
            if (su)
                su_unstage(task, &su_state);
            goto out_release;
        }
    }
    if (ephemeral) {
        /* Linker unloads itself: maps/solist cleaned by Android's own
         * linker, no layout knowledge needed on our side. */
        retval = 0;
        if (remote_call(task, mm, addrs.dlclose_va, *handle_out, NULL, 0,
                        &retval, MEMD_INJ_CALL_TRIES * MEMD_INJ_POLL_MS) ||
            retval) {
            if (su)
                su_unstage(task, &su_state);
            ret = -EIO;
            goto out_release;
        }
        *handle_out = 0;
    }
    if (su)
        su_unstage(task, &su_state);
    ret = 0;
out_release:
    /* Wipe our scratch before resume (still stopped here on all paths
     * that got past seize; best-effort, never fails the inject). */
    wipe_scratch(task);
    memd_inj_release(task);
out_mm:
    mmput(mm);
out_task:
    put_task_struct(task);
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
    return 0;
}
