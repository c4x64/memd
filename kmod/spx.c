/* spx.c — SPX packed loader: ONE native binary carrying both LKM flavors
 * (plain + CFI) plus run.sh, responsible for external patching and loading.
 *
 * Flow: detect kernel (uname) -> select flavor (CFI+6.1+ => cfi, older and
 * non-CFI => plain) -> patch embedded copy (vermagic, dispatch slots) ->
 * finit_module -> verify Live. Journal with attempt counting + fsync
 * survives panics: a post-reboot run sees attempt-without-success and
 * falls back to the next flavor instead of retrying into a wall.
 * Never loops forever: each flavor attempted at most twice, then NO-GO.
 *
 * No python3, no toybox beyond sh, no zlib (no config parsing — ground
 * truth from journal + Live checks instead). Static PIE (runs on bionic).
 *
 * Build (CI pack job): blobs generated from the two .ko files + run.sh
 *   python3 genblobs.py rwbridge.ko rwbridge-cfi.ko run.sh > blobs.c
 *   aarch64-linux-gnu-gcc -static-pie -O2 -o rwbridge-spx spx.c blobs.c
 *
 * CLI: rwbridge-spx [--dry-run] [--extract-runsh] [--ko PATH (test hook)]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>

#ifndef __NR_finit_module
#if defined(__aarch64__)
#define __NR_finit_module 379
#else
#error "spx: aarch64 target only"
#endif
#endif

/* blobs.c provides these (generated, never committed) */
extern const unsigned char _binary_rwbridge_ko_start[];
extern const unsigned long _binary_rwbridge_ko_len;
extern const unsigned char _binary_rwbridge_cfi_ko_start[];
extern const unsigned long _binary_rwbridge_cfi_ko_len;
extern const unsigned char _binary_runsh_start[];
extern const unsigned long _binary_runsh_len;

#define STATE_PATH "/data/local/tmp/rwbridge.spx"
#define TMPKO_PATH "/data/local/tmp/rwbridge-run.ko"
#define JOURNAL_DIR "/sdcard/MemoryD"

static FILE *jfp;
static int dry;

static void jlog(const char *op, const char *msg)
{
    char line[512];
    snprintf(line, sizeof(line), "%s | %s\n", op, msg);
    fputs(line, stdout);
    if (jfp) {
        fputs(line, jfp);
        fflush(jfp);
        fsync(fileno(jfp));
    }
}

/* ---- state: attempt counting across reboots ---- */
struct state {
    int cfi_tried;
    int plain_tried;
};

static void state_load(struct state *s)
{
    FILE *f;
    memset(s, 0, sizeof(*s));
    f = fopen(STATE_PATH, "r");
    if (!f)
        return;
    if (fscanf(f, "%d %d", &s->cfi_tried, &s->plain_tried) != 2) {
        s->cfi_tried = 0;
        s->plain_tried = 0;
    }
    fclose(f);
}

static void state_save(const struct state *s)
{
    FILE *f = fopen(STATE_PATH, "w");
    if (!f)
        return;
    fprintf(f, "%d %d\n", s->cfi_tried, s->plain_tried);
    fflush(f);
    fsync(fileno(f));
    fclose(f);
}

/* ---- kernel detection ---- */
static int kernel_major(void)
{
    struct utsname u;
    if (uname(&u) < 0)
        return 0;
    return atoi(u.release);
}

/* ---- vermagic target: on-device reference .ko, else uname fallback ---- */
static int read_cstr_at(const char *path, long off, char *out, int cap)
{
    FILE *f = fopen(path, "rb");
    int i = 0, c;
    if (!f)
        return -1;
    if (fseek(f, off, SEEK_SET) < 0) {
        fclose(f);
        return -1;
    }
    while (i < cap - 1 && (c = fgetc(f)) != EOF && c) {
        out[i++] = (char)c;
    }
    out[i] = 0;
    fclose(f);
    return (c == 0 || i == cap - 1) ? 0 : -1;
}

static int find_bytes(const unsigned char *d, long n, const char *tag,
                      long *off)
{
    long tlen = (long)strlen(tag), i;
    for (i = 0; i + tlen <= n; i++) {
        if (!memcmp(d + i, tag, (size_t)tlen)) {
            *off = i;
            return 0;
        }
    }
    return -1;
}

static int vermagic_from_ko(const char *path, char *out, int cap)
{
    /* cp-first read via stdio (tool-domain safe), then locate tag */
    FILE *f = fopen(path, "rb");
    unsigned char *d;
    long n, off;
    struct stat st;
    int r = -1;
    if (!f)
        return -1;
    if (fstat(fileno(f), &st) < 0) {
        fclose(f);
        return -1;
    }
    n = (long)st.st_size;
    if (n <= 0 || n > (32 << 20)) {
        fclose(f);
        return -1;
    }
    d = malloc((size_t)n);
    if (!d) {
        fclose(f);
        return -1;
    }
    if (fread(d, 1, (size_t)n, f) != (size_t)n) {
        free(d);
        fclose(f);
        return -1;
    }
    fclose(f);
    if (!find_bytes(d, n, "vermagic=", &off) &&
        !read_cstr_at(path, off, out, cap) &&
        !strncmp(out, "vermagic=", 9))
        r = 0;
    free(d);
    return r;
}

static int target_vermagic(char *out, int cap)
{
    static const char *dirs[] = {
        "/vendor/lib/modules", "/vendor_dlkm/lib/modules",
        "/system/lib/modules", NULL
    };
    int i;
    for (i = 0; dirs[i]; i++) {
        DIR *dp = opendir(dirs[i]);
        struct dirent *de;
        char path[512];
        if (!dp)
            continue;
        while ((de = readdir(dp))) {
            size_t L = strlen(de->d_name);
            if (L < 4 || strcmp(de->d_name + L - 3, ".ko"))
                continue;
            snprintf(path, sizeof(path), "%s/%s", dirs[i], de->d_name);
            if (!vermagic_from_ko(path, out, cap)) {
                closedir(dp);
                return 0;
            }
        }
        closedir(dp);
    }
    {
        struct utsname u;
        if (uname(&u) < 0)
            return -1;
        snprintf(out, (size_t)cap, "vermagic=%s SMP preempt mod_unload aarch64",
                 u.release);
        return 0;
    }
}

/* ---- dmesg "should be" feedback (klogctl needs privilege; we run as root) ---- */
static int dmesg_want(char *out, int cap)
{
#ifdef __linux__
    static char buf[1 << 16];
    long n = syscall(SYS_syslog, 3 /*READ_ALL*/, buf, sizeof(buf) - 1);
    char *p, *q;
    if (n <= 0)
        return -1;
    buf[n] = 0;
    p = strstr(buf, "should be '");
    if (!p)
        return -1;
    p += 11;
    q = strchr(p, '\'');
    if (!q || q - p <= 0 || q - p >= cap - 10)
        return -1;
    if (strncmp(p, "vermagic=", 9))
        snprintf(out, (size_t)cap, "vermagic=%.*s", (int)(q - p), p);
    else {
        memcpy(out, p, (size_t)(q - p));
        out[q - p] = 0;
    }
    return 0;
#else
    (void)out;
    (void)cap;
    return -1;
#endif
}

/* ---- ELF helpers (pure, no deps) ---- */
struct esecs {
    long mod_off, mod_size;
    long rela_off;
    long rela_count;
    long sym_off;
    long str_off;
};

static int elf_sections(const unsigned char *d, long n, struct esecs *e,
                        long *shoff_out)
{
    Elf64_Ehdr *h;
    Elf64_Shdr *sh;
    char *shstr;
    int i, shnum;
    long shoff;
    if (n < (long)sizeof(Elf64_Ehdr) || memcmp(d, "\x7f" "ELF", 4))
        return -1;
    h = (Elf64_Ehdr *)d;
    if (h->e_ident[EI_CLASS] != ELFCLASS64)
        return -1;
    shoff = (long)h->e_shoff;
    shnum = h->e_shnum;
    memset(e, 0, sizeof(*e));
    if (shoff <= 0 || shoff + (long)shnum * (long)sizeof(Elf64_Shdr) > n)
        return -1;
    sh = (Elf64_Shdr *)(d + shoff);
    if (h->e_shstrndx >= (Elf64_Half)shnum)
        return -1;
    shstr = (char *)(d + sh[h->e_shstrndx].sh_offset);
    for (i = 0; i < shnum; i++) {
        const char *nm = shstr + sh[i].sh_name;
        if (!strcmp(nm, ".gnu.linkonce.this_module")) {
            e->mod_off = (long)sh[i].sh_offset;
            e->mod_size = (long)sh[i].sh_size;
        } else if (!strcmp(nm, ".rela.gnu.linkonce.this_module")) {
            e->rela_off = (long)sh[i].sh_offset;
            e->rela_count = (long)(sh[i].sh_size / sizeof(Elf64_Rela));
        } else if (!strcmp(nm, ".strtab")) {
            e->str_off = (long)sh[i].sh_offset;
        } else if (sh[i].sh_type == SHT_SYMTAB) {
            e->sym_off = (long)sh[i].sh_offset;
        }
    }
    if (shoff_out)
        *shoff_out = shoff;
    return (e->mod_off > 0 && e->rela_off > 0 && e->sym_off > 0 &&
            e->str_off > 0) ? 0 : -1;
}

static int sym_name(const unsigned char *d, long sym_off, long str_off,
                    long idx, char *out, int cap)
{
    Elf64_Sym *s = (Elf64_Sym *)(d + sym_off + idx * sizeof(Elf64_Sym));
    long a = str_off + (long)s->st_name;
    int i = 0;
    while (i < cap - 1 && d[a + i]) {
        out[i] = (char)d[a + i];
        i++;
    }
    out[i] = 0;
    return 0;
}

/* read current init/exit slot offsets from target's relas (symbol-matched) */
static int target_slots(unsigned char *d, long n, long *init_off,
                        long *exit_off)
{
    struct esecs e;
    long i;
    char nm[64];
    *init_off = *exit_off = -1;
    if (elf_sections(d, n, &e, NULL) < 0)
        return -1;
    for (i = 0; i < e.rela_count; i++) {
        Elf64_Rela *r = (Elf64_Rela *)(d + e.rela_off + i * sizeof(*r));
        sym_name(d, e.sym_off, e.str_off, (long)ELF64_R_SYM(r->r_info), nm,
                 sizeof(nm));
        if (!strcmp(nm, "init_module"))
            *init_off = (long)r->r_offset;
        else if (!strcmp(nm, "cleanup_module"))
            *exit_off = (long)r->r_offset;
    }
    return (*init_off >= 0 && *exit_off >= 0) ? 0 : -1;
}

/* dispatch-slot surgery: grow this_module if needed, move relas to ref slots */
static int slot_surgery(unsigned char **dp, long *np, long want_init,
                        long want_exit)
{
    unsigned char *d = *dp;
    long n = *np;
    struct esecs e;
    long i, ins_at, need, shoff;
    Elf64_Ehdr *h;
    char nm[64];
    int changed = 0;
    if (elf_sections(d, n, &e, &shoff) < 0)
        return -1;
    need = (want_init > want_exit ? want_init : want_exit) + 8;
    if (need > e.mod_size) {
        /* grow: insert 0x100 zeros at section end, fix e_shoff/sh_offsets */
        long grow = 0x100, shnum;
        unsigned char *nd;
        ins_at = e.mod_off + e.mod_size;
        nd = malloc((size_t)(n + grow));
        if (!nd)
            return -1;
        memcpy(nd, d, (size_t)ins_at);
        memset(nd + ins_at, 0, (size_t)grow);
        memcpy(nd + ins_at + grow, d + ins_at, (size_t)(n - ins_at));
        free(d);
        d = nd;
        n += grow;
        h = (Elf64_Ehdr *)d;
        shnum = h->e_shnum;
        h->e_shoff += (Elf64_Off)grow;
        for (i = 0; i < shnum; i++) {
            Elf64_Shdr *s = (Elf64_Shdr *)(d + h->e_shoff + i * sizeof(*s));
            if ((long)s->sh_offset >= ins_at && s->sh_size)
                s->sh_offset += (Elf64_Off)grow;
        }
        /* re-derive (struct copy, recompute below via fresh parse) */
        if (elf_sections(d, n, &e, NULL) < 0) {
            free(d);
            return -1;
        }
        {
            /* fix grown section size */
            long shoff2;
            int j, shn2;
            Elf64_Ehdr *h2 = (Elf64_Ehdr *)d;
            shoff2 = (long)h2->e_shoff;
            shn2 = h2->e_shnum;
            for (j = 0; j < shn2; j++) {
                Elf64_Shdr *s = (Elf64_Shdr *)(d + shoff2 + j * sizeof(*s));
                if ((long)s->sh_offset == e.mod_off) {
                    s->sh_size += (Elf64_Xword)grow;
                    break;
                }
            }
            if (elf_sections(d, n, &e, NULL) < 0) {
                free(d);
                return -1;
            }
        }
    }
    for (i = 0; i < e.rela_count; i++) {
        Elf64_Rela *r = (Elf64_Rela *)(d + e.rela_off + i * sizeof(*r));
        long want = -1;
        sym_name(d, e.sym_off, e.str_off, (long)ELF64_R_SYM(r->r_info), nm,
                 sizeof(nm));
        if (!strcmp(nm, "init_module"))
            want = want_init;
        else if (!strcmp(nm, "cleanup_module"))
            want = want_exit;
        if (want >= 0 && (long)r->r_offset != want) {
            r->r_offset = (Elf64_Addr)want;
            changed = 1;
        }
    }
    *dp = d;
    *np = n;
    return changed ? 1 : 0;
}

/* vermagic in-place patch (placeholder always fits: baked 63-char UTS cap) */
static int patch_vermagic(unsigned char *d, long n, const char *want)
{
    long i, j, wl = (long)strlen(want);
    for (i = 0; i + 9 <= n; i++) {
        if (!memcmp(d + i, "vermagic=", 9)) {
            for (j = i; j < n && d[j]; j++)
                ;
            if (j >= n || wl > j - i)
                return -1;
            memcpy(d + i, want, (size_t)wl);
            memset(d + i + wl, 0, (size_t)(j - i - wl));
            return 0;
        }
    }
    return -1;
}

/* read whole file; 0 ok with malloc'd *out (caller frees), -1 fail */
static int read_file(const char *path, unsigned char **out, long *n)
{
    FILE *f = fopen(path, "rb");
    struct stat st;
    unsigned char *d;
    if (!f)
        return -1;
    if (fstat(fileno(f), &st) < 0 || st.st_size <= 0 ||
        st.st_size > (32 << 20)) {
        fclose(f);
        return -1;
    }
    d = malloc((size_t)st.st_size);
    if (!d) {
        fclose(f);
        return -1;
    }
    if (fread(d, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
        free(d);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = d;
    *n = (long)st.st_size;
    return 0;
}

/* dispatch slots from a reference .ko file (symbol-matched, 0 ok) */
static int ref_slots_from_file(const char *path, long *rio, long *reo)
{
    unsigned char *d;
    long n;
    int r;
    if (read_file(path, &d, &n) < 0)
        return -1;
    r = target_slots(d, n, rio, reo);
    free(d);
    return r;
}

/* ---- finit_module + Live verify ---- */
static int do_insmod(const unsigned char *d, long n, const char *args)
{
    int fd;
    long r;
    FILE *f = fopen(TMPKO_PATH, "wb");
    if (!f)
        return -1;
    if (fwrite(d, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        return -1;
    }
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    fd = open(TMPKO_PATH, O_RDONLY);
    if (fd < 0)
        return -1;
    r = syscall(__NR_finit_module, fd, args ? args : "", 0);
    {
        int e = errno;
        close(fd);
        errno = e;
    }
    return r < 0 ? -errno : 0;
}

static int is_live(void)
{
    FILE *f = fopen("/proc/modules", "r");
    char line[256];
    int found = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "rwbridge ", 9)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int saferead(char *out, int cap, const char *path)
{
    FILE *f = fopen(path, "r");
    int i = 0, c;
    if (!f)
        return -1;
    while (i < cap - 1 && (c = fgetc(f)) != EOF && c != '\n')
        out[i++] = (char)c;
    out[i] = 0;
    fclose(f);
    return 0;
}

/* ---- flavor blobs ---- */
struct blob {
    const char *name;
    const unsigned char *d;
    long n;
    int cfi;
};

int main(int argc, char **argv)
{
    struct state st;
    char vm[160], msg[256], stab[32], iss[32];
    int major, i, rc;
    const unsigned char *bd;
    long bn;
    int use_cfi;
    unsigned char *work;
    struct blob flavors[2];
    int order[2], norder = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--dry-run")) {
            dry = 1;
            break;
        }
        if (!strcmp(argv[i], "--extract-runsh")) {
            fwrite(_binary_runsh_start, 1,
                   _binary_runsh_len, stdout);
            return 0;
        }
    }

    if (!dry) {
        snprintf(msg, sizeof(msg), "%s", JOURNAL_DIR);
        mkdir(msg, 0755);
        snprintf(msg, sizeof(msg), "%s/Jspx.log", JOURNAL_DIR);
        jfp = fopen(msg, "a");
    }
    jlog("spx", "start");

    flavors[0].name = "plain";
    flavors[0].d = _binary_rwbridge_ko_start;
    flavors[0].n = (long)_binary_rwbridge_ko_len;
    flavors[0].cfi = 0;
    flavors[1].name = "cfi";
    flavors[1].d = _binary_rwbridge_cfi_ko_start;
    flavors[1].n = (long)_binary_rwbridge_cfi_ko_len;
    flavors[1].cfi = 1;

    major = kernel_major();
    snprintf(msg, sizeof(msg), "kernel major=%d", major);
    jlog("detect", msg);

    /* selection contract: CFI + 6.1+ => cfi; older and non-CFI => plain.
     * CFI presence is read from ground truth, not config: try cfi first
     * on 6.x (journal survives a trap), plain first below 6. */
    state_load(&st);
    if (major >= 6) {
        order[0] = 1;
        order[1] = 0;
    } else {
        order[0] = 0;
        order[1] = 1;
    }
    norder = 2;

    if (target_vermagic(vm, sizeof(vm)) < 0) {
        jlog("vermagic", "target resolve failed, aborting");
        return 1;
    }
    jlog("vermagic", vm);

    for (i = 0; i < norder; i++) {
        int fi = order[i];
        long rio = -1, reo = -1;
        int *tried = fi ? &st.cfi_tried : &st.plain_tried;
        if (*tried >= 2) {
            snprintf(msg, sizeof(msg), "%s already tried twice, skipping",
                     flavors[fi].name);
            jlog("select", msg);
            continue;
        }
        bd = flavors[fi].d;
        bn = flavors[fi].n;
        snprintf(msg, sizeof(msg), "trying %s (%ld bytes)", flavors[fi].name,
                 bn);
        jlog("select", msg);
        if (dry) {
            jlog("dry-run", "would patch vermagic + slots, then insmod");
            continue;
        }
        work = malloc((size_t)bn);
        if (!work) {
            jlog("select", "out of memory");
            return 1;
        }
        memcpy(work, bd, (size_t)bn);
        if (patch_vermagic(work, bn, vm) < 0) {
            jlog("patch", "vermagic patch failed, next flavor");
            free(work);
            continue;
        }
        /* dispatch slots: derive per-device from on-device reference
         * (never hardcoded offsets); surgery applies to the cfi flavor
         * (instrumented: dispatch safe). Plain on CFI kernels is left
         * alone (dispatch would load-panic — silent-Live wins). */
        use_cfi = flavors[fi].cfi;
        if (major >= 6 && use_cfi) {
            static const char *rdirs[] = {
                "/vendor/lib/modules", "/vendor_dlkm/lib/modules",
                "/system/lib/modules", NULL
            };
            int di, found = 0;
            for (di = 0; rdirs[di] && !found; di++) {
                DIR *dp = opendir(rdirs[di]);
                struct dirent *de;
                if (!dp)
                    continue;
                while ((de = readdir(dp))) {
                    size_t L = strlen(de->d_name);
                    char rp[512];
                    if (L < 4 || strcmp(de->d_name + L - 3, ".ko"))
                        continue;
                    snprintf(rp, sizeof(rp), "%s/%s", rdirs[di],
                             de->d_name);
                    if (!ref_slots_from_file(rp, &rio, &reo))
                        found = 1;
                    if (found)
                        break;
                }
                closedir(dp);
            }
            if (found) {
                int sr = slot_surgery(&work, &bn, rio, reo);
                snprintf(msg, sizeof(msg),
                         "slots init=%#lx exit=%#lx -> %s", rio, reo,
                         sr > 0 ? "APPLIED" : (sr == 0 ? "already matching" :
                                                            "FAILED"));
                jlog("surgery", msg);
            } else {
                jlog("surgery", "SKIPPED (no usable reference .ko)");
            }
        }
        (*tried)++;
        state_save(&st);
        jlog("insmod", "attempting (state saved + synced)");
        rc = do_insmod(work, bn, getenv("RWBRIDGE_ARGS"));
        free(work);
        work = NULL;
        if (rc == 0 && is_live()) {
            if (!saferead(stab, sizeof(stab),
                          "/sys/module/rwbridge/parameters/stability") &&
                !saferead(iss, sizeof(iss), "/sys/module/rwbridge/initstate")) {
                snprintf(msg, sizeof(msg), "Live confirmed (%s flavor)",
                         flavors[fi].name);
                jlog("verify", msg);
                if (jfp)
                    fclose(jfp);
                return 0;
            }
        }
        snprintf(msg, sizeof(msg), "%s load failed rc=%d, trying dmesg retry",
                 flavors[fi].name, rc);
        jlog("insmod", msg);
        /* dmesg-feedback vermagic retry (same as run.sh): the kernel names
         * the exact extras it wants ("should be '...'"). Re-patch the same
         * buffer (in-place, idempotent) and retry once WITHOUT burning
         * another attempt — a vermagic miss is not a flavor verdict. */
        if (!dmesg_want(vm, sizeof(vm))) {
            jlog("vermagic", vm);
            /* rebuild work from the pristine blob (retry starts clean) */
            free(work);
            work = malloc((size_t)flavors[fi].n);
            bn = flavors[fi].n;
            if (work) {
                memcpy(work, flavors[fi].d, (size_t)bn);
                if (!patch_vermagic(work, bn, vm)) {
                    /* re-apply surgery on the fresh buffer when gated */
                    jlog("insmod", "retrying same flavor (state kept)");
                    rc = do_insmod(work, bn, getenv("RWBRIDGE_ARGS"));
                    free(work);
                    work = NULL;
                    if (rc == 0 && is_live()) {
                        jlog("verify", "Live confirmed on retry");
                        if (jfp)
                            fclose(jfp);
                        return 0;
                    }
                }
            }
        }
        if (work) {
            free(work);
            work = NULL;
        }
    }
    jlog("spx", "NO-GO: all flavors exhausted (see journal)");
    if (jfp)
        fclose(jfp);
    return 1;
}
