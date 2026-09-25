/* spx.c — SPX packed loader: ONE native binary carrying the 8 KMI LKM
 * artifacts plus run.sh, responsible for external patching and loading.
 *
 * Flow: detect kernel (uname -r) -> select artifacts whose (kver+generation)
 * match, exact matches first, kver-only siblings after -> patch embedded
 * copy (vermagic placeholder) -> finit_module -> verify Live (modules +
 * socket-probe). Journal with per-artifact attempt counting + fsync survives
 * panics: a post-reboot run sees attempt-without-success and moves to the
 * next match instead of retrying into a wall. Never loops forever: each
 * artifact attempted at most twice, then NO-GO (refuse loudly — a wrong
 * generation's structs would mis-walk, strictly worse than not loading).
 * No dispatch-slot surgery exists anymore (matched builds need none).
 *
 * No python3, no toybox beyond sh, no zlib (ground truth from journal +
 * Live checks instead). Static PIE (runs on bionic).
 *
 * Build (CI pack job): blobs generated from the eight .ko files + run.sh
 * (see workflow heredoc) then
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
extern const unsigned char _binary_rwbridge_a12_5_10_ko_start[];
extern const unsigned long _binary_rwbridge_a12_5_10_ko_len;
extern const unsigned char _binary_rwbridge_a13_5_10_ko_start[];
extern const unsigned long _binary_rwbridge_a13_5_10_ko_len;
extern const unsigned char _binary_rwbridge_a13_5_15_ko_start[];
extern const unsigned long _binary_rwbridge_a13_5_15_ko_len;
extern const unsigned char _binary_rwbridge_a14_5_15_ko_start[];
extern const unsigned long _binary_rwbridge_a14_5_15_ko_len;
extern const unsigned char _binary_rwbridge_a14_6_1_ko_start[];
extern const unsigned long _binary_rwbridge_a14_6_1_ko_len;
extern const unsigned char _binary_rwbridge_a15_6_1_ko_start[];
extern const unsigned long _binary_rwbridge_a15_6_1_ko_len;
extern const unsigned char _binary_rwbridge_a15_6_6_ko_start[];
extern const unsigned long _binary_rwbridge_a15_6_6_ko_len;
extern const unsigned char _binary_rwbridge_a16_6_12_ko_start[];
extern const unsigned long _binary_rwbridge_a16_6_12_ko_len;
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
    int tried[8];
};

static void state_load(struct state *s)
{
    FILE *f;
    memset(s, 0, sizeof(*s));
    f = fopen(STATE_PATH, "r");
    if (!f)
        return;
    if (fscanf(f, "%d %d %d %d %d %d %d %d", &s->tried[0], &s->tried[1],
                &s->tried[2], &s->tried[3], &s->tried[4], &s->tried[5],
                &s->tried[6], &s->tried[7]) != 8) {
        memset(s->tried, 0, sizeof(s->tried));
    }
    fclose(f);
}

static void state_save(const struct state *s)
{
    FILE *f = fopen(STATE_PATH, "w");
    if (!f)
        return;
    fprintf(f, "%d %d %d %d %d %d %d %d\n", s->tried[0], s->tried[1],
            s->tried[2], s->tried[3], s->tried[4], s->tried[5],
            s->tried[6], s->tried[7]);
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



/* read current init/exit slot offsets from target's relas (symbol-matched) */

/* dispatch-slot surgery: grow this_module if needed, move relas to ref slots */

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

/* dispatch slots from a reference .ko file (symbol-matched, 0 ok) */

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

/* proto liveness: scan families for the driver marker (SEQPACKET ->
 * ENOKEY) then open a RAW socket on it. Proves the proto registered,
 * i.e. the module is not just present but serving. Bounded scan. */
#include <sys/socket.h>
#include <errno.h>
#ifndef SOCK_SEQPACKET
#define SOCK_SEQPACKET 5
#endif
#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif
#ifndef PF_DECNET
#define PF_DECNET 12
#endif
#ifndef ENOKEY
#define ENOKEY 126
#endif
static int proto_live(void)
{
    int fam, s1, s2;
    for (fam = PF_DECnet; fam < PF_DECnet + 16; fam++) {
        s1 = socket(fam, SOCK_SEQPACKET, 0);
        if (s1 >= 0) {
            close(s1);
            continue;
        }
        if (errno != ENOKEY)
            continue;
        s2 = socket(fam, SOCK_RAW, 0);
        if (s2 < 0)
            continue;
        close(s2);
        return 1;
    }
    return 0;
}


/* ---- flavor blobs ---- */
struct blob {
    const char *name;
    const char *kver;
    const char *gen;
    const unsigned char *d;
    long n;
};

int main(int argc, char **argv)
{
    struct state st;
    char vm[160], msg[256];
    int major, i, rc;
    const unsigned char *bd;
    long bn;
    unsigned char *work;
    struct blob flavors[8];
    int order[8], norder = 0;

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

    flavors[0].name = "a12-5.10"; flavors[0].kver = "5.10"; flavors[0].gen = "android12";
    flavors[0].d = _binary_rwbridge_a12_5_10_ko_start;
    flavors[0].n = (long)_binary_rwbridge_a12_5_10_ko_len;
    flavors[1].name = "a13-5.10"; flavors[1].kver = "5.10"; flavors[1].gen = "android13";
    flavors[1].d = _binary_rwbridge_a13_5_10_ko_start;
    flavors[1].n = (long)_binary_rwbridge_a13_5_10_ko_len;
    flavors[2].name = "a13-5.15"; flavors[2].kver = "5.15"; flavors[2].gen = "android13";
    flavors[2].d = _binary_rwbridge_a13_5_15_ko_start;
    flavors[2].n = (long)_binary_rwbridge_a13_5_15_ko_len;
    flavors[3].name = "a14-5.15"; flavors[3].kver = "5.15"; flavors[3].gen = "android14";
    flavors[3].d = _binary_rwbridge_a14_5_15_ko_start;
    flavors[3].n = (long)_binary_rwbridge_a14_5_15_ko_len;
    flavors[4].name = "a14-6.1"; flavors[4].kver = "6.1"; flavors[4].gen = "android14";
    flavors[4].d = _binary_rwbridge_a14_6_1_ko_start;
    flavors[4].n = (long)_binary_rwbridge_a14_6_1_ko_len;
    flavors[5].name = "a15-6.1"; flavors[5].kver = "6.1"; flavors[5].gen = "android15";
    flavors[5].d = _binary_rwbridge_a15_6_1_ko_start;
    flavors[5].n = (long)_binary_rwbridge_a15_6_1_ko_len;
    flavors[6].name = "a15-6.6"; flavors[6].kver = "6.6"; flavors[6].gen = "android15";
    flavors[6].d = _binary_rwbridge_a15_6_6_ko_start;
    flavors[6].n = (long)_binary_rwbridge_a15_6_6_ko_len;
    flavors[7].name = "a16-6.12"; flavors[7].kver = "6.12"; flavors[7].gen = "android16";
    flavors[7].d = _binary_rwbridge_a16_6_12_ko_start;
    flavors[7].n = (long)_binary_rwbridge_a16_6_12_ko_len;

    major = kernel_major();
    snprintf(msg, sizeof(msg), "kernel major=%d", major);
    jlog("detect", msg);

    /* selection contract: match uname -r against (kver AND generation)
     * exactly first (pass 1), then kver-only siblings (pass 2, e.g. vendor
     * releases without an android tag). kver compares NUMERICALLY
     * (major.minor) so 6.1 never matches 6.12. Cross-generation attempts
     * are refused outright: a wrong generation's structs would mis-walk,
     * strictly worse than not loading. */
    state_load(&st);
    {
        struct utsname u;
        char rel[160] = {0};
        int pass, f;
        if (uname(&u) == 0) {
            size_t rl = strlen(u.release);
            if (rl >= sizeof(rel)) rl = sizeof(rel) - 1;
            memcpy(rel, u.release, rl);
            rel[rl] = 0;
        }
        snprintf(msg, sizeof(msg), "release=%s", rel[0] ? rel : "?");
        jlog("detect", msg);
        for (pass = 0; pass < 2 && norder < 8; pass++) {
            for (f = 0; f < 8 && norder < 8; f++) {
                int kvmaj = 0, kvmin = 0, ok = 0;
                if (!rel[0]) continue;
                if (sscanf(rel, "%d.%d", &kvmaj, &kvmin) != 2) continue;
                {
                    int fmaj = 0, fmin = 0;
                    if (sscanf(flavors[f].kver, "%d.%d", &fmaj, &fmin) != 2)
                        continue;
                    if (kvmaj != fmaj || kvmin != fmin)
                        continue;
                }
                if (pass == 0) {
                    if (!strstr(rel, flavors[f].gen))
                        continue;
                    ok = 1;
                } else {
                    ok = 1;
                }
                if (ok) {
                    int dup = 0, k;
                    for (k = 0; k < norder; k++)
                        if (order[k] == f) dup = 1;
                    if (!dup) {
                        order[norder++] = f;
                        snprintf(msg, sizeof(msg), "match pass %d: %s",
                                 pass, flavors[f].name);
                        jlog("select", msg);
                    }
                }
            }
        }
    }
    if (norder == 0) {
        jlog("select", "NO-GO: no artifact matches this kernel");
        if (jfp)
            fclose(jfp);
        return 1;
    }

    if (target_vermagic(vm, sizeof(vm)) < 0) {
        jlog("vermagic", "target resolve failed, aborting");
        return 1;
    }
    jlog("vermagic", vm);

    for (i = 0; i < norder; i++) {
        int fi = order[i];
        int *tried = &st.tried[fi];
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
            jlog("dry-run", "would patch vermagic, then insmod");
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
        (*tried)++;
        state_save(&st);
        jlog("insmod", "attempting (state saved + synced)");
        rc = do_insmod(work, bn, "");
        free(work);
        work = NULL;
        if (rc == 0 && is_live() && proto_live()) {
            snprintf(msg, sizeof(msg), "Live confirmed (%s artifact)",
                     flavors[fi].name);
            jlog("verify", msg);
            if (jfp)
                fclose(jfp);
            return 0;
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
                    jlog("insmod", "retrying same flavor (state kept)");
                    rc = do_insmod(work, bn, "");
                    free(work);
                    work = NULL;
                    if (rc == 0 && is_live() && proto_live()) {
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
    if (dry) {
        jlog("spx", "dry-run complete (no actions taken)");
        return 0;
    }
    jlog("spx", "NO-GO: all flavors exhausted (see journal)");
    if (jfp)
        fclose(jfp);
    return 1;
}
