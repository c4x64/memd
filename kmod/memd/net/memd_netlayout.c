/* Runtime kernel-version / generation mapping for memd_netlayout.
 *
 * Generalizes the (major, minor) -> generation map so it works for both
 * Android GKI and normal/mainline Linux LTS kernels: the gen is derived
 * solely from (major, minor), never from an "android"/vendor token in
 * the release string. Unknown versions fail closed (MEMD_GEN_UNKNOWN)
 * instead of guessing offsets. */
#include "memd_netlayout.h"

#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include "memd_common.h"
#include "memd_utils.h"

/* Cached detection result for the running kernel. -2 means "not yet
 * computed"; -1 (MEMD_GEN_UNKNOWN) means "computed, unsupported". */
static int memd_cached_gen = -2;
static int memd_cached_major = 0;
static int memd_cached_minor = 0;
static int memd_cached_patch = 0;
static int memd_cached_android = 0;
static char memd_cached_release[72];

/* Map (major, minor) to a generation index, or MEMD_GEN_UNKNOWN. Pure
 * function of its arguments: no kernel state, no allocation. */
int memd_net_gen_from_version(int major, int minor)
{
    if (major == 5 && minor == 4)
        return MEMD_GEN_54;
    if (major == 5 && minor == 10)
        return MEMD_GEN_510;
    if (major == 5 && minor == 15)
        return MEMD_GEN_515;
    if (major == 6 && minor == 1)
        return MEMD_GEN_61;
    if (major == 6 && minor == 6)
        return MEMD_GEN_66;
    if (major == 6 && minor == 12)
        return MEMD_GEN_612;
    return MEMD_GEN_UNKNOWN;
}

/* True when the release string contains an "android" token (case
 * insensitive). Informational only: generation mapping does not depend
 * on it, so normal Linux kernels are first-class. */
int memd_net_is_android_release(const char *release)
{
    size_t i, j;
    static const char needle[] = "android";
    if (!release)
        return 0;
    for (i = 0; release[i]; i++) {
        for (j = 0; needle[j]; j++) {
            char c = release[i + j];
            if (!c)
                return 0;
            if (c >= 'A' && c <= 'Z')
                c = (char)(c - 'A' + 'a');
            if (c != needle[j])
                break;
        }
        if (!needle[j])
            return 1;
    }
    return 0;
}

/* Parse "5.15.0-64-generic", "6.1.0-...", "5.4.147-android11-..." etc.
 * Returns 0 when a major.minor pair is found, -1 otherwise. Patch is 0
 * when absent. Output pointers may be NULL. */
int memd_net_parse_release(const char *release, int *major, int *minor,
                           int *patch)
{
    int maj = 0, min = 0, pat = 0;
    int i, j;
    if (!release)
        return -1;
    for (i = 0; i < 64 && release[i]; i++) {
        if (release[i] < '0' || release[i] > '9')
            continue;
        maj = 0;
        j = i;
        while (j < 64 && release[j] >= '0' && release[j] <= '9' &&
               maj < 10000) {
            maj = maj * 10 + (release[j] - '0');
            j++;
        }
        if (release[j] != '.')
            continue;
        j++;
        if (j >= 64 || release[j] < '0' || release[j] > '9')
            continue;
        min = 0;
        while (j < 64 && release[j] >= '0' && release[j] <= '9' &&
               min < 10000) {
            min = min * 10 + (release[j] - '0');
            j++;
        }
        /* Optional patch level (ignored for gen mapping but reported). */
        pat = 0;
        if (j < 64 && release[j] == '.') {
            j++;
            while (j < 64 && release[j] >= '0' && release[j] <= '9' &&
                   pat < 100000) {
                pat = pat * 10 + (release[j] - '0');
                j++;
            }
        }
        break;
    }
    if (i >= 64 || !release[i])
        return -1;
    if (major)
        *major = maj;
    if (minor)
        *minor = min;
    if (patch)
        *patch = pat;
    return 0;
}

int memd_net_version_supported(int major, int minor)
{
    return memd_net_gen_from_version(major, minor) != MEMD_GEN_UNKNOWN;
}

const char *memd_net_gen_name(int gen)
{
    switch (gen) {
    case MEMD_GEN_54:
        return "5.4";
    case MEMD_GEN_510:
        return "5.10";
    case MEMD_GEN_515:
        return "5.15";
    case MEMD_GEN_61:
        return "6.1";
    case MEMD_GEN_66:
        return "6.6";
    case MEMD_GEN_612:
        return "6.12";
    default:
        return "unknown";
    }
}

int memd_net_release_str(char *buf, size_t cap)
{
    size_t i;
    if (!buf || cap == 0)
        return -1;
    /* Ensure the cache is populated. */
    (void)memd_net_gen();
    if (!memd_cached_release[0])
        return -1;
    for (i = 0; i + 1 < cap && memd_cached_release[i]; i++)
        buf[i] = memd_cached_release[i];
    buf[i] = '\0';
    return 0;
}

/* Read /proc/sys/kernel/osrelease content (exact string, no struct
 * offsets). Returns 0 ok, negative otherwise.
 * Uses runtime-resolved filp_open/close (no VFS import); kernel_read is a
 * stable GKI export. */
static int memd_read_osrelease(char *out, size_t cap)
{
    struct file *f;
    loff_t pos = 0;
    ssize_t n;
    size_t i;
    if (cap < 8)
        return -1;
    if (memd_filp_open("/proc/sys/kernel/osrelease", O_RDONLY, 0, &f) != 0)
        return -1;
    /* Load-bearing, not redundant: memd_filp_open returns 0 for any
     * non-NULL result including ERR_PTR, so a failed filp_open arrives
     * here as return 0 with f == ERR_PTR. */
    if (IS_ERR(f))
        return -1;
    n = memd_kernel_read(f, out, cap - 1, &pos);
    memd_filp_close(&f, NULL);
    if (n <= 0)
        return -1;
    out[n] = '\0';
    for (i = 0; i < (size_t)n; i++) {
        if (out[i] == '\n' || out[i] == '\r' || out[i] == ' ') {
            out[i] = '\0';
            break;
        }
    }
    if (!out[0])
        return -1;
    return 0;
}

int memd_net_gen(void)
{
    /* Cached on first use; safe to call repeatedly. Concurrent first calls
     * may recompute the same boot-constant result (benign, idempotent). */
    char rel[72];
    int maj = 0, min = 0, pat = 0;
    int is_android;

    if (memd_cached_gen != -2)
        return memd_cached_gen;

    memd_cached_gen = MEMD_GEN_UNKNOWN;
    /* Primary: /proc/sys/kernel/osrelease content (exact string, no
     * struct offsets involved). Fallback: init_utsname scan. Neither
     * assumes an Android release string. */
    if (!memd_read_osrelease(rel, sizeof(rel))) {
        memd_info("netlayout: release=%.64s\n", rel);
        is_android = memd_net_is_android_release(rel);
    } else {
        snprintf(rel, sizeof(rel), "%s", init_utsname()->release);
        memd_info("netlayout: release=%.64s (uts)\n", rel);
        is_android = memd_net_is_android_release(rel);
    }

    if (memd_net_parse_release(rel, &maj, &min, &pat) != 0) {
        memd_warn("netlayout: could not parse kernel version from "
                  "release; treating as unknown (NO-GO)\n");
        return memd_cached_gen;
    }

    memd_cached_major = maj;
    memd_cached_minor = min;
    memd_cached_patch = pat;
    memd_cached_android = is_android;

    /* Copy cached release (best effort). */
    {
        size_t i;
        for (i = 0; i + 1 < sizeof(memd_cached_release) && rel[i]; i++)
            memd_cached_release[i] = rel[i];
        memd_cached_release[i] = '\0';
    }

    memd_cached_gen = memd_net_gen_from_version(maj, min);
    if (memd_cached_gen == MEMD_GEN_UNKNOWN) {
        memd_warn("netlayout: unsupported kernel %d.%d.%d (android=%d) "
                  "-> NO-GO (refuse socket init, never guess)\n",
                  maj, min, pat, is_android);
    } else {
        memd_info("netlayout: gen=%d (%s) kernel=%d.%d.%d android=%d\n",
                  memd_cached_gen, memd_net_gen_name(memd_cached_gen),
                  maj, min, pat, is_android);
    }
    return memd_cached_gen;
}

int memd_net_gen_safe(void)
{
    return memd_net_gen();
}

/* Runtime-detected components of the running kernel release. These force
 * the cache to be populated first, so they never report stale zeros for a
 * supported kernel. */
int memd_net_cached_major(void)
{
    (void)memd_net_gen();
    return memd_cached_major;
}

int memd_net_cached_minor(void)
{
    (void)memd_net_gen();
    return memd_cached_minor;
}

int memd_net_cached_patch(void)
{
    (void)memd_net_gen();
    return memd_cached_patch;
}

int memd_net_cached_is_android(void)
{
    (void)memd_net_gen();
    return memd_cached_android;
}

/* kmod/memd/net/memd_netlayout.c[∂] */
