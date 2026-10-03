/* Runtime generation select: parse the RUNNING kernel release once.
 * Exact (major, minor) match against the known table; anything else is
 * an explicit NO-GO (-1), never a guess. */
#include "memd_netlayout.h"

#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include "memd_common.h"

/* Read /proc/sys/kernel/osrelease content (exact string, no struct
 * offsets). Returns 0 ok, negative otherwise. */
static int memd_read_osrelease(char *out, size_t cap)
{
    struct file *f;
    loff_t pos = 0;
    ssize_t n;
    size_t i;
    if (cap < 8)
        return -1;
    f = filp_open("/proc/sys/kernel/osrelease", O_RDONLY, 0);
    if (IS_ERR(f))
        return -1;
    n = kernel_read(f, out, cap - 1, &pos);
    filp_close(f, NULL);
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
    static int gen = -2;
    char rel[72];
    int i, maj, min, j;
    if (gen != -2)
        return gen;
    gen = -1;
    /* Primary: /proc/sys/kernel/osrelease content (exact string, no
     * struct offsets involved). Fallback: init_utsname scan. */
    if (!memd_read_osrelease(rel, sizeof(rel)))
        memd_info("netlayout: release=%.16s\n", rel);
    else {
        snprintf(rel, sizeof(rel), "%s", init_utsname()->release);
        memd_info("netlayout: release=%.16s (uts)\n", rel);
    }
    /* Scan for the first digit.digit pair (tolerates junk prefixes). */
    for (i = 0; i < 64 && rel[i]; i++) {
        if (rel[i] < '0' || rel[i] > '9')
            continue;
        maj = 0;
        j = i;
        while (j < 64 && rel[j] >= '0' && rel[j] <= '9') {
            maj = maj * 10 + (rel[j] - '0');
            j++;
        }
        if (rel[j] != '.')
            continue;
        j++;
        if (j >= 64 || rel[j] < '0' || rel[j] > '9')
            continue;
        min = 0;
        while (j < 64 && rel[j] >= '0' && rel[j] <= '9') {
            min = min * 10 + (rel[j] - '0');
            j++;
        }
        break;
    }
    if (i >= 64 || !rel[i])
        return gen;
    if (maj == 5 && min == 10)
        gen = MEMD_GEN_510;
    else if (maj == 5 && min == 15)
        gen = MEMD_GEN_515;
    else if (maj == 6 && min == 1)
        gen = MEMD_GEN_61;
    else if (maj == 6 && min == 6)
        gen = MEMD_GEN_66;
    else if (maj == 6 && min == 12)
        gen = MEMD_GEN_612;
    return gen;
}
