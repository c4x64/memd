/* Runtime generation select: parse the RUNNING kernel release once.
 * Exact (major, minor) match against the known table; anything else is
 * an explicit NO-GO (-1), never a guess. */
#include "wuwa_netlayout.h"

#include <linux/utsname.h>
#include <linux/kernel.h>
#include "wuwa_common.h"

int wuwa_net_gen(void)
{
    static int gen = -2;
    const char *r;
    int i, maj, min, j;
    if (gen != -2)
        return gen;
    gen = -1;
    r = init_utsname()->release;
    wuwa_info("netlayout: release=%.16s\n", r);
    /* Scan for the first digit.digit pair (tolerates junk prefixes). */
    for (i = 0; i < 16 && r[i]; i++) {
        if (r[i] < '0' || r[i] > '9')
            continue;
        maj = 0;
        j = i;
        while (j < 16 && r[j] >= '0' && r[j] <= '9') {
            maj = maj * 10 + (r[j] - '0');
            j++;
        }
        if (r[j] != '.')
            continue;
        j++;
        if (j >= 16 || r[j] < '0' || r[j] > '9')
            continue;
        min = 0;
        while (j < 16 && r[j] >= '0' && r[j] <= '9') {
            min = min * 10 + (r[j] - '0');
            j++;
        }
        break;
    }
    if (i >= 16 || !r[i])
        return gen;
    if (maj == 5 && min == 10)
        gen = WUWA_GEN_510;
    else if (maj == 5 && min == 15)
        gen = WUWA_GEN_515;
    else if (maj == 6 && min == 1)
        gen = WUWA_GEN_61;
    else if (maj == 6 && min == 6)
        gen = WUWA_GEN_66;
    else if (maj == 6 && min == 12)
        gen = WUWA_GEN_612;
    return gen;
}
