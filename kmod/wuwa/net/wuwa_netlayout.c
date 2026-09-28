/* Runtime generation select: parse the RUNNING kernel release once.
 * Exact (major, minor) match against the known table; anything else is
 * an explicit NO-GO (-1), never a guess. */
#include "wuwa_netlayout.h"

#include <linux/utsname.h>
#include <linux/kernel.h>

int wuwa_net_gen(void)
{
    static int gen = -2;
    const char *r;
    int maj = 0, min = 0;
    if (gen != -2)
        return gen;
    gen = -1;
    r = init_utsname()->release;
    while (*r >= '0' && *r <= '9') {
        maj = maj * 10 + (*r - '0');
        r++;
    }
    if (*r != '.')
        return gen;
    r++;
    while (*r >= '0' && *r <= '9') {
        min = min * 10 + (*r - '0');
        r++;
    }
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
