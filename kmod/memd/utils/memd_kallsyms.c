/* /proc/kallsyms self-parse resolver. See header for the universality
 * argument. Only stable file APIs (filp_open, kernel_read) are imported;
 * everything else is exact-name matching on text. */
#include "memd_kallsyms.h"

#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
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
    "kallsyms_lookup_name",
    "pfn_valid",
    "max_pfn",
    "find_vma",
    "__find_vma",
};

#define MEMD_NWANT (sizeof(memd_wanted) / sizeof(memd_wanted[0]))

static unsigned long memd_addrs[sizeof(memd_wanted) / sizeof(memd_wanted[0])];
static bool memd_parsed;
static bool memd_unavailable;

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
static int memd_parse_line(const char *line, size_t len)
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
    if (idx < 0 || memd_addrs[idx] != 0)
        return 0;
    memd_addrs[idx] = addr;
    return 1;
}

static void memd_do_parse(void)
{
    struct file *f;
    char *buf;
    loff_t pos = 0;
    ssize_t n;
    size_t carry = 0;
    int found = 0;

    memd_parsed = true;
    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) {
        memd_unavailable = true;
        return;
    }
    f = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f)) {
        memd_unavailable = true;
        kfree(buf);
        return;
    }
    while (!memd_unavailable) {
        size_t avail;
        size_t start = 0, eol;
        n = kernel_read(f, buf + carry, 4096 - carry - 1, &pos);
        if (n <= 0)
            break;
        avail = carry + (size_t)n;
        buf[avail] = '\0';
        /* process complete lines; keep the tail carry */
        while (start < avail) {
            eol = start;
            while (eol < avail && buf[eol] != '\n')
                eol++;
            if (eol >= avail)
                break;
            found += memd_parse_line(buf + start, eol - start);
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
            start = avail;
        } else if (carry > 0 && start > 0) {
            memmove(buf, buf + start, carry);
        }
        if (n < (ssize_t)(4096 - carry - 1))
            break; /* EOF */
    }
    filp_close(f, NULL);
    kfree(buf);
    /* kptr_restrict renders every address 0: detect and mark so callers
     * fail soft once instead of per-call. A zero table with successful
     * reads means hidden, not absent. */
    {
        unsigned long i, nonzero = 0;
        for (i = 0; i < MEMD_NWANT; i++)
            nonzero += memd_addrs[i] ? 1 : 0;
        if (!nonzero)
            memd_unavailable = true;
    }
}

unsigned long memd_kallsyms(const char *name)
{
    int idx;
    if (!name)
        return 0;
    if (!memd_parsed)
        memd_do_parse();
    if (memd_unavailable)
        return 0;
    idx = memd_want_index(name);
    if (idx < 0)
        return 0;
    return memd_addrs[idx];
}
