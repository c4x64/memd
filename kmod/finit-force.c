/* finit-force — finit_module(2) with version-magic override flags.
 *
 * Some devices ship an insmod(8) without -f, and --force semantics are
 * needed as a LAST resort only (modversions/vermagic mismatch on an
 * otherwise matching image). This helper performs exactly that syscall
 * and nothing else: IGNORE_MODVERSIONS | IGNORE_VERMAGIC. Signatures are
 * NOT overridable (sig-enforcing kernels stay NO-GO — the syscall
 * returns EKEYREJECTED and we report it).
 *
 * Usage: finit-force /path/to.ko   (prints rc=0 or rc=-errno)
 * Options:
 *   --dry-run    Print what would be done without loading
 *   --verbose    Show detailed information
 *   --no-verify  Skip post-load verification
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#ifndef __NR_finit_module
#if defined(__aarch64__)
#define __NR_finit_module 379
#else
#error "finit-force: aarch64 only"
#endif
#endif

#ifndef MODULE_INIT_IGNORE_MODVERSIONS
#define MODULE_INIT_IGNORE_MODVERSIONS 0x0001
#endif
#ifndef MODULE_INIT_IGNORE_VERMAGIC
#define MODULE_INIT_IGNORE_VERMAGIC 0x0002
#endif

static void print_usage(const char *prog)
 {
    printf("usage: %s [options] /path/to.ko\n", prog);
    printf("options:\n");
    printf("  --dry-run     Print what would be done without loading\n");
    printf("  --verbose     Show detailed information\n");
    printf("  --no-verify   Skip post-load verification\n");
    printf("  --help        Show this help\n");
}

static int verify_module_loaded(const char *module_name)
 {
    FILE *f = fopen("/proc/modules", "r");
    if (!f)
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, module_name)) {
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

int main(int argc, char **argv)
 {
    int fd;
    long r;
    int dry_run = 0;
    int verbose = 0;
    int no_verify = 0;
    char *module_path = NULL;
    char *module_name = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--no-verify") == 0) {
            no_verify = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            if (module_path) {
                fprintf(stderr, "Error: multiple module paths specified\n");
                return 2;
            }
            module_path = argv[i];
        } else {
            fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!module_path) {
        fprintf(stderr, "Error: module path required\n");
        print_usage(argv[0]);
        return 2;
    }

    if (verbose) {
        printf("finit-force: loading %s\n", module_path);
        if (dry_run)
            printf("  [DRY RUN] Would load with flags: IGNORE_MODVERSIONS | IGNORE_VERMAGIC\n");
    }

    if (dry_run) {
        printf("rc=0 (dry run)\n");
        return 0;
    }

    /* Extract module name for verification (into a copy: truncating
     * the extension in place would corrupt module_path for open()). */
    char modname[256];
    const char *slash = strrchr(module_path, '/');
    const char *base = slash ? slash + 1 : module_path;
    size_t blen = strlen(base);
    char *dot;
    if (blen >= sizeof(modname))
        blen = sizeof(modname) - 1;
    memcpy(modname, base, blen);
    modname[blen] = '\0';
    module_name = modname;
    dot = strrchr(module_name, '.');
    if (dot) *dot = '\0';

    fd = open(module_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "rc=-1 open: %s\n", strerror(errno));
        return 1;
    }

    if (verbose)
        printf("  finit_module(fd=%d, flags=0x%x)...\n", fd,
               MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);

    r = syscall(__NR_finit_module, fd, "",
                 (long)(MODULE_INIT_IGNORE_MODVERSIONS |
                        MODULE_INIT_IGNORE_VERMAGIC));
    if (r < 0) {
        int e = errno;
        close(fd);
        if (e == EKEYREJECTED) {
            fprintf(stderr, "rc=-%d %s (signature enforcement active)\n", e, strerror(e));
        } else {
            fprintf(stderr, "rc=-%d %s\n", e, strerror(e));
        }
        return 1;
    }
    close(fd);

    if (!no_verify) {
        if (verbose)
            printf("  verifying module '%s' in /proc/modules...\n", module_name);
        if (verify_module_loaded(module_name) == 0) {
            if (verbose)
                printf("  module verified in /proc/modules\n");
            printf("rc=0\n");
        } else {
            fprintf(stderr, "rc=-1 module not found in /proc/modules after load\n");
            return 1;
        }
    } else {
        printf("rc=0\n");
    }
    return 0;
}
