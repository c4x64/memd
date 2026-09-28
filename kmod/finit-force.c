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
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

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

int main(int argc, char **argv)
{
    int fd;
    long r;
    if (argc != 2) {
        printf("usage: finit-force /path/to.ko\n");
        return 2;
    }
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("rc=-1 open: %s\n", strerror(errno));
        return 1;
    }
    r = syscall(__NR_finit_module, fd, "",
                (long)(MODULE_INIT_IGNORE_MODVERSIONS |
                       MODULE_INIT_IGNORE_VERMAGIC));
    if (r < 0) {
        int e = errno;
        close(fd);
        printf("rc=-%d %s\n", e, strerror(e));
        return 1;
    }
    close(fd);
    printf("rc=0\n");
    return 0;
}
