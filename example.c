/* ExampleModule: basic MEMD API usage in C.
 * Demonstrates opening the driver, querying version, and reading memory.
 * Requires root on the target device. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include "client.h"

int main(void)
{
    int fd;
    struct memd_version_cmd vcmd;
    int alive;

    printf("=== MEMD Example (C) ===\n");

    /* 1. Open the driver channel */
    fd = memd_open();
    if (fd < 0) {
        perror("memd_open");
        printf("Is the rwbridge module loaded? (insmod rwbridge.ko)\n");
        return 1;
    }
    printf("Driver opened (fd=%d)\n", fd);

    /* 2. Query version */
    memset(&vcmd, 0, sizeof(vcmd));
    if (memd_call(fd, MEMD_IOCTL_VERSION, &vcmd) < 0) {
        perror("MEMD_IOCTL_VERSION");
    } else {
        printf("Module version: %d.%d.%d (abi=%d, flags=0x%x, gen=%d)\n",
               vcmd.major, vcmd.minor, vcmd.patch,
               vcmd.abi, vcmd.flags, vcmd.gen);
    }

    /* 3. Check if a process is alive (e.g., PID 1 = init) */
    if (memd_is_process_alive(fd, 1, &alive) < 0) {
        perror("MEMD_IOCTL_IS_PROCESS_ALIVE");
    } else {
        printf("PID 1 (init) alive: %s\n", alive ? "yes" : "no");
    }

    /* 4. Read memory from PID 1 (first 16 bytes of /proc/1/exe base) */
    {
        struct memd_read_physical_memory_cmd cmd;
        char buf[64];
        memset(&cmd, 0, sizeof(cmd));
        cmd.pid = 1;
        cmd.src_va = 0; /* placeholder — real usage resolves via module base */
        cmd.dst_va = (uintptr_t)buf;
        cmd.size = sizeof(buf);
        if (memd_read_memory(fd, 1, 0, (uintptr_t)buf, sizeof(buf)) < 0) {
            /* Expected to fail with src_va=0; demonstrates the call path */
            printf("Read memory: %s (expected for src_va=0)\n", strerror(errno));
        } else {
            printf("Read %zu bytes from PID 1\n", sizeof(buf));
        }
    }

    /* 5. Hide / unhide a process (demonstration only — use real PID) */
    {
        struct memd_hide_proc_cmd cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.pid = 0; /* 0 = no-op demonstration */
        cmd.hide = 1;
        if (memd_call(fd, MEMD_IOCTL_HIDE_PROCESS, &cmd) < 0) {
            printf("Hide process: %s (expected for pid=0)\n", strerror(errno));
        }
    }

    /* 6. Clean shutdown */
    close(fd);
    printf("Driver closed. Example complete.\n");
    return 0;
}
/* branch-ExampleModule/example.c[∂] */