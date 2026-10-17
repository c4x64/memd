/* memd_client.c — iOS/macOS user-mode client for MEMD.
 * Demonstrates basic usage: open device, query version, check process. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "client.h"

int main(int argc, char **argv)
{
    int fd;
    memd_version_cmd vcmd;
    int alive;
    uint32_t pid;

    printf("=== MEMD iOS/macOS Client ===\n");

    fd = memd_open();
    if (fd < 0) {
        printf("Failed to open %s: %s\n", MEMD_DEVICE_PATH, strerror(errno));
        printf("Is the MEMD kernel extension loaded?\n");
        return 1;
    }
    printf("Device opened (fd=%d)\n", fd);

    if (memd_version(fd, &vcmd) < 0) {
        printf("Version query failed: %s\n", strerror(errno));
    } else {
        printf("Version: %u.%u.%u (abi=%u, flags=0x%x, gen=%u)\n",
               vcmd.major, vcmd.minor, vcmd.patch,
               vcmd.abi, vcmd.flags, vcmd.gen);
    }

    if (memd_is_process_alive(fd, 1, &alive) < 0) {
        printf("Process check failed: %s\n", strerror(errno));
    } else {
        printf("PID 1 (launchd) alive: %s\n", alive ? "yes" : "no");
    }

    if (argc > 1) {
        if (memd_find_process(fd, argv[1], &pid) < 0) {
            printf("Find process failed: %s\n", strerror(errno));
        } else {
            printf("Found '%s' -> PID %u\n", argv[1], pid);
        }
    }

    memd_close(fd);
    printf("Done.\n");
    return 0;
}
/* iOS/memd_client.c[∂] */