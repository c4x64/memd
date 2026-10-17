/* memd_client.c — Windows user-mode client for MEMD.
 * Demonstrates basic usage: open device, query version, check process. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "client.h"

int main(int argc, char **argv)
{
    HANDLE h;
    memd_version_cmd vcmd;
    int alive;
    uint32_t pid;

    printf("=== MEMD Windows Client ===\n");

    h = memd_open();
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed to open %s (error %lu)\n", MEMD_DEVICE_NAME, GetLastError());
        printf("Is the MEMD driver loaded?\n");
        return 1;
    }
    printf("Device opened.\n");

    if (memd_version(h, &vcmd) < 0) {
        printf("Version query failed (error %lu)\n", GetLastError());
    } else {
        printf("Version: %u.%u.%u (abi=%u, flags=0x%x, gen=%u)\n",
               vcmd.major, vcmd.minor, vcmd.patch,
               vcmd.abi, vcmd.flags, vcmd.gen);
    }

    if (memd_is_process_alive(h, 4, &alive) < 0) {
        printf("Process check failed (error %lu)\n", GetLastError());
    } else {
        printf("PID 4 (System) alive: %s\n", alive ? "yes" : "no");
    }

    if (argc > 1) {
        if (memd_find_process(h, argv[1], &pid) < 0) {
            printf("Find process failed (error %lu)\n", GetLastError());
        } else {
            printf("Found '%s' -> PID %u\n", argv[1], pid);
        }
    }

    memd_close(h);
    printf("Done.\n");
    return 0;
}
/* Windows/memd_client.c[∂] */