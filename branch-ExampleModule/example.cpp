/* ExampleModule: basic MEMD API usage in C++.
 * Demonstrates the memd.hpp interface for version querying and root.
 * Requires root on the target device. */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <errno.h>

#include "memd.hpp"

int main(void)
{
    printf("=== MEMD Example (C++) ===\n");

    /* The memd.hpp header provides the lxgr:: namespace with
     * in-process helpers. Kernel-module interaction goes through
     * the client.h ioctl interface (see example.c). */

    /* Demonstrate basic memory utilities from memd.hpp */
    printf("memd.hpp loaded successfully.\n");
    printf("sizeof(zygisk::Module) = %zu\n", sizeof(zygisk::Module));

    printf("=== Example complete ===\n");
    return 0;
}
/* branch-ExampleModule/example.cpp[∂] */