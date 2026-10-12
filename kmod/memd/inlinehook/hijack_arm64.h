#ifndef ANDROID_MEMD_HIJACK_ARM64_H
#define ANDROID_MEMD_HIJACK_ARM64_H

#define INSTRUCTION_SIZE (4)
#define HIJACK_INST_NUM (6)
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#define HOOK_TARGET_OFFSET (0)

int init_arch(void);

__nocfi int hook_write_range(void *target, void *source, int size);

struct memd_trampoline;

struct memd_trampoline *memd_create_trampoline(void *target, void *handler, size_t hook_size);
void memd_destroy_trampoline(struct memd_trampoline *tramp);
int memd_install_inline_hook(void *target, void *handler, void **orig);
void memd_remove_inline_hook(void *target, void *orig);

#endif // ANDROID_MEMD_HIJACK_ARM64_H
