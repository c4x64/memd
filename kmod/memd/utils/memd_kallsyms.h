#ifndef MEMD_KALLSYMS_H
#define MEMD_KALLSYMS_H

/* Runtime kallsyms via /proc/kallsyms self-parse (KPM-grade universality).
 *
 * No kprobe imports (weak or otherwise): vendor loaders reject GOT-page
 * relocs against even weak kprobe references, so the kprobe trick can
 * never be in a universal image. File access itself cannot be imported
 * either (GKI protects filp_open/kernel_read from unsigned modules),
 * so the three file helpers arrive once via MEMD_IOCTL_BOOTSTRAP from
 * userspace, which reads real addresses out of /proc/kallsyms. Until
 * then every lookup fails closed. The fixed wanted list is matched by
 * exact name. No headers beyond stable file APIs, no per-version code:
 * the same binary resolves on 5.10 through 6.12.
 *
 * kptr_restrict hiding addresses (%pK -> 0) is the fail-soft boundary:
 * userspace lowers it before install; without real addresses the
 * bootstrap is rejected and every caller degrades to "not found"
 * (R/W + hide + display-probe need no kallsyms at all).
 */
unsigned long memd_kallsyms(const char *name);

/* Install bootstrap file-helper addresses (kernel-canonical, else
 * -EINVAL). Re-arms the parser so a later lookup re-parses. */
int memd_kallsyms_bootstrap(unsigned long filp_open_addr,
                            unsigned long kernel_read_addr,
                            unsigned long filp_close_addr);

#endif /* MEMD_KALLSYMS_H */
/* kmod/memd/utils/memd_kallsyms.h[∂] */
