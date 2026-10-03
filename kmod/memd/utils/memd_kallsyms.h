#ifndef MEMD_KALLSYMS_H
#define MEMD_KALLSYMS_H

/* Runtime kallsyms via /proc/kallsyms self-parse (KPM-grade universality).
 *
 * No kprobe imports (weak or otherwise): vendor loaders reject GOT-page
 * relocs against even weak kprobe references, so the kprobe trick can
 * never be in a universal image. Instead we read /proc/kallsyms with our
 * directly-imported filp_open + kernel_read and match the fixed wanted
 * list by exact name. No headers beyond stable file APIs, no per-version
 * code: the same binary resolves on 5.10 through 6.12.
 *
 * kptr_restrict hiding addresses (%pK -> 0) is the fail-soft boundary:
 * parse succeeds with zero addresses and every caller degrades to
 * "not found" (R/W + hide + display-probe need no kallsyms at all).
 */
unsigned long memd_kallsyms(const char *name);

#endif /* MEMD_KALLSYMS_H */
