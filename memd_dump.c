/*
 * memtool — process memory inspector
 *
 * Uses /dev/memd (kernel phys-mem module) when available;
 * falls back to /proc/<pid>/mem.  Supports JSON output for
 * external tool integration.
 *
 * Usage:
 *   memtool ps                   list processes
 *   memtool maps <pid>           memory mappings
 *   memtool libs <pid>           loaded libraries
 *   memtool va2pa <pid> <vaddr>  virtual → physical address
 *   memtool phys <paddr> <len>   physical memory dump
 *   memtool read <pid> <vaddr> <len>  memory dump
 *   memtool offset <pid> <lib> <off> <len>  read at lib+offset
 *
 *   --json   JSON output (for external tools)
 *   --dev    set /dev/memd path (default /dev/memd)
 *
 * Environment:
 *   MEMD_DEV  path to kernel module device node
 *
 * Build:
 *   aarch64-linux-android34-clang -static -O2 -s -o memtool memd_dump.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <dirent.h>

#define MAX_READ    65536
#define MAPS_SZ     524288
#define PAGE_SIZE   4096

#define MEMD_IOC_MAGIC 0xed
#define MEMD_IOC_XFER  _IOWR(MEMD_IOC_MAGIC, 1, struct memd_req)

struct __attribute__((packed)) memd_req {
    uint64_t phys_addr;
    uint32_t size;
    uint8_t  write;
    uint64_t user_buf_ptr;
};

static int memd_fd = -1;
static int json_mode = 0;

/* ── JSON helpers ── */
static void json_printf(const char *fmt, ...)
{
    if (!json_mode) return;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static void out(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

/* ── open /dev/memd ── */
static int open_memd(const char *devpath)
{
    int fd = open(devpath, O_RDWR);
    if (fd < 0 && !json_mode)
        fprintf(stderr, "note: %s not available, falling back to /proc/pid/mem\n", devpath);
    return fd;
}

/* ── physical read via ioctl ── */
static ssize_t read_phys(uint64_t paddr, void *buf, size_t size)
{
    struct memd_req req = {
        .phys_addr    = paddr,
        .size         = size < MAX_READ ? size : MAX_READ,
        .write        = 0,
        .user_buf_ptr = (uint64_t)(uintptr_t)buf,
    };
    return ioctl(memd_fd, MEMD_IOC_XFER, &req);
}

/* ── fallback via /proc/pid/mem ── */
static ssize_t read_procmem(pid_t pid, uint64_t addr, void *buf, size_t size)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t ret = pread64(fd, buf, size, (off64_t)addr);
    close(fd);
    return ret;
}

/* ── read via best path (phys via pagemap, or fallback) ── */
static ssize_t xread(pid_t pid, uint64_t vaddr, void *buf, size_t size)
{
    if (memd_fd >= 0) {
        uint64_t paddr = 0;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
        int pm_fd = open(path, O_RDONLY);
        if (pm_fd >= 0) {
            off64_t off = (vaddr / PAGE_SIZE) * sizeof(uint64_t);
            uint64_t ent;
            if (pread64(pm_fd, &ent, sizeof(ent), off) == sizeof(ent) && (ent & (1ULL << 63))) {
                uint64_t pfn = ent & ((1ULL << 55) - 1);
                paddr = pfn * PAGE_SIZE + (vaddr & (PAGE_SIZE - 1));
            }
            close(pm_fd);
        }
        if (paddr) return read_phys(paddr, buf, size);
    }
    return read_procmem(pid, vaddr, buf, size);
}

/* ── read /proc/<pid>/maps ── */
static int read_maps(pid_t pid, char *buf, int bufsz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int total = 0;
    while (total < bufsz) {
        int n = read(fd, buf + total, bufsz - total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    return total;
}

/* ── find library base ── */
static uint64_t find_lib_base(pid_t pid, const char *libname)
{
    static char maps[MAPS_SZ + 1];
    int len = read_maps(pid, maps, MAPS_SZ);
    if (len <= 0) return 0;
    maps[len] = '\0';
    char *p = maps;
    while (p && *p) {
        char *line = p;
        p = strchr(p, '\n');
        if (p) *p++ = '\0';
        unsigned long start;
        char perms[16], path[512];
        path[0] = '\0';
        if (sscanf(line, "%lx-%*x %4s %*x %*s %*d %511s", &start, perms, path) >= 2)
            if (perms[2] == 'x' && strstr(path, libname))
                return start;
    }
    return 0;
}

/* ── hex dump ── */
static void hex_dump(uint64_t base, const unsigned char *buf, size_t len, const char *suffix)
{
    if (json_mode) {
        json_printf("{\"base_addr\":\"0x%lx\",\"bytes\":%zu,\"data\":\"", base, len);
        for (size_t i = 0; i < len; i++)
            json_printf("%02x", buf[i]);
        json_printf("\"}\n");
        return;
    }
    for (size_t i = 0; i < len; i += 16) {
        out("%08lx  ", base + i);
        for (size_t j = 0; j < 16 && i + j < len; j++)
            out("%02x%c", buf[i + j], j == 7 ? '-' : ' ');
        for (size_t j = 0; j < 16 && i + j < len; j++)
            out("%c", buf[i + j] >= 32 && buf[i + j] < 127 ? buf[i + j] : '.');
        out("\n");
    }
    if (suffix) out("  (%zu bytes%s)\n", len, suffix);
}

/* ── commands ── */

static void cmd_ps(void)
{
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    if (!json_mode) out("%-8s %-6s %s\n", "PID", "UID", "NAME");
    json_printf("[");
    int first = 1;
    while ((de = readdir(d))) {
        pid_t pid = atoi(de->d_name);
        if (pid <= 0) continue;
        char path[64], line[256], name[256] = "?";
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        int n = read(fd, line, sizeof(line)-1);
        close(fd);
        if (n > 0) {
            line[n] = '\0';
            char *close_paren = strrchr(line, ')');
            if (close_paren) {
                char *open_paren = close_paren;
                while (open_paren > line && *open_paren != '(') open_paren--;
                if (*open_paren == '(') {
                    size_t nlen = close_paren - open_paren - 1;
                    if (nlen > 0 && nlen < sizeof(name)) {
                        memcpy(name, open_paren + 1, nlen);
                        name[nlen] = '\0';
                    }
                }
            }
        }
        struct stat st;
        uid_t uid = 0;
        if (stat(path, &st) == 0) uid = st.st_uid;
        if (json_mode) {
            json_printf("%s{\"pid\":%d,\"uid\":%d,\"name\":\"%s\"}", first ? "" : ",", pid, uid, name);
            first = 0;
        } else {
            out("%-8d %-6d %s\n", pid, uid, name);
        }
    }
    json_printf("]\n");
    closedir(d);
}

static void cmd_maps(int argc, char **argv)
{
    pid_t pid = atoi(argv[0]);
    char buf[MAPS_SZ + 1];
    int len = read_maps(pid, buf, MAPS_SZ);
    if (len <= 0) { out("error: can't read /proc/%d/maps\n", pid); return; }
    buf[len] = '\0';
    if (json_mode) {
        json_printf("{\"pid\":%d,\"maps\":%zu,\"data\":\"", pid, (size_t)len);
        for (int i = 0; i < len; i++) {
            if (buf[i] == '\n') json_printf("\\n");
            else if (buf[i] == '\\') json_printf("\\\\");
            else if (buf[i] == '"') json_printf("\\\"");
            else if (buf[i] >= 32) json_printf("%c", buf[i]);
        }
        json_printf("\"}\n");
        return;
    }
    out("%s", buf);
}

static void cmd_libs(int argc, char **argv)
{
    pid_t pid = atoi(argv[0]);
    char buf[MAPS_SZ + 1];
    int len = read_maps(pid, buf, MAPS_SZ);
    if (len <= 0) { out("error: can't read /proc/%d/maps\n", pid); return; }
    buf[len] = '\0';
    if (!json_mode) out("%-4s  %-18s  %s\n", "PERM", "ADDRESS", "LIBRARY");
    json_printf("[");
    int first = 1;
    char *p = buf;
    while (p && *p) {
        char *line = p;
        p = strchr(p, '\n');
        if (p) *p++ = '\0';
        unsigned long start, stop;
        char perms[16], path[512];
        path[0] = '\0';
        if (sscanf(line, "%lx-%lx %4s %*x %*s %*d %511s", &start, &stop, perms, path) >= 4 && path[0] == '/') {
            if (json_mode) {
                json_printf("%s{\"base\":\"0x%lx\",\"end\":\"0x%lx\",\"perms\":\"%s\",\"path\":\"%s\"}",
                           first ? "" : ",", start, stop, perms, path);
                first = 0;
            } else {
                out("%-4s  0x%lx-0x%lx  %s\n", perms, start, stop, path);
            }
        }
    }
    json_printf("]\n");
}

static void cmd_va2pa(int argc, char **argv)
{
    pid_t pid = atoi(argv[0]);
    uint64_t vaddr = strtoull(argv[1], NULL, 0);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { out("error: can't open %s\n", path); return; }
    off64_t off = (vaddr / PAGE_SIZE) * sizeof(uint64_t);
    uint64_t ent;
    if (pread64(fd, &ent, sizeof(ent), off) != sizeof(ent)) { close(fd); out("error: pagemap read\n"); return; }
    close(fd);
    if (json_mode) {
        json_printf("{\"vaddr\":\"0x%lx\",\"entry\":\"0x%016llx\",\"present\":%d", vaddr, (unsigned long long)ent, !!(ent & (1ULL<<63)));
        if (ent & (1ULL << 63)) {
            uint64_t pfn = ent & ((1ULL << 55) - 1);
            json_printf(",\"pfn\":\"0x%lx\",\"paddr\":\"0x%lx\"", pfn, pfn * PAGE_SIZE + (vaddr & (PAGE_SIZE - 1)));
        }
        json_printf("}\n");
        return;
    }
    out("0x%lx  entry=0x%016llx  present=%d\n", vaddr, (unsigned long long)ent, !!(ent & (1ULL<<63)));
    if (!(ent & (1ULL << 63))) { out("  (not present)\n"); return; }
    uint64_t pfn = ent & ((1ULL << 55) - 1);
    out("  → phys 0x%lx (PFN 0x%lx)\n", pfn * PAGE_SIZE + (vaddr & (PAGE_SIZE - 1)), pfn);
}

static void cmd_phys(int argc, char **argv)
{
    uint64_t paddr = strtoull(argv[0], NULL, 0);
    size_t size = atol(argv[1]);
    if (size > MAX_READ) size = MAX_READ;
    if (memd_fd < 0) { out("error: /dev/memd unavailable\n"); return; }
    unsigned char buf[MAX_READ];
    ssize_t ret = read_phys(paddr, buf, size);
    if (ret <= 0) { out("error: read failed (%zd)\n", ret); return; }
    hex_dump(paddr, buf, (size_t)ret, NULL);
}

static void cmd_read(int argc, char **argv)
{
    pid_t pid = atoi(argv[0]);
    uint64_t vaddr = strtoull(argv[1], NULL, 0);
    size_t size = atol(argv[2]);
    if (size > MAX_READ) size = MAX_READ;
    unsigned char buf[MAX_READ];
    ssize_t ret = xread(pid, vaddr, buf, size);
    if (ret <= 0) { out("error: read failed (%zd)\n", ret); return; }
    hex_dump(vaddr, buf, (size_t)ret, NULL);
}

static void cmd_offset(int argc, char **argv)
{
    pid_t pid = atoi(argv[0]);
    const char *lib = argv[1];
    uint64_t offset = strtoull(argv[2], NULL, 0);
    size_t size = atol(argv[3]);
    if (size > MAX_READ) size = MAX_READ;
    uint64_t base = find_lib_base(pid, lib);
    if (!base) { out("error: '%s' not found in pid %d\n", lib, pid); return; }
    uint64_t vaddr = base + offset;
    if (!json_mode) out("lib: %s  base: 0x%lx  offset: 0x%lx  vaddr: 0x%lx\n", lib, base, offset, vaddr);
    unsigned char buf[MAX_READ];
    ssize_t ret = xread(pid, vaddr, buf, size);
    if (ret <= 0) { out("error: read failed (%zd)\n", ret); return; }
    char suffix[128];
    snprintf(suffix, sizeof(suffix), " from %s+0x%lx", lib, offset);
    hex_dump(vaddr, buf, (size_t)ret, suffix);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s [--json] [--dev path] <command> [args...]\n\n"
            "Commands:\n"
            "  ps                         list processes\n"
            "  maps <pid>                 memory mappings\n"
            "  libs <pid>                 loaded libraries\n"
            "  va2pa <pid> <vaddr>        virtual->physical translation\n"
            "  phys <paddr> <len>         physical memory dump\n"
            "  read <pid> <vaddr> <len>   memory dump\n"
            "  offset <pid> <lib> <off> <len>  read at lib+offset\n"
            "Environment:\n"
            "  MEMD_DEV  path to kernel module device (default /dev/memd)\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *devpath = getenv("MEMD_DEV");
    if (!devpath) devpath = "/dev/memd";

    /* parse global flags before command */
    int argpos = 1;
    while (argpos < argc && argv[argpos][0] == '-') {
        if (strcmp(argv[argpos], "--json") == 0)      { json_mode = 1; argpos++; }
        else if (strcmp(argv[argpos], "--dev") == 0 && argpos + 1 < argc) { devpath = argv[argpos + 1]; argpos += 2; }
        else break;
    }

    if (argpos >= argc) { usage(argv[0]); return 1; }

    memd_fd = open_memd(devpath);

    const char *cmd = argv[argpos];
    int nargs = argc - argpos - 1;
    char **args = argv + argpos + 1;

    int ok = 1;
    if (strcmp(cmd, "ps") == 0)
        cmd_ps();
    else if (strcmp(cmd, "maps") == 0 && nargs >= 1)
        cmd_maps(nargs, args);
    else if (strcmp(cmd, "libs") == 0 && nargs >= 1)
        cmd_libs(nargs, args);
    else if (strcmp(cmd, "va2pa") == 0 && nargs >= 2)
        cmd_va2pa(nargs, args);
    else if (strcmp(cmd, "phys") == 0 && nargs >= 2)
        cmd_phys(nargs, args);
    else if (strcmp(cmd, "read") == 0 && nargs >= 3)
        cmd_read(nargs, args);
    else if (strcmp(cmd, "offset") == 0 && nargs >= 4)
        cmd_offset(nargs, args);
    else {
        usage(argv[0]);
        ok = 0;
    }

    if (memd_fd >= 0) close(memd_fd);
    return ok ? 0 : 1;
}
