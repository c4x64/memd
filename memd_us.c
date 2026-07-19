/*
 * debugd_unsafe — SYSCALL-MODE FALLBACK daemon
 *
 * WARNING: This daemon uses /proc/<pid>/mem and fork() per connection,
 * which are visible in the target's fd/, strace, and audit logs.
 * Prefer the kernel module (/dev/memd, phys-mem path) for silent operation.
 *
 * This is a FALLBACK ONLY for environments where the kernel module
 * cannot be loaded.  Every read/write leaves detectable traces.
 *
 * Protocol: [pid:4LE][address:8LE][size:4LE][mode:1]
 *   mode 0 = read  (raw data),  mode 1 = write (payload follows)
 *   Error  = "ERR", "DENY", "TOOBIG"
 *
 * Socket path: $DEBUGD_SOCK or /data/local/tmp/debug_socket
 *
 * Build:
 *   aarch64-linux-android34-clang -static -O2 -s -o debugd_unsafe memd_us.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>

#define DATABUF_SZ  65536
#define MAX_CLIENTS 8
#define MAPS_SZ     524288
#define RCV_TIMEOUT 10
#define SHELL_UID   2000
#define APP_UID_MIN 10000
#define APP_UID_MAX 19999

static const char *default_sock = "/data/local/tmp/debug_socket";
static const char *g_sock_path;
static pid_t g_force_pid = 0;

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        p += n; len -= n;
    }
    return 0;
}

static int pid_allowed(pid_t pid)
{
    if (g_force_pid) return pid == g_force_pid;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    struct stat st;
    if (stat(path, &st) < 0) return 0;
    uid_t u = st.st_uid;
    return (u >= APP_UID_MIN && u <= APP_UID_MAX) || u == SHELL_UID;
}

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

static int range_allowed(pid_t pid, unsigned long addr, unsigned int size, int is_write)
{
    if (size == 0) return 0;
    unsigned long end = addr + (unsigned long)size;
    if (end < addr) return 0;
    static char maps[MAPS_SZ + 1];
    int len = read_maps(pid, maps, MAPS_SZ);
    if (len <= 0) return 0;
    maps[len] = '\0';
    char *p = maps, *ep = maps + len;
    while (p < ep) {
        char *line = p;
        while (p < ep && *p != '\n') p++;
        if (p >= ep) break;
        *p++ = '\0';
        unsigned long ms, me;
        char perms[8], mpath[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*x %*s %*d %255s", &ms, &me, perms, mpath) < 3) continue;
        if (addr >= me) continue;
        if (end  <= ms) continue;
        if (addr < ms || end > me) return 0;
        if (perms[2] == 'x') return !is_write;
        if (mpath[0] == '\0' || mpath[0] == '[') return is_write ? (perms[1] == 'w') : 1;
        return 0;
    }
    return 0;
}

static ssize_t xfer(pid_t pid, unsigned long addr, void *buf, size_t size, int is_write)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, is_write ? O_RDWR : O_RDONLY);
    if (fd < 0) return -1;
    ssize_t ret;
    if (is_write) ret = pwrite64(fd, buf, size, (off64_t)addr);
    else          ret = pread64(fd, buf, size, (off64_t)addr);
    close(fd);
    return ret;
}

static void handle(int clifd)
{
    struct timeval tv = { .tv_sec = RCV_TIMEOUT };
    setsockopt(clifd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct ucred cred;
    socklen_t clen = sizeof(cred);
    if (getsockopt(clifd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0 || cred.uid != SHELL_UID)
        { write_all(clifd, "DENY", 4); close(clifd); return; }

    unsigned char hdr[17];
    int tot = 0;
    while (tot < 17) {
        int n = read(clifd, hdr + tot, 17 - tot);
        if (n <= 0) { write_all(clifd, "ERR", 3); close(clifd); return; }
        tot += n;
    }
    uint32_t pr; uint64_t ad; uint32_t sr;
    memcpy(&pr, hdr, 4); memcpy(&ad, hdr + 4, 8); memcpy(&sr, hdr + 12, 4);
    pid_t pid = pr; unsigned int size = sr; int mode = hdr[16];
    if (mode != 0 && mode != 1) { write_all(clifd, "ERR", 3); close(clifd); return; }
    if (size > DATABUF_SZ)      { write_all(clifd, "TOOBIG", 6); close(clifd); return; }
    if (!pid_allowed(pid))      { write_all(clifd, "DENY", 4); close(clifd); return; }
    if (!range_allowed(pid, ad, size, mode)) { write_all(clifd, "DENY", 4); close(clifd); return; }

    static char buf[DATABUF_SZ];
    if (mode) {
        int rem = size; char *dp = buf;
        while (rem > 0) {
            int n = read(clifd, dp, rem);
            if (n <= 0) { write_all(clifd, "ERR", 3); close(clifd); return; }
            rem -= n; dp += n;
        }
        ssize_t r = xfer(pid, ad, buf, size, 1);
        if (r <= 0) { write_all(clifd, "ERR", 3); close(clifd); return; }
        write_all(clifd, "OK", 2);
    } else {
        ssize_t r = xfer(pid, ad, buf, size, 0);
        if (r <= 0) { write_all(clifd, "ERR", 3); close(clifd); return; }
        write_all(clifd, buf, (size_t)r);
    }
    close(clifd);
}

int main(int argc, char **argv)
{
    /* No prctl rename — let the binary name show in ps as-is;
     * renaming from a known path is itself suspicious. */

    int opt;
    while ((opt = getopt(argc, argv, "p:h")) != -1) {
        switch (opt) {
        case 'p': {
            char *e; long v = strtol(optarg, &e, 10);
            if (*e || v <= 0) return 1;
            g_force_pid = (pid_t)v; break;
        }
        case 'h': return 0;
        default:  return 1;
        }
    }
    const char *env = getenv("DEBUGD_SOCK");
    g_sock_path = optind < argc ? argv[optind] : env ? env : default_sock;

    /* Print warning to stderr before daemonizing */
    fprintf(stderr, "WARNING: syscall-mode daemon — every R/W is detectable.\n");
    fprintf(stderr, "         Use /dev/memd kernel module for silent operation.\n");

    signal(SIGCHLD, SIG_IGN);
    pid_t p = fork(); if (p < 0) return 1; if (p > 0) _exit(0);
    setsid();
    p = fork(); if (p < 0) _exit(1); if (p > 0) _exit(0);

    close(0); close(1); close(2);
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }

    unlink(g_sock_path);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) _exit(1);
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, g_sock_path, sizeof(sa.sun_path) - 1);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) _exit(1);
    chmod(g_sock_path, 0666);
    listen(srv, MAX_CLIENTS);

    while (1) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) { if (errno == EINTR) continue; break; }
        pid_t c = fork();
        if (c == 0) { close(srv); handle(cli); _exit(0); }
        close(cli);
    }
    close(srv);
    unlink(g_sock_path);
    return 0;
}
