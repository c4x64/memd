// memd.hpp — Zygisk-scheme module SDK for the MEMD injector.
//
// One header, two namespaces, zero link dependencies beyond libc:
//
//   lxgr::    native side: entry ABI, hotswap client, stealth helpers,
//             companion protocol (daemon + payload ends).
//   zygisk::  source-compatible module scheme: Module base, Api
//             (JNI hooks, in-process PLT hooks, companion fd, options),
//             App/ServerSpecialize args, REGISTER_ZYGISK_MODULE.
//
// A module written against zygisk.hpp rebuilds against this header with
// the include swapped (REGISTER_ZYGISK_MODULE is aliased). Differences
// from real Zygisk, by design:
//   - No zygote: our injector loads the .so into an already-running app
//     via remote dlopen, then calls the entry. onLoad + pre/post
//     specialize run back-to-back at entry time with best-effort args
//     harvested from the live process (uid/gid, cmdline, JNIEnv via
//     JNI_GetCreatedJavaVMs when ART is present).
//   - No reboot/zygote restart for updates: hotswap = load new persistent
//     library + run entry + dlclose old handle (MEMD_IOCTL_LOADSO_UNLOAD).
//     The target linker's own dlclose erases maps/solist residue.
//   - OPTION_DLCLOSE_MODULE_LIBRARY is honored as policy: ephemeral
//     loads always dlclose after entry.
//   - onUnload is reserved and never invoked (calling back into a library
//     being unmapped is unsafe); do teardown in the entry before return
//     when running ephemeral.
//   - connectCompanion talks to a module-authored daemon over an abstract
//     socket "@memd-<id>" with an SCM_RIGHTS private channel (protocol
//     below); there is no zygote broker.
//   - getFlags reports PROCESS_GRANTED_ROOT when getuid() == 0 (our su
//     window zeroes uid); denylist state is not visible — always 0.
//
// Stealth contract (what "silent" concretely means here):
//   - Ephemeral + scratch wipe (driver) leave no link_map/maps residue.
//   - lxgr::stealth::lock_down hides the FILE (root-only perms).
//   - Unlink-after-load (loader unlinks the staged file once dlopen
//     succeeds) removes the path; the mapping persists on the inode.
//   - Payloads must not log in release (LXGR_LOG is compiled out unless
//     LXGR_DEBUG), must not leave argv/env markers, and must keep their
//     import surface boring (libc + libdl + liblog only).
// Full /proc/pid/maps content filtering is a driver-side follow-up
// (seq_file show hook), not claimed here.

#ifndef MEMD_HPP
#define MEMD_HPP

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // accept4, abstract unix sockets
#endif

#include "client.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <link.h>
#endif
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

#if __has_include(<jni.h>)
#include <jni.h>
#define LXGR_HAS_JNI 1
#else
// Minimal declarations so this header parses without the NDK (host
// syntax checks, loader-daemon builds). Real NDK builds provide the
// full header and these exact spellings stay compatible.
typedef int jint;
typedef jint jsize;
struct _JNIEnv;
struct _JavaVM;
typedef struct _JNIEnv JNIEnv;
typedef struct _JavaVM JavaVM;
typedef unsigned char jboolean;
struct JNINativeMethod {
    const char *name;
    const char *signature;
    void *fnPtr;
};
#define JNI_OK 0
#define JNI_VERSION_1_6 0x00010006
#endif

#ifndef LXGR_DEBUG
#define LXGR_LOG(...) ((void)0)
#else
#define LXGR_LOG(...) do { fprintf(stderr, "[lxgr] " __VA_ARGS__); fputc('\n', stderr); } while (0)
#endif

#define LXGR_VERSION_MAJOR 1
#define LXGR_VERSION_MINOR 0
#define LXGR_VERSION_PATCH 0
#define LXGR_ENTRY_NAME "lxgr_main"

// The injector calls entry(handle) with the dlopen handle in x0.
typedef int (*lxgr_entry_fn)(uintptr_t dlopen_handle);

namespace lxgr {

// ---- ABI pins: these must match client.h / the driver, or nothing lines up.
static_assert(sizeof(struct memd_bootstrap_cmd) == 32, "bootstrap cmd ABI");
static_assert(sizeof(struct memd_loadso_unload_cmd) == 24, "unload cmd ABI");
static_assert(sizeof(struct memd_loadso_cmd) == 352, "loadso cmd ABI");

// Hotswap from the loader side: load new (persistent) + run entry,
// then unload the old handle. Thin wrapper over client.h.
static inline int hotswap(int fd, pid_t pid, uintptr_t old_handle,
                          const char *path, const char *entry, int su,
                          uintptr_t *out_handle, int *out_entry) {
    return memd_hotswap_so(fd, pid, old_handle, path, entry, su,
                           out_handle, out_entry);
}

namespace stealth {

// Root-only file perms for a staged payload: the app sandbox can see
// the path in its own maps while resident, but cannot open/read the
// file itself. Returns 0 ok / -errno. Loader-side (needs root).
static inline int lock_down(const char *path) {
    if (!path || !path[0]) {
        errno = EINVAL;
        return -EINVAL;
    }
    if (chown(path, 0, 0) < 0)
        return -errno;
    if (chmod(path, S_IRUSR | S_IWUSR | S_IXUSR) < 0)
        return -errno;
    return 0;
}

// Best-effort unlink of the staged file (call AFTER dlopen succeeds:
// the mapping survives on the open inode, the path disappears).
static inline int unlink_staged(const char *path) {
    if (!path || !path[0]) {
        errno = EINVAL;
        return -EINVAL;
    }
    if (unlink(path) < 0)
        return -errno;
    return 0;
}

} // namespace stealth

namespace companion {

// Wire protocol (abstract unix socket "@memd-<module-id>"):
//   payload -> daemon:  "MEMD1 <module-id>\n"
//   daemon  -> payload: "OK\n" then one SCM_RIGHTS message carrying the
//                       private channel fd; payload speaks only there.
static const char kHelloPrefix[] = "MEMD1 ";
static const char kHelloOk[] = "OK\n";

static inline int socket_path(char *out, size_t cap, const char *module_id) {
    int n = snprintf(out, cap, "@memd-%s", module_id ? module_id : "?");
    if (n <= 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static inline int send_fd(int sock, int fd_to_send) {
    struct msghdr msg;
    struct iovec iov;
    char dummy = 0;
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &dummy;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
    return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

static inline int recv_fd(int sock) {
    struct msghdr msg;
    struct iovec iov;
    char dummy = 0;
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &dummy;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    if (recvmsg(sock, &msg, 0) != 1)
        return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len < CMSG_LEN(sizeof(int)))
        return -1;
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

// Payload side: connect, say hello, get the private channel fd.
// Abstract unix sockets are Linux-only; elsewhere this fails closed.
static inline int connect(const char *module_id) {
#if !defined(__linux__) && !defined(__ANDROID__)
    (void)module_id;
    return -1;
#else
    char path[108];
    char hello[160];
    char reply[8];
    if (!module_id || !module_id[0] || socket_path(path, sizeof(path), module_id))
        return -1;
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0)
        return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    size_t namelen = strlen(path + 1) + 1;
    if (namelen + 1 > sizeof(addr.sun_path)) {
        close(sock);
        return -1;
    }
    memcpy(addr.sun_path + 1, path + 1, namelen);
    socklen_t addrlen = (socklen_t)(sizeof(sa_family_t) + 1 + namelen);
    if (::connect(sock, (struct sockaddr *)&addr, addrlen) < 0) {
        close(sock);
        return -1;
    }
    int n = snprintf(hello, sizeof(hello), "%s%s\n", kHelloPrefix, module_id);
    if (n <= 0 || (size_t)n >= sizeof(hello) ||
        write(sock, hello, (size_t)n) != (ssize_t)n) {
        close(sock);
        return -1;
    }
    ssize_t r = read(sock, reply, sizeof(reply) - 1);
    if (r <= 0) {
        close(sock);
        return -1;
    }
    reply[r] = '\0';
    if (strcmp(reply, kHelloOk) != 0) {
        close(sock);
        return -1;
    }
    int channel = recv_fd(sock);
    close(sock);
    return channel;
#endif
}

// Daemon side: serve one module id; handler(fd, ctx) returns nonzero to
// stop serving. Single-threaded; fork/thread around serve() for more.
typedef int (*client_handler_fn)(int channel_fd, void *ctx);

static inline int serve(const char *module_id, client_handler_fn handler, void *ctx) {
#if !defined(__linux__) && !defined(__ANDROID__)
    (void)module_id;
    (void)handler;
    (void)ctx;
    return -1;
#else
    char path[108];
    if (!module_id || !module_id[0] || !handler || socket_path(path, sizeof(path), module_id))
        return -1;
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0)
        return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    size_t namelen = strlen(path + 1) + 1;
    if (namelen + 1 > sizeof(addr.sun_path)) {
        close(listener);
        return -1;
    }
    memcpy(addr.sun_path + 1, path + 1, namelen);
    socklen_t addrlen = (socklen_t)(sizeof(sa_family_t) + 1 + namelen);
    if (::bind(listener, (struct sockaddr *)&addr, addrlen) < 0 || ::listen(listener, 8) < 0) {
        close(listener);
        return -1;
    }
    char want[160];
    int wn = snprintf(want, sizeof(want), "%s%s\n", kHelloPrefix, module_id);
    if (wn <= 0 || (size_t)wn >= sizeof(want)) {
        close(listener);
        return -1;
    }
    for (;;) {
        int client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        // Stream sockets may split the short hello across reads;
        // accumulate until the newline, EOF, or a full buffer.
        char line[160];
        size_t used = 0;
        for (;;) {
            if (used >= sizeof(line) - 1)
                break;
            ssize_t r = read(client, line + used, sizeof(line) - 1 - used);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (r == 0)
                break;
            used += (size_t)r;
            if (memchr(line, '\n', used))
                break;
        }
        bool ok = used > 0;
        if (ok) {
            line[used] = '\0';
            ok = strcmp(line, want) == 0;
        }
        if (ok)
            ok = write(client, kHelloOk, strlen(kHelloOk)) == (ssize_t)strlen(kHelloOk);
        int channel = -1, peer = -1;
        if (ok) {
            int pair[2] = {-1, -1};
            if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0) {
                channel = pair[0];
                peer = pair[1];
                ok = send_fd(client, peer) == 0;
                close(peer);
            } else {
                ok = false;
            }
        }
        close(client);
        if (!ok) {
            if (channel >= 0)
                close(channel);
            continue;
        }
        int stop = handler(channel, ctx);
        close(channel);
        if (stop)
            break;
    }
    close(listener);
    return 0;
#endif
}

} // namespace companion

namespace detail {

// Module registry: REGISTER_* macros install a factory; our entry boots it.
class IModule {
  public:
    virtual ~IModule() {}
};

using ModuleFactory = IModule *(*)();

static inline ModuleFactory &factory_slot() {
    static ModuleFactory factory = nullptr;
    return factory;
}

struct ModuleFactorySetter {
    explicit ModuleFactorySetter(ModuleFactory factory) { factory_slot() = factory; }
};

// Anchor address for getModuleDir (lives in the module's own .so).
static inline void module_anchor() {}

// Directory containing this .so (dladdr on our own symbol). Linux only;
// payloads only execute on Linux/Android.
static inline bool module_dir(char *out, size_t cap) {
#if defined(__linux__) || defined(__ANDROID__)
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (!dladdr((void *)&module_anchor, &info) || !info.dli_fname)
        return false;
    size_t n = strlen(info.dli_fname);
    if (n + 1 > cap)
        return false;
    memcpy(out, info.dli_fname, n + 1);
    char *slash = strrchr(out, '/');
    if (slash)
        *slash = '\0';
    else {
        out[0] = '.';
        out[1] = '\0';
    }
    return true;
#else
    (void)out;
    (void)cap;
    return false;
#endif
}

// Module id = staged directory basename (loader stages
// <dir>/<id>/payload.so; see tools/lxgr_load.py).
static inline bool module_id(char *out, size_t cap) {
    char dir[512];
    if (!module_dir(dir, sizeof(dir)))
        return false;
    const char *base = strrchr(dir, '/');
    base = base ? base + 1 : dir;
    size_t n = strlen(base);
    if (!n || n + 1 > cap)
        return false;
    memcpy(out, base, n + 1);
    return true;
}

} // namespace detail
} // namespace lxgr

// =====================================================================
// zygisk:: — source-compatible module scheme.
// =====================================================================

namespace zygisk {

static const uint32_t OPTION_DLCLOSE_MODULE_LIBRARY = 0x1;
static const int PROCESS_GRANTED_ROOT = (1 << 0);
static const int PROCESS_ON_DENYLIST = (1 << 1);

struct AppSpecializeArgs {
    uid_t uid = 0;
    gid_t gid = 0;
    std::vector<gid_t> groups;
    uint32_t runtime_flags = 0;
    std::string package_name;
    std::string nice_name;
    std::string se_info;
    bool is_child_zygote = false;
};

struct ServerSpecializeArgs {
    uid_t uid = 0;
    gid_t gid = 0;
    std::string process_name;
};

class Api {
  public:
    virtual ~Api() {}
    virtual bool hookJniNativeMethods(JNIEnv *env, const char *className,
                                      const JNINativeMethod *methods, int numMethods) = 0;
    virtual bool pltHookRegister(const char *regex, const char *symbol, void *newFunc,
                                 void **oldFunc) = 0;
    virtual bool pltHookExclude(const char *regex, const char *symbol) = 0;
    virtual bool pltHookCommit() = 0;
    virtual int connectCompanion() = 0;
    virtual void setOption(int option) = 0;
    virtual std::string getModuleDir() = 0;
    virtual int getFlags() = 0;
};

class Module : public lxgr::detail::IModule {
  public:
    ~Module() override {}
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(ServerSpecializeArgs *args) {}
    // MEMD extension: reserved, never invoked (see header top).
    virtual void onUnload() {}
};

namespace detail {

// ---- in-process PLT hooking (Linux/Android only; no driver needed) ----
struct PltRule {
    std::string lib_re;
    std::string sym;
    void *replacement = nullptr;
    void **out_old = nullptr;
    bool exclude = false;
    regex_t compiled;
    bool compiled_ok = false;
};

struct PltHookState {
    std::vector<PltRule> rules;
};

static inline PltHookState &plt_state() {
    static PltHookState state;
    return state;
}

#if defined(__aarch64__)
static const uint32_t kJumpSlotType = 1026; // R_AARCH64_JUMP_SLOT
#elif defined(__x86_64__)
static const uint32_t kJumpSlotType = 7; // R_X86_64_JUMP_SLOT
#elif defined(__i386__)
static const uint32_t kJumpSlotType = 22; // R_386_JUMP_SLOT
#else
static const uint32_t kJumpSlotType = 0; // unsupported here
#endif

static inline bool rule_applies(const PltRule &rule, const char *lib, const char *sym) {
    if (!rule.compiled_ok)
        return false;
    if (regexec(&rule.compiled, lib && lib[0] ? lib : "", 0, nullptr, 0) != 0)
        return false;
    if (!rule.sym.empty() && rule.sym != sym)
        return false;
    return true;
}

static inline bool rule_excluded(const char *lib, const char *sym) {
    for (const auto &rule : plt_state().rules) {
        if (rule.exclude && rule_applies(rule, lib, sym))
            return true;
    }
    return false;
}

// GOT slots are mprotect'd per patched entry: use the running kernel's
// page size (arm64 allows 4K/16K/64K), never a hardcoded 4K, or the
// mprotect fails with EINVAL on large-page devices and hooks misfire.
static inline long plt_pagesize() {
    long ps = sysconf(_SC_PAGESIZE);
    return ps > 0 ? ps : 4096;
}

#if defined(__linux__) || defined(__ANDROID__)
static inline int patch_one_plt(struct dl_phdr_info *info, const PltRule &rule) {
    const ElfW(Phdr) *dynamic = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynamic = &info->dlpi_phdr[i];
            break;
        }
    }
    if (!dynamic)
        return 0;
    uintptr_t bias = (uintptr_t)info->dlpi_addr;
    const ElfW(Dyn) *dyn = (const ElfW(Dyn) *)(bias + dynamic->p_vaddr);
    uintptr_t jmprel = 0, pltrelsz = 0;
    uintptr_t symtab = 0, strtab = 0, syment = 0;
    bool rela = true;
    bool saw_pltrel = false;
    int tags = 0;
    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        // Corrupt PT_DYNAMIC without DT_NULL must not walk off the map.
        if (++tags > 64)
            return 0;
        switch (d->d_tag) {
        case DT_JMPREL:
            jmprel = (uintptr_t)d->d_un.d_ptr + bias;
            break;
        case DT_PLTRELSZ:
            pltrelsz = (uintptr_t)d->d_un.d_val;
            break;
        case DT_PLTREL:
            rela = d->d_un.d_val == DT_RELA;
            saw_pltrel = true;
            break;
        case DT_SYMTAB:
            symtab = (uintptr_t)d->d_un.d_ptr + bias;
            break;
        case DT_STRTAB:
            strtab = (uintptr_t)d->d_un.d_ptr + bias;
            break;
        case DT_SYMENT:
            syment = (uintptr_t)d->d_un.d_val;
            break;
        default:
            break;
        }
    }
    if (!jmprel || !pltrelsz || !symtab || !strtab || !syment)
        return 0;
    if (!saw_pltrel) {
        // DT_PLTREL is mandatory in practice; without it assume the
        // native relocation flavor rather than guessing wrong.
        rela = sizeof(void *) == 8;
    }
    int patched = 0;
    if (rela) {
        size_t count = pltrelsz / sizeof(ElfW(Rela));
        for (size_t i = 0; i < count; i++) {
            const ElfW(Rela) *rel = (const ElfW(Rela) *)(jmprel + i * sizeof(ElfW(Rela)));
            if (ELF64_R_TYPE(rel->r_info) != kJumpSlotType)
                continue;
            size_t symidx = (size_t)ELF64_R_SYM(rel->r_info);
            const char *name = (const char *)(strtab +
                *(const uint32_t *)(symtab + symidx * syment));
            if (strcmp(name, rule.sym.c_str()) != 0)
                continue;
            uintptr_t target = (uintptr_t)rel->r_offset + bias;
            long psize = plt_pagesize();
            uintptr_t page = target & ~((uintptr_t)psize - 1);
            if (mprotect((void *)page, (size_t)psize, PROT_READ | PROT_WRITE) != 0)
                continue;
            if (rule.out_old)
                *rule.out_old = *(void *const *)target;
            *(void **)target = rule.replacement;
            __builtin___clear_cache((char *)page, (char *)page + psize);
            mprotect((void *)page, (size_t)psize, PROT_READ);
            patched++;
        }
    } else {
        size_t count = pltrelsz / sizeof(ElfW(Rel));
        for (size_t i = 0; i < count; i++) {
            const ElfW(Rel) *rel = (const ElfW(Rel) *)(jmprel + i * sizeof(ElfW(Rel)));
            if (ELF32_R_TYPE(rel->r_info) != kJumpSlotType)
                continue;
            size_t symidx = (size_t)ELF32_R_SYM(rel->r_info);
            const char *name = (const char *)(strtab +
                *(const uint32_t *)(symtab + symidx * syment));
            if (strcmp(name, rule.sym.c_str()) != 0)
                continue;
            uintptr_t target = (uintptr_t)rel->r_offset + bias;
            long psize = plt_pagesize();
            uintptr_t page = target & ~((uintptr_t)psize - 1);
            if (mprotect((void *)page, (size_t)psize, PROT_READ | PROT_WRITE) != 0)
                continue;
            if (rule.out_old)
                *rule.out_old = *(void *const *)target;
            *(void **)target = rule.replacement;
            mprotect((void *)page, (size_t)psize, PROT_READ);
            patched++;
        }
    }
    return patched;
}

static inline int plt_iterate(struct dl_phdr_info *info, size_t, void *data) {
    int *total = (int *)data;
    const char *lib = info->dlpi_name && info->dlpi_name[0] ? info->dlpi_name : "";
    for (const auto &rule : plt_state().rules) {
        if (rule.exclude || !rule.replacement || rule.sym.empty())
            continue;
        if (!rule_applies(rule, lib, rule.sym.c_str()))
            continue;
        if (rule_excluded(lib, rule.sym.c_str()))
            continue;
        *total += patch_one_plt(info, rule);
    }
    return 0;
}
#endif // __linux__ || __ANDROID__

// Resolve JNIEnv from ART when present (running app with a VM).
static inline JNIEnv *resolve_env() {
#ifdef LXGR_HAS_JNI
    JavaVM *vms[4] = {nullptr, nullptr, nullptr, nullptr};
    jsize count = 0;
    if (JNI_GetCreatedJavaVMs(vms, 4, &count) != JNI_OK || count <= 0 || !vms[0])
        return nullptr;
    JNIEnv *env = nullptr;
    if (vms[0]->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return nullptr;
    return env;
#else
    return nullptr;
#endif
}

// Fill specialize args from the live process (best-effort provenance;
// fields we cannot know stay zero/empty — see header top).
static inline void fill_app_args(AppSpecializeArgs *args) {
    if (!args)
        return;
    args->uid = getuid();
    args->gid = getgid();
    args->groups.push_back(args->gid);
    char cmd[256] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (n > 0) {
            cmd[n] = '\0';
            const char *base = strrchr(cmd, '/');
            args->package_name = base ? base + 1 : cmd;
            args->nice_name = args->package_name;
        }
    }
    args->is_child_zygote = false;
}

class ApiImpl : public Api {
  public:
    explicit ApiImpl(std::string module_id) : module_id_(module_id), options_(0) {}

    bool hookJniNativeMethods(JNIEnv *env, const char *className,
                              const JNINativeMethod *methods, int numMethods) override {
#ifdef LXGR_HAS_JNI
        if (!env || !className || !methods || numMethods <= 0)
            return false;
        jclass clazz = env->FindClass(className);
        if (!clazz)
            return false;
        bool ok = env->RegisterNatives(clazz, methods, numMethods) == 0;
        env->DeleteLocalRef(clazz);
        return ok;
#else
        (void)env;
        (void)className;
        (void)methods;
        (void)numMethods;
        return false;
#endif
    }

    bool pltHookRegister(const char *regex, const char *symbol, void *newFunc,
                         void **oldFunc) override {
        if (!regex || !symbol || !newFunc)
            return false;
        PltRule rule;
        rule.lib_re = regex;
        rule.sym = symbol;
        rule.replacement = newFunc;
        rule.out_old = oldFunc;
        rule.exclude = false;
        if (regcomp(&rule.compiled, regex, REG_EXTENDED | REG_NOSUB) != 0)
            return false;
        rule.compiled_ok = true;
        plt_state().rules.push_back(rule);
        return true;
    }

    bool pltHookExclude(const char *regex, const char *symbol) override {
        if (!regex)
            return false;
        PltRule rule;
        rule.lib_re = regex;
        rule.sym = symbol ? symbol : "";
        rule.exclude = true;
        if (regcomp(&rule.compiled, regex, REG_EXTENDED | REG_NOSUB) != 0)
            return false;
        rule.compiled_ok = true;
        plt_state().rules.push_back(rule);
        return true;
    }

    bool pltHookCommit() override {
#if defined(__linux__) || defined(__ANDROID__)
        if (kJumpSlotType == 0)
            return false;
        int total = 0;
        dl_iterate_phdr(plt_iterate, &total);
        return total > 0;
#else
        return false;
#endif
    }

    int connectCompanion() override {
        return lxgr::companion::connect(module_id_.c_str());
    }

    void setOption(int option) override { options_ |= option; }

    std::string getModuleDir() override {
        char dir[512];
        if (lxgr::detail::module_dir(dir, sizeof(dir)))
            return std::string(dir);
        return std::string();
    }

    int getFlags() override {
        // Approximation: our su window zeroes uid, so root here means
        // the payload was installed privileged.
        return getuid() == 0 ? PROCESS_GRANTED_ROOT : 0;
    }

  private:
    std::string module_id_;
    int options_;
};

// Boot a registered module: onLoad, then app/server specialize back to
// back (our injection point IS a live, specialized process). The
// instance intentionally leaks: its code must outlive this call.
static inline int boot_module(uintptr_t /*dlopen_handle*/) {
    lxgr::detail::ModuleFactory factory = lxgr::detail::factory_slot();
    if (!factory)
        return -ENODEV;
    lxgr::detail::IModule *raw = factory();
    if (!raw)
        return -ENOMEM;
    Module *module = static_cast<Module *>(raw);
    char id[128] = {0};
    if (!lxgr::detail::module_id(id, sizeof(id))) {
        id[0] = '?';
        id[1] = '\0';
    }
    ApiImpl api(id);
    JNIEnv *env = resolve_env();
    module->onLoad(&api, env);
    char procname[128] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, procname, sizeof(procname) - 1);
        close(fd);
        if (n <= 0)
            procname[0] = '\0';
        else
            procname[(size_t)n] = '\0';
    }
    bool server = strstr(procname, "zygote") != nullptr ||
                  strstr(procname, "system_server") != nullptr;
    if (server) {
        ServerSpecializeArgs args;
        args.uid = getuid();
        args.gid = getgid();
        args.process_name = procname;
        module->preServerSpecialize(&args);
        module->postServerSpecialize(&args);
    } else {
        AppSpecializeArgs args;
        fill_app_args(&args);
        module->preAppSpecialize(&args);
        module->postAppSpecialize(&args);
    }
    static Module *resident = nullptr;
    resident = module;
    (void)resident;
    return 0;
}

} // namespace detail
} // namespace zygisk

#define REGISTER_MEMD_MODULE(cls)                                              \
    static ::lxgr::detail::ModuleFactorySetter _lxgr_module_factory_##cls{   \
        +[]() -> ::lxgr::detail::IModule * { return new cls(); } };
// Source compatibility with zygisk.hpp-based modules.
#define REGISTER_ZYGISK_MODULE(cls) REGISTER_MEMD_MODULE(cls)

// Our injector calls this symbol with the dlopen handle in x0.
// Single-TU only: one definition per module (inline keeps multi-TU
// payloads linking; REGISTER_* must still appear exactly once, in the
// same TU as the factory it registers).
extern "C" inline int lxgr_main(uintptr_t dlopen_handle) {
    return zygisk::detail::boot_module(dlopen_handle);
}

#endif // MEMD_HPP
