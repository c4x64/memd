# memd JNI bridge (`Userspace App/native/`)

Thin translation layer between `com.lxgr.dsu.MemdDriver` (Java) and the
driver ioctl surface declared in repo-root `client.h`, which is included
by relative path (`../../client.h`) and never copied. No stealth, no
concealment, no persistence: each entry validates args, fills one
`client.h` struct, issues one `ioctl()` on the caller-supplied fd, and
returns a status int. Expected driver errors are returned, never thrown.

## JNI signatures

Java class: `com.lxgr.dsu.MemdDriver` (all methods `static native`).

| Java signature | JNI symbol | ioctl (`client.h`) | Notes |
|---|---|---|---|
| `int getVersion(int fd, int[] out)` | `Java_com_lxgr_dsu_MemdDriver_getVersion` | `MEMD_IOCTL_VERSION` | `out` len >= 5: major, minor, patch, flags (bit-cast), gen |
| `int getLearnStatus(int fd, int[] out)` | `Java_com_lxgr_dsu_MemdDriver_getLearnStatus` | `MEMD_IOCTL_LEARN_STATUS` | `out` len >= 10: gen, t_pid, t_tgid, t_mm, t_cred, v_start, v_end, v_flags, m_pgd, mask (bit-cast) |
| `int bootstrap(int fd, long filpOpen, long kernelRead, long filpClose)` | `Java_com_lxgr_dsu_MemdDriver_bootstrap` | `MEMD_IOCTL_BOOTSTRAP` | all three addresses must be > 0 |
| `int loadSo(int fd, int pid, String path, String entry, boolean su, boolean ephemeral, long[] outHandle, int[] outEntry)` | `Java_com_lxgr_dsu_MemdDriver_loadSo` | `MEMD_IOCTL_LOAD_SOTOAPP` (`su=false`) / `MEMD_IOCTL_LOAD_SOSUTOAPP` (`su=true`) | `path` absolute, non-empty, < 256 B; `entry` null/empty = dlopen only, else bare symbol (no `/`, < 64 B); `outHandle` len >= 1 required, `outEntry` null = skip |
| `int unloadSo(int fd, int pid, long handle)` | `Java_com_lxgr_dsu_MemdDriver_unloadSo` | `MEMD_IOCTL_LOADSO_UNLOAD` | `pid > 0`, `handle > 0` |

Return codes: `0` ok; `-22` (`EINVAL`: bad fd, null/empty arg, short
array, range); `-36` (`ENAMETOOLONG`: path too long); `-12` (`ENOMEM`:
string fetch OOM, JVM holds pending `OutOfMemoryError`); otherwise
`-errno` from a failed `ioctl()` or the driver-reported `cmd.result`.

Every `GetStringUTFChars` is released on all paths (validated copies are
made into the struct before the ioctl). Output arrays use
`Set*ArrayRegion`, so nothing is pinned.

## Build command used

```sh
NDK="$HOME/Library/Android/sdk/ndk/27.0.11902837"
CC="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang"
"$CC" -c "Userspace App/native/memd_bridge.c" -o memd_bridge.o -fPIC -Wall -Wextra
"$CC" -shared -o libmemd_bridge.so memd_bridge.o   # link attempt
```

## Verified vs needs a device

Verified on macOS host (no device): compile-only build passes with
`-Wall -Wextra` and zero warnings; `-shared` link succeeds; `file`
confirms `ELF 64-bit LSB ... ARM aarch64` for both `.o` and `.so`;
`llvm-nm` confirms all five `Java_com_lxgr_dsu_MemdDriver_*` symbols are
exported (`T`).

Needs an authorized device with the driver installed: runtime behavior
of all five calls (valid fd/ioctl round-trip, `cmd.result` mapping, and
Java-side `UnsatisfiedLinkError`/permission handling), plus the Gradle
`externalNativeBuild` wiring, which does not exist yet in this
directory. Note: NDK `28.2.13676358` in `~/Library/Android/sdk/ndk/` is
an incomplete install (no toolchains); build uses `27.0.11902837`.
