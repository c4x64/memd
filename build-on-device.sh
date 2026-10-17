#!/bin/sh
# build-on-device.sh — multi-backend on-device build for rwbridge.
#
# Backends (auto-selected by availability, best first):
#   1) standard   — full kernel headers package (include/linux/module.h)
#   2) btf        — BTF + generated vmlinux.h (needs bpftool + /sys/kernel/btf/vmlinux)
#   3) kbuild     — kbuild tree only (/lib/modules/$(uname -r)/build)
#   4) proot      — proot/Termux cross-compile fallback
#
# CPU throttling is always applied (nice -n 19, jobs = nproc/2 capped).
# POSIX sh compatible: validated with `sh -n`.

set -eu

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_VERSION="2.0.0"
MODNAME="rwbridge"
NICE_LEVEL=19
DEFAULT_JOBS_CAP=4
MIN_JOBS=1
MAX_JOBS=8

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
BACKEND_REQUESTED="auto"
BACKEND=""
KVER=""
KVER_OVERRIDE=""
KDIR=""
KDIR_OVERRIDE=""
SRC_ROOT=""
MOD_SRC_DIR=""
CC=""
CC_OVERRIDE=""
JOBS_OVERRIDE=""
JOBS=""
CPU_COUNT=""
DRY_RUN=0
DKMS_MODE=0
INSTALL_MODE=0
FORCE=0
VERBOSE=0
LIST_BACKENDS=0
DIAGNOSE=0
TRY_ALL=0
SELF_TEST=0

# Backend-specific globals
STANDARD_KDIR=""
KBUILD_KDIR=""
BTF_SOURCE="/sys/kernel/btf/vmlinux"
BTF_OUTPUT=""
CROSS_COMPILE=""
TARGET_ARCH=""
TARGET_TRIPLE=""
AVAILABLE_BACKENDS=""
BUILD_REPORT=""
ANDROID=0
TERMUX=0
PROOT=0
LINUX=0
OS_NAME="unknown"
OS_ARCH="unknown"
CLEAN_FIRST=1
STAGE_SYMVERS=1
VERIFY_ARTIFACT=1
INSTALL_DEST=""
MODULE_FILE="${MODNAME}.ko"

# Temporary tracking
TMP_FILES=""
WORK_STARTED=0

# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

is_dir() { [ -d "$1" ]; }
is_file() { [ -f "$1" ]; }
is_readable() { [ -r "$1" ]; }
is_executable() { [ -x "$1" ]; }
is_nonempty() { [ -s "$1" ]; }

ts_now() { date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || echo "unknown-time"; }

log_info() { printf '[%s] [INFO] %s\n' "$(ts_now)" "$*"; }
log_warn() { printf '[%s] [WARN] %s\n' "$(ts_now)" "$*" >&2; }
log_error() { printf '[%s] [ERROR] %s\n' "$(ts_now)" "$*" >&2; }
log_step() { printf '\n==================== %s ====================\n' "$*"; }
log_debug() { if [ "$VERBOSE" -eq 1 ]; then printf '[%s] [DEBUG] %s\n' "$(ts_now)" "$*"; fi; }

die() { log_error "$*"; exit 1; }

warn() { log_warn "$*"; }

ensure_dir() {
    _ed_path="$1"
    if [ ! -d "$_ed_path" ]; then
        mkdir -p "$_ed_path" 2>/dev/null || die "cannot create directory: $_ed_path"
    fi
}

safe_copy() {
    _sc_src="$1"
    _sc_dst="$2"
    if [ ! -f "$_sc_src" ]; then
        log_warn "source missing, skip copy: $_sc_src"
        return 1
    fi
    cp -f "$_sc_src" "$_sc_dst" 2>/dev/null || { log_warn "copy failed: $_sc_src -> $_sc_dst"; return 1; }
    return 0
}

safe_rm() {
    for _sr_item in "$@"; do
        if [ -e "$_sr_item" ] || [ -L "$_sr_item" ]; then
            rm -rf "$_sr_item" 2>/dev/null || log_warn "remove failed: $_sr_item"
        fi
    done
}

register_tmp() {
    TMP_FILES="${TMP_FILES} $1"
}

cleanup() {
    _cu_status=$?
    if [ -n "$TMP_FILES" ]; then
        for _cu_f in $TMP_FILES; do
            if [ -e "$_cu_f" ] || [ -L "$_cu_f" ]; then
                rm -rf "$_cu_f" 2>/dev/null || true
            fi
        done
    fi
    if [ "$_cu_status" -ne 0 ]; then
        log_error "build-on-device exited with status $_cu_status"
    fi
    exit "$_cu_status"
}
trap cleanup EXIT HUP INT TERM

# ---------------------------------------------------------------------------
# Usage / help
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: build-on-device.sh [options]

Multi-backend on-device builder for rwbridge.

Options:
  --backend NAME      Force backend: auto|standard|btf|kbuild|proot|termux
  --auto              Auto-select best available backend (default)
                      (default: auto)
  --kver VERSION      Override kernel version (default: uname -r)
  --kdir PATH         Override kernel build directory
  --src PATH          Source root (default: script directory)
  --jobs N            Override parallel job count
  --cc COMPILER       Override C compiler
  --dry-run           Print commands without executing
  --dkms              DKMS mode (honors kernelver env)
  --install           Install built module after success
  --force             Force regeneration of generated files
  --verbose           Verbose output
  --list-backends     List backends and availability, then exit
  --diagnose          Print environment diagnostics, then exit
  --self-test         Run internal self-tests, then exit
  --try-all           Try all available backends until one succeeds
  -h, --help          Show this help
  --version           Show version

Backends:
  standard  Full kernel headers (include/linux/module.h present).
  btf       BTF + vmlinux.h via bpftool (kernel 5.10+ typical).
  kbuild    Kbuild tree only (/lib/modules/$(uname -r)/build).
  proot     proot/Termux cross-compile fallback.

CPU throttling:
  Builds run under nice -n 19 with jobs = nproc/2 (capped).
EOF
}

show_version() {
    printf 'build-on-device.sh %s\n' "$SCRIPT_VERSION"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            --version) show_version; exit 0 ;;
            --backend)
                [ $# -ge 2 ] || die "--backend requires a value"
                BACKEND_REQUESTED="$2"; shift 2 ;;
            --auto) BACKEND_REQUESTED="auto"; shift ;;
            --backend=*)
                BACKEND_REQUESTED="${1#*=}"; shift ;;
            --kver)
                [ $# -ge 2 ] || die "--kver requires a value"
                KVER_OVERRIDE="$2"; shift 2 ;;
            --kver=*)
                KVER_OVERRIDE="${1#*=}"; shift ;;
            --kdir)
                [ $# -ge 2 ] || die "--kdir requires a value"
                KDIR_OVERRIDE="$2"; shift 2 ;;
            --kdir=*)
                KDIR_OVERRIDE="${1#*=}"; shift ;;
            --src)
                [ $# -ge 2 ] || die "--src requires a value"
                SRC_ROOT="$2"; shift 2 ;;
            --src=*)
                SRC_ROOT="${1#*=}"; shift ;;
            --jobs)
                [ $# -ge 2 ] || die "--jobs requires a value"
                JOBS_OVERRIDE="$2"; shift 2 ;;
            --jobs=*)
                JOBS_OVERRIDE="${1#*=}"; shift ;;
            --cc)
                [ $# -ge 2 ] || die "--cc requires a value"
                CC_OVERRIDE="$2"; shift 2 ;;
            --cc=*)
                CC_OVERRIDE="${1#*=}"; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            --dkms) DKMS_MODE=1; shift ;;
            --install) INSTALL_MODE=1; shift ;;
            --force) FORCE=1; shift ;;
            --verbose) VERBOSE=1; shift ;;
            --list-backends) LIST_BACKENDS=1; shift ;;
            --diagnose) DIAGNOSE=1; shift ;;
            --self-test) SELF_TEST=1; shift ;;
            --try-all) TRY_ALL=1; shift ;;
            --no-clean) CLEAN_FIRST=0; shift ;;
            --no-verify) VERIFY_ARTIFACT=0; shift ;;
            *)
                die "unknown argument: $1 (use --help)" ;;
        esac
    done

    # Validate backend request
    case "$BACKEND_REQUESTED" in
        auto|standard|btf|kbuild|proot|termux) : ;;
        *) die "invalid backend: $BACKEND_REQUESTED" ;;
    esac

    # Validate jobs override if given
    if [ -n "$JOBS_OVERRIDE" ]; then
        case "$JOBS_OVERRIDE" in
            ''|*[!0-9]*) die "invalid --jobs value: $JOBS_OVERRIDE" ;;
        esac
        if [ "$JOBS_OVERRIDE" -lt 1 ] || [ "$JOBS_OVERRIDE" -gt "$MAX_JOBS" ]; then
            die "jobs must be between 1 and $MAX_JOBS"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
detect_kernel_version() {
    if [ -n "$KVER_OVERRIDE" ]; then
        KVER="$KVER_OVERRIDE"
    elif [ -n "${kernelver:-}" ] && [ "$DKMS_MODE" -eq 1 ]; then
        KVER="$kernelver"
    else
        KVER="$(uname -r 2>/dev/null || true)"
    fi
    if [ -z "$KVER" ]; then
        die "cannot determine kernel version"
    fi
    log_debug "kernel version: $KVER"
}

detect_environment() {
    OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
    OS_ARCH="$(uname -m 2>/dev/null || echo unknown)"
    ANDROID=0
    TERMUX=0
    PROOT=0
    LINUX=0
    case "$OS_NAME" in
        Linux) LINUX=1 ;;
    esac
    if [ -d /system ] && { [ -f /system/build.prop ] || [ -d /system/lib ]; }; then
        ANDROID=1
    fi
    if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ] && [ -d "${PREFIX}/lib" ]; then
        TERMUX=1
    fi
    if [ -n "${PROOT_TMP_DIR:-}" ] || [ -n "${PROOT_LOADER:-}" ] || [ -n "${PROOT_NO_SECCOMP:-}" ]; then
        PROOT=1
    fi
    if [ -d /data/data/com.termux ]; then
        TERMUX=1
    fi
    # proot often runs inside termux
    if [ "$TERMUX" -eq 1 ] && [ -n "${PROOT_TMP_DIR:-}" ]; then
        PROOT=1
    fi
    log_debug "OS=$OS_NAME ARCH=$OS_ARCH ANDROID=$ANDROID TERMUX=$TERMUX PROOT=$PROOT"
}

detect_cpu_count() {
    _dcc_result=1
    if have nproc; then
        _dcc_result="$(nproc 2>/dev/null || echo 1)"
    elif [ -r /proc/cpuinfo ]; then
        _dcc_result="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
    elif have getconf; then
        _dcc_result="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
    fi
    case "$_dcc_result" in
        ''|*[!0-9]*) _dcc_result=1 ;;
    esac
    if [ "$_dcc_result" -lt 1 ]; then
        _dcc_result=1
    fi
    CPU_COUNT="$_dcc_result"
    echo "$_dcc_result"
}

compute_jobs() {
    _cj_n="$1"
    _cj_j=$(( _cj_n / 2 ))
    if [ "$_cj_j" -lt "$MIN_JOBS" ]; then
        _cj_j="$MIN_JOBS"
    fi
    if [ "$_cj_j" -gt "$DEFAULT_JOBS_CAP" ]; then
        _cj_j="$DEFAULT_JOBS_CAP"
    fi
    if [ -n "$JOBS_OVERRIDE" ]; then
        _cj_j="$JOBS_OVERRIDE"
    fi
    if [ "$_cj_j" -lt 1 ]; then
        _cj_j=1
    fi
    if [ "$_cj_j" -gt "$MAX_JOBS" ]; then
        _cj_j="$MAX_JOBS"
    fi
    JOBS="$_cj_j"
    echo "$_cj_j"
}

apply_throttle_env() {
    # Throttle environment: nice is applied at invocation; job count is passed
    # to make explicitly. Do not duplicate -j in MAKEFLAGS (avoids jobserver
    # warnings in recursive kbuild).
    log_debug "throttle env applied: nice=$NICE_LEVEL jobs=$JOBS"
}

# ---------------------------------------------------------------------------
# Toolchain detection
# ---------------------------------------------------------------------------
detect_toolchain() {
    CC=""
    if [ -n "$CC_OVERRIDE" ]; then
        CC="$CC_OVERRIDE"
        if ! have "$CC"; then
            # allow path-based compiler
            if [ ! -x "$CC" ]; then
                die "compiler not found: $CC"
            fi
        fi
        log_debug "using overridden CC: $CC"
        return 0
    fi

    if [ "$TERMUX" -eq 1 ] || [ "$PROOT" -eq 1 ] || [ "$ANDROID" -eq 1 ]; then
        for cand in \
            aarch64-linux-android-clang \
            aarch64-linux-android-gcc \
            arm-linux-androideabi-clang \
            arm-linux-androideabi-gcc \
            clang \
            gcc \
            cc; do
            if have "$cand"; then CC="$cand"; break; fi
        done
    else
        for cand in gcc clang cc tcc; do
            if have "$cand"; then CC="$cand"; break; fi
        done
    fi

    if [ -z "$CC" ]; then
        die "no C compiler found (install gcc/clang or Termux toolchain)"
    fi

    if have ccache; then
        CC="ccache $CC"
        log_debug "ccache enabled"
    fi
    log_info "selected compiler: $CC"
}

validate_toolchain() {
    detect_toolchain
    # Probe compiler
    _vt_tmp="/tmp/bod-cc-probe-$$"
    register_tmp "$_vt_tmp"
    if ! printf 'int main(void){return 0;}\n' > "$_vt_tmp.c" 2>/dev/null; then
        die "cannot write compiler probe"
    fi
    if ! $CC -c "$_vt_tmp.c" -o "$_vt_tmp.o" >/dev/null 2>&1; then
        log_warn "compiler probe failed; continuing anyway"
    else
        log_debug "compiler probe OK"
    fi
    safe_rm "$_vt_tmp.c" "$_vt_tmp.o"
}

# ---------------------------------------------------------------------------
# Kernel directory resolution
# ---------------------------------------------------------------------------
resolve_src_root() {
    if [ -z "$SRC_ROOT" ]; then
        # script directory
        _rsd=$(dirname "$0")
        SRC_ROOT=$(CDPATH= cd "$_rsd" && pwd)
    fi
    if [ ! -d "$SRC_ROOT" ]; then
        die "source root not a directory: $SRC_ROOT"
    fi
    if [ -d "$SRC_ROOT/kmod" ]; then
        MOD_SRC_DIR="$SRC_ROOT/kmod"
    else
        MOD_SRC_DIR="$SRC_ROOT"
    fi
    log_debug "source root: $SRC_ROOT"
    log_debug "module source dir: $MOD_SRC_DIR"
}

find_standard_kdir() {
    STANDARD_KDIR=""
    for cand in \
        "/lib/modules/${KVER}/build" \
        "/usr/src/linux-headers-${KVER}" \
        "/usr/src/kernels/${KVER}" \
        "/usr/lib/modules/${KVER}/build" \
        "/lib/modules/${KVER}/source" \
        "/data/local/tmp/linux-headers-${KVER}" \
        "/sdcard/linux-headers-${KVER}" \
        "${PREFIX:-}/lib/modules/${KVER}/build" \
        "/system/lib/modules/${KVER}/build" \
        "/opt/linux-headers-${KVER}"; do
        if [ -d "$cand" ] && [ -f "$cand/Makefile" ]; then
            if [ -f "$cand/include/linux/module.h" ] || [ -f "$cand/include/linux/init.h" ]; then
                STANDARD_KDIR="$cand"
                log_debug "standard kdir candidate OK: $cand"
                return 0
            fi
        fi
    done
    log_debug "no standard kdir found"
    return 1
}

find_kbuild_kdir() {
    KBUILD_KDIR=""
    for cand in \
        "/lib/modules/${KVER}/build" \
        "/usr/src/linux-${KVER}" \
        "/usr/src/linux" \
        "/data/local/tmp/linux-${KVER}" \
        "/data/local/tmp/linux-build-${KVER}" \
        "${PREFIX:-}/lib/modules/${KVER}/build" \
        "/system/lib/modules/${KVER}/build" \
        "/opt/linux-build-${KVER}"; do
        if [ -d "$cand" ] && [ -f "$cand/Makefile" ]; then
            KBUILD_KDIR="$cand"
            log_debug "kbuild kdir candidate OK: $cand"
            return 0
        fi
    done
    log_debug "no kbuild kdir found"
    return 1
}

validate_kdir() {
    if [ -z "$KDIR" ]; then
        die "KDIR is empty"
    fi
    if [ ! -d "$KDIR" ]; then
        die "KDIR not a directory: $KDIR"
    fi
    if [ ! -f "$KDIR/Makefile" ]; then
        die "KDIR missing Makefile: $KDIR"
    fi
    log_debug "KDIR validated: $KDIR"
}

detect_kernel_config() {
    _dkc_found=0
    if [ -r /proc/config.gz ]; then
        _dkc_found=1
        log_info "kernel config available via /proc/config.gz"
    elif [ -f "$KDIR/.config" ]; then
        _dkc_found=1
        log_info "kernel config available via $KDIR/.config"
    elif [ -f "/boot/config-$KVER" ]; then
        _dkc_found=1
        log_info "kernel config available via /boot/config-$KVER"
    else
        log_warn "kernel config not found (build may still succeed)"
    fi
    if [ "$_dkc_found" -eq 1 ]; then
        return 0
    fi
    return 1
}

check_headers_integrity() {
    _chi_kdir="$1"
    _chi_ok=1
    for _chi_f in \
        "Makefile" \
        "include/linux/module.h" \
        "include/linux/init.h" \
        "include/linux/kernel.h" \
        "scripts/Makefile.build"; do
        if [ ! -f "$_chi_kdir/$_chi_f" ]; then
            log_debug "header integrity: missing $_chi_f"
            _chi_ok=0
        fi
    done
    if [ "$_chi_ok" -eq 1 ]; then
        log_debug "header integrity OK: $_chi_kdir"
        return 0
    fi
    log_warn "header integrity incomplete: $_chi_kdir"
    return 1
}

retry_make() {
    _rm_attempt=0
    _rm_max=2
    while [ "$_rm_attempt" -le "$_rm_max" ]; do
        _rm_attempt=$((_rm_attempt + 1))
        log_info "make attempt $_rm_attempt/$(( _rm_max + 1 ))"
        if run_make_single; then
            return 0
        fi
        log_warn "make attempt $_rm_attempt failed"
        if [ "$_rm_attempt" -le "$_rm_max" ]; then
            log_info "retrying after cleanup"
            cd "$MOD_SRC_DIR"
            make clean >/dev/null 2>&1 || true
            sleep 1
        fi
    done
    return 1
}

run_make_single() {
    validate_kdir
    stage_symvers
    cd "$MOD_SRC_DIR"
    _rms_jobs="$JOBS"
    _rms_cc="$CC"
    _rms_extra="$(make_args)"
    log_info "KDIR=$KDIR"
    log_info "CC=$_rms_cc"
    log_info "jobs=$_rms_jobs (nice=$NICE_LEVEL)"
    if [ "$DRY_RUN" -eq 1 ]; then
        log_info "dry run; printing command only"
        printf 'nice -n %s make -j%s CC=%s KDIR=%s KMI=on-device %s modules\n' \
            "$NICE_LEVEL" "$_rms_jobs" "$_rms_cc" "$KDIR" "$_rms_extra"
        return 0
    fi
    # shellcheck disable=SC2086
    if ! nice -n "$NICE_LEVEL" make -j"$_rms_jobs" CC="$_rms_cc" KDIR="$KDIR" KMI="on-device" $_rms_extra modules; then
        log_error "make failed for backend $BACKEND"
        return 1
    fi
    return 0
}

run_post_build_checks() {
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    _rpbc_ko="$MOD_SRC_DIR/$MODULE_FILE"
    if [ ! -f "$_rpbc_ko" ]; then
        return 1
    fi
    # check_universal if available
    if [ -f "$MOD_SRC_DIR/check_universal.py" ]; then
        log_info "running check_universal.py"
        if have python3; then
            # best-effort; do not fail build on missing System.map
            _rpbc_sysmap=""
            for _rpbc_cand in "$KDIR/System.map" "/boot/System.map-$KVER" "/lib/modules/$KVER/System.map"; do
                if [ -f "$_rpbc_cand" ]; then _rpbc_sysmap="$_rpbc_cand"; break; fi
            done
            if [ -n "$_rpbc_sysmap" ]; then
                if have nm; then
                    nm -u "$_rpbc_ko" 2>/dev/null | awk '{print $2}' | sort -u > "/tmp/bod-undef-$$" 2>/dev/null || true
                    python3 "$MOD_SRC_DIR/check_universal.py" "$_rpbc_ko" "/tmp/bod-undef-$$" "on-device" "$_rpbc_sysmap" 2>&1 | sed 's/^/    /' || log_warn "check_universal.py reported issues"
                    safe_rm "/tmp/bod-undef-$$"
                fi
            else
                log_debug "System.map not found; skipping check_universal.py"
            fi
        fi
    fi
    # modinfo sanity
    if have modinfo; then
        _rpbc_vermagic=$(modinfo "$_rpbc_ko" 2>/dev/null | awk -F: '/^vermagic:/{print $2}' | sed 's/^ *//')
        if [ -n "$_rpbc_vermagic" ]; then
            log_info "modinfo vermagic: $_rpbc_vermagic"
        fi
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Backend availability checks
# ---------------------------------------------------------------------------
btf_available() {
    if [ ! -r "$BTF_SOURCE" ]; then
        return 1
    fi
    if ! have bpftool; then
        return 1
    fi
    # BTF provides types; a kbuild tree is still needed to drive the build.
    if [ -n "$KDIR_OVERRIDE" ]; then
        return 0
    fi
    if find_standard_kdir >/dev/null 2>&1; then
        return 0
    fi
    if find_kbuild_kdir >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

proot_termux_available() {
    if [ "$TERMUX" -eq 1 ] || [ "$PROOT" -eq 1 ] || [ "$ANDROID" -eq 1 ]; then
        if have clang || have gcc || have cc || have aarch64-linux-android-clang; then
            return 0
        fi
    fi
    return 1
}

standard_available() {
    find_standard_kdir >/dev/null 2>&1
}

kbuild_available() {
    find_kbuild_kdir >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Backend setup functions
# ---------------------------------------------------------------------------
setup_standard() {
    if [ -n "$KDIR_OVERRIDE" ]; then
        KDIR="$KDIR_OVERRIDE"
        if [ ! -d "$KDIR" ] || [ ! -f "$KDIR/Makefile" ] || [ ! -f "$KDIR/include/linux/module.h" ]; then
            return 1
        fi
        BACKEND="standard"
        return 0
    fi
    if find_standard_kdir; then
        KDIR="$STANDARD_KDIR"
        BACKEND="standard"
        log_debug "setup_standard: $KDIR"
        return 0
    fi
    return 1
}

setup_kbuild() {
    if [ -n "$KDIR_OVERRIDE" ]; then
        KDIR="$KDIR_OVERRIDE"
        if [ ! -d "$KDIR" ] || [ ! -f "$KDIR/Makefile" ]; then
            return 1
        fi
        BACKEND="kbuild"
        return 0
    fi
    if find_kbuild_kdir; then
        KDIR="$KBUILD_KDIR"
        BACKEND="kbuild"
        log_debug "setup_kbuild: $KDIR"
        return 0
    fi
    return 1
}

generate_vmlinux_h() {
    if [ -z "$MOD_SRC_DIR" ]; then
        resolve_src_root
    fi
    BTF_OUTPUT="${MOD_SRC_DIR}/vmlinux.h"
    if [ -f "$BTF_OUTPUT" ] && [ "$FORCE" -ne 1 ]; then
        log_info "vmlinux.h already present: $BTF_OUTPUT"
        return 0
    fi
    if [ ! -r "$BTF_SOURCE" ]; then
        log_error "BTF source not readable: $BTF_SOURCE"
        return 1
    fi
    if ! have bpftool; then
        log_error "bpftool not found"
        return 1
    fi
    log_info "generating vmlinux.h from $BTF_SOURCE"
    _gv_tmp="${BTF_OUTPUT}.tmp.$$"
    register_tmp "$_gv_tmp"
    if bpftool btf dump file "$BTF_SOURCE" format c > "$_gv_tmp" 2>"$_gv_tmp.err"; then
        if is_nonempty "$_gv_tmp"; then
            mv -f "$_gv_tmp" "$BTF_OUTPUT"
            safe_rm "$_gv_tmp.err"
            log_info "generated $BTF_OUTPUT ($(wc -c < "$BTF_OUTPUT") bytes)"
            return 0
        fi
    fi
    safe_rm "$_gv_tmp" "$_gv_tmp.err"
    log_error "bpftool dump failed"
    return 1
}

setup_btf() {
    if ! btf_available; then
        return 1
    fi
    if [ -n "$KDIR_OVERRIDE" ]; then
        KDIR="$KDIR_OVERRIDE"
        if [ ! -d "$KDIR" ] || [ ! -f "$KDIR/Makefile" ]; then
            return 1
        fi
    else
        # BTF provides types; still need a kbuild tree for the build system
        if find_standard_kdir; then
            KDIR="$STANDARD_KDIR"
        elif find_kbuild_kdir; then
            KDIR="$KBUILD_KDIR"
        else
            log_warn "btf backend: no kbuild tree found; cannot build .ko"
            return 1
        fi
    fi
    if ! generate_vmlinux_h; then
        return 1
    fi
    BACKEND="btf"
    log_debug "setup_btf: KDIR=$KDIR BTF_OUTPUT=$BTF_OUTPUT"
    return 0
}

setup_proot() {
    if ! proot_termux_available; then
        return 1
    fi
    if [ -n "$KDIR_OVERRIDE" ]; then
        KDIR="$KDIR_OVERRIDE"
    else
        if find_kbuild_kdir; then
            KDIR="$KBUILD_KDIR"
        elif find_standard_kdir; then
            KDIR="$STANDARD_KDIR"
        else
            KDIR="/lib/modules/${KVER}/build"
        fi
    fi
    # A build tree is still required for kbuild.
    if [ ! -d "$KDIR" ] || [ ! -f "$KDIR/Makefile" ]; then
        log_warn "proot: no usable kbuild tree at $KDIR"
        return 1
    fi
    # Determine target arch / cross compile
    TARGET_ARCH="$OS_ARCH"
    case "$OS_ARCH" in
        aarch64) TARGET_ARCH="arm64" ;;
        armv7l|armv8l) TARGET_ARCH="arm" ;;
        x86_64) TARGET_ARCH="x86_64" ;;
    esac
    # Termux cross-compile: prefer NDK-style or installed cross toolchains
    CROSS_COMPILE=""
    for cand in \
        aarch64-linux-android- \
        arm-linux-androideabi- \
        aarch64-linux-gnu- \
        arm-linux-gnueabihf-; do
        if have "${cand}gcc"; then CROSS_COMPILE="$cand"; break; fi
    done
    if [ -z "$CROSS_COMPILE" ]; then
        case "$TARGET_ARCH" in
            arm64) TARGET_TRIPLE="aarch64-linux-android" ;;
            arm) TARGET_TRIPLE="arm-linux-androideabi" ;;
            *) TARGET_TRIPLE="" ;;
        esac
        if [ -n "$TARGET_TRIPLE" ]; then
            CC="$CC --target=$TARGET_TRIPLE"
            log_debug "proot: using clang target $TARGET_TRIPLE"
        fi
    fi
    BACKEND="proot"
    log_debug "setup_proot: KDIR=$KDIR TARGET_ARCH=$TARGET_ARCH CROSS_COMPILE=$CROSS_COMPILE"
    return 0
}

# ---------------------------------------------------------------------------
# Auto-selection
# ---------------------------------------------------------------------------
auto_select_backend() {
    log_step "Backend auto-selection"
    if [ "$BACKEND_REQUESTED" != "auto" ]; then
        case "$BACKEND_REQUESTED" in
            standard) setup_standard ;;
            kbuild) setup_kbuild ;;
            btf) setup_btf ;;
            proot|termux) setup_proot ;;
            *) die "unknown backend: $BACKEND_REQUESTED" ;;
        esac
        if [ $? -ne 0 ]; then
            log_error "requested backend unavailable: $BACKEND_REQUESTED"
            return 1
        fi
        log_info "backend selected (forced): $BACKEND"
        return 0
    fi

    # Priority order: standard > btf > kbuild > proot
    if setup_standard; then
        log_info "backend selected: standard headers ($KDIR)"
        return 0
    fi
    log_warn "standard headers unavailable"

    if setup_btf; then
        log_info "backend selected: BTF+vmlinux.h ($KDIR)"
        return 0
    fi
    log_warn "BTF backend unavailable"

    if setup_kbuild; then
        log_info "backend selected: kbuild-only ($KDIR)"
        return 0
    fi
    log_warn "kbuild tree unavailable"

    if setup_proot; then
        log_info "backend selected: proot/Termux fallback"
        return 0
    fi
    log_warn "proot/Termux backend unavailable"

    log_error "no build backend available for $KVER"
    return 1
}

detect_available_backends() {
    AVAILABLE_BACKENDS=""
    if standard_available; then AVAILABLE_BACKENDS="$AVAILABLE_BACKENDS standard"; fi
    if btf_available; then AVAILABLE_BACKENDS="$AVAILABLE_BACKENDS btf"; fi
    if kbuild_available; then AVAILABLE_BACKENDS="$AVAILABLE_BACKENDS kbuild"; fi
    if proot_termux_available; then AVAILABLE_BACKENDS="$AVAILABLE_BACKENDS proot"; fi
    # trim leading space
    AVAILABLE_BACKENDS="$(echo "$AVAILABLE_BACKENDS" | sed 's/^ *//')"
}

# ---------------------------------------------------------------------------
# Environment diagnostics
# ---------------------------------------------------------------------------
dump_environment() {
    log_step "Environment diagnostics"
    printf 'script_version=%s\n' "$SCRIPT_VERSION"
    printf 'kernel_version=%s\n' "$KVER"
    printf 'os_name=%s\n' "$OS_NAME"
    printf 'os_arch=%s\n' "$OS_ARCH"
    printf 'android=%s termux=%s proot=%s linux=%s\n' "$ANDROID" "$TERMUX" "$PROOT" "$LINUX"
    printf 'cpu_count=%s\n' "$CPU_COUNT"
    printf 'nice_level=%s\n' "$NICE_LEVEL"
    printf 'jobs=%s\n' "$JOBS"
    printf 'compiler=%s\n' "$CC"
    printf 'source_root=%s\n' "$SRC_ROOT"
    printf 'module_source=%s\n' "$MOD_SRC_DIR"
    printf 'kdir=%s\n' "$KDIR"
    printf 'backend=%s\n' "$BACKEND"
    printf 'dry_run=%s\n' "$DRY_RUN"
    printf 'dkms_mode=%s\n' "$DKMS_MODE"
    detect_available_backends
    printf 'available_backends=%s\n' "$AVAILABLE_BACKENDS"
    if [ -r /proc/config.gz ]; then
        printf 'kernel_config=/proc/config.gz (present)\n'
    else
        printf 'kernel_config=/proc/config.gz (absent)\n'
    fi
    if [ -r /sys/kernel/btf/vmlinux ]; then
        printf 'btf=/sys/kernel/btf/vmlinux (present)\n'
    else
        printf 'btf=/sys/kernel/btf/vmlinux (absent)\n'
    fi
    if have bpftool; then
        printf 'bpftool=%s\n' "$(command -v bpftool)"
    else
        printf 'bpftool=absent\n'
    fi
    if [ -f "$MOD_SRC_DIR/Makefile" ]; then
        printf 'makefile=%s/Makefile (present)\n' "$MOD_SRC_DIR"
    else
        printf 'makefile=MISSING\n'
    fi
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
preflight_checks() {
    log_step "Preflight checks"
    # make
    if ! have make; then die "make not found"; fi
    log_info "make: $(command -v make)"
    # compiler
    validate_toolchain
    # source tree
    resolve_src_root
    if [ ! -f "$MOD_SRC_DIR/Makefile" ]; then
        die "Makefile not found in $MOD_SRC_DIR"
    fi
    log_info "source tree OK: $MOD_SRC_DIR"
    # kernel version
    detect_kernel_version
    log_info "kernel version: $KVER"
    # cpu
    detect_cpu_count >/dev/null
    compute_jobs "$CPU_COUNT" >/dev/null
    log_info "cpu count: $CPU_COUNT, jobs: $JOBS"
    # disk space (best effort)
    if have df; then
        _pf_free=$(df -k "$MOD_SRC_DIR" 2>/dev/null | awk 'NR==2{print $4}')
        case "$_pf_free" in
            ''|*[!0-9]*) _pf_free=0 ;;
        esac
        if [ "$_pf_free" -gt 0 ] && [ "$_pf_free" -lt 10240 ]; then
            log_warn "low disk space: ${_pf_free} KB free"
        else
            log_debug "disk free: ${_pf_free} KB"
        fi
    fi
    log_info "preflight OK"
}

# ---------------------------------------------------------------------------
# Build helpers
# ---------------------------------------------------------------------------
stage_symvers() {
    if [ "$STAGE_SYMVERS" -ne 1 ]; then return 0; fi
    if [ -f "$KDIR/Module.symvers" ]; then
        if [ ! -f "$MOD_SRC_DIR/Module.symvers" ] || [ "$FORCE" -eq 1 ]; then
            if safe_copy "$KDIR/Module.symvers" "$MOD_SRC_DIR/Module.symvers"; then
                log_info "staged Module.symvers from $KDIR"
            fi
        else
            log_debug "Module.symvers already present; skipping stage"
        fi
    else
        log_debug "no Module.symvers in $KDIR"
    fi
}

clean_build() {
    if [ "$CLEAN_FIRST" -ne 1 ]; then return 0; fi
    log_info "cleaning previous build artifacts"
    cd "$MOD_SRC_DIR"
    if [ -z "$KDIR" ] || [ ! -d "$KDIR" ]; then
        make clean >/dev/null 2>&1 || true
    else
        make clean KDIR="$KDIR" >/dev/null 2>&1 || true
    fi
    # remove leftover objects
    find "$MOD_SRC_DIR" \( -name '*.o' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' -o -name '*.mod.o' -o -name '.*.cmd' \) -delete 2>/dev/null || true
    safe_rm "$MOD_SRC_DIR/.tmp_versions"
}

make_args() {
    # Echo extra make arguments based on backend
    _ma_extra=""
    if [ "$BACKEND" = "proot" ]; then
        if [ -n "$TARGET_ARCH" ]; then
            _ma_extra="$_ma_extra ARCH=$TARGET_ARCH"
        fi
        if [ -n "$CROSS_COMPILE" ]; then
            _ma_extra="$_ma_extra CROSS_COMPILE=$CROSS_COMPILE"
        fi
    fi
    if [ "$BACKEND" = "btf" ]; then
        _ma_extra="$_ma_extra ccflags-y+=-I$MOD_SRC_DIR"
    fi
    echo "$_ma_extra"
}


verify_build_artifact() {
    if [ "$VERIFY_ARTIFACT" -ne 1 ] || [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    _vba_ko="$MOD_SRC_DIR/$MODULE_FILE"
    if [ ! -f "$_vba_ko" ]; then
        log_error "build artifact not found: $_vba_ko"
        return 1
    fi
    _vba_size=$(wc -c < "$_vba_ko" 2>/dev/null || echo 0)
    log_info "build succeeded: $_vba_ko ($_vba_size bytes)"
    if [ "$_vba_size" -lt 1024 ]; then
        log_warn "artifact suspiciously small: $_vba_size bytes"
    fi
    if have modinfo; then
        log_info "modinfo:"
        modinfo "$_vba_ko" 2>/dev/null | sed 's/^/    /' || true
    fi
    if have strings; then
        if strings "$_vba_ko" | grep -q '^vermagic='; then
            log_info "vermagic placeholder present"
            _vba_vm=$(strings "$_vba_ko" | grep '^vermagic=' | head -n 1)
            log_debug "vermagic: $_vba_vm"
        else
            log_warn "vermagic placeholder not found"
        fi
    fi
    if have file; then
        file "$_vba_ko" 2>/dev/null | sed 's/^/    /' || true
    fi
    return 0
}

install_module() {
    if [ "$INSTALL_MODE" -ne 1 ]; then return 0; fi
    _im_ko="$MOD_SRC_DIR/$MODULE_FILE"
    if [ ! -f "$_im_ko" ]; then
        die "no artifact to install: $_im_ko"
    fi
    if [ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]; then
        die "install requires root privileges"
    fi
    if [ -z "$INSTALL_DEST" ]; then
        INSTALL_DEST="/lib/modules/${KVER}/extra/${MODULE_FILE}"
    fi
    ensure_dir "$(dirname "$INSTALL_DEST")"
    if ! safe_copy "$_im_ko" "$INSTALL_DEST"; then
        die "install copy failed"
    fi
    log_info "installed module to $INSTALL_DEST"
    if have depmod; then
        depmod -a "$KVER" 2>/dev/null || log_warn "depmod failed (continuing)"
    fi
    if [ -f "$INSTALL_DEST" ]; then
        log_info "install verified"
    else
        die "install verification failed"
    fi
}

write_build_report() {
    _wbr_path="${BUILD_REPORT:-$MOD_SRC_DIR/build-on-device.report}"
    {
        printf 'build-on-device report\n'
        printf 'version=%s\n' "$SCRIPT_VERSION"
        printf 'timestamp=%s\n' "$(ts_now)"
        printf 'kernel=%s\n' "$KVER"
        printf 'backend=%s\n' "$BACKEND"
        printf 'kdir=%s\n' "$KDIR"
        printf 'compiler=%s\n' "$CC"
        printf 'jobs=%s\n' "$JOBS"
        printf 'nice=%s\n' "$NICE_LEVEL"
        printf 'artifact=%s\n' "$MOD_SRC_DIR/$MODULE_FILE"
        if [ -f "$MOD_SRC_DIR/$MODULE_FILE" ]; then
            printf 'artifact_size=%s\n' "$(wc -c < "$MOD_SRC_DIR/$MODULE_FILE")"
        fi
    } > "$_wbr_path" 2>/dev/null || log_warn "cannot write report: $_wbr_path"
    log_debug "report written: $_wbr_path"
}

# ---------------------------------------------------------------------------
# Self-test (minimal)
# ---------------------------------------------------------------------------
run_self_test() {
    log_step "Self-test"
    _st_fail=0
    # test have()
    if have sh; then log_info "self-test: have(sh) OK"; else log_error "self-test: have(sh) FAIL"; _st_fail=1; fi
    # test compute_jobs
    _st_j=$(compute_jobs 8)
    if [ "$_st_j" -ge 1 ] && [ "$_st_j" -le 4 ]; then
        log_info "self-test: compute_jobs(8)=$_st_j OK"
    else
        log_error "self-test: compute_jobs(8)=$_st_j FAIL"
        _st_fail=1
    fi
    # test is_dir
    if is_dir /; then log_info "self-test: is_dir(/) OK"; else log_error "self-test: is_dir(/) FAIL"; _st_fail=1; fi
    if is_file /etc/hosts 2>/dev/null || is_file /bin/sh; then
        log_info "self-test: is_file OK"
    fi
    # test safe_rm on temp
    _st_tmp="/tmp/bod-selftest-$$"
    printf 'x' > "$_st_tmp"
    register_tmp "$_st_tmp"
    safe_rm "$_st_tmp"
    if [ ! -e "$_st_tmp" ]; then log_info "self-test: safe_rm OK"; else log_error "self-test: safe_rm FAIL"; _st_fail=1; fi
    if [ "$_st_fail" -eq 0 ]; then
        log_info "self-test: ALL PASSED"
        return 0
    fi
    log_error "self-test: FAILURES PRESENT"
    return 1
}

# ---------------------------------------------------------------------------
# List backends
# ---------------------------------------------------------------------------
list_backends_cmd() {
    detect_environment
    detect_kernel_version
    detect_available_backends
    log_step "Backend availability"
    for b in standard btf kbuild proot; do
        case " $AVAILABLE_BACKENDS " in
            *" $b "*) printf '%-10s available\n' "$b" ;;
            *) printf '%-10s unavailable\n' "$b" ;;
        esac
    done
    printf 'available: %s\n' "$AVAILABLE_BACKENDS"
}

# ---------------------------------------------------------------------------
# Main build flow
# ---------------------------------------------------------------------------
build_once() {
    _bo_backend="$1"
    BACKEND_REQUESTED="$_bo_backend"
    if ! auto_select_backend; then
        return 1
    fi
    validate_kdir
    detect_kernel_config || true
    check_headers_integrity "$KDIR" || true
    clean_build
    retry_make
}

main_build() {
    detect_environment
    preflight_checks
    detect_kernel_version
    resolve_src_root

    _mb_cpu=$(detect_cpu_count)
    compute_jobs "$_mb_cpu" >/dev/null
    apply_throttle_env

    if [ "$LIST_BACKENDS" -eq 1 ]; then
        list_backends_cmd
        exit 0
    fi
    if [ "$DIAGNOSE" -eq 1 ]; then
        if auto_select_backend; then
            :
        else
            log_warn "no backend auto-selected"
        fi
        dump_environment
        exit 0
    fi
    if [ "$SELF_TEST" -eq 1 ]; then
        run_self_test
        exit $?
    fi

    if [ "$TRY_ALL" -eq 1 ]; then
        detect_available_backends
        if [ -z "$AVAILABLE_BACKENDS" ]; then
            die "no backends available"
        fi
        _mb_success=0
        for _mb_b in $AVAILABLE_BACKENDS; do
            log_step "Trying backend: $_mb_b"
            if build_once "$_mb_b"; then
                if verify_build_artifact; then
                    run_post_build_checks || true
                    _mb_success=1
                    break
                fi
            fi
            log_warn "backend $_mb_b failed; trying next"
        done
        if [ "$_mb_success" -ne 1 ]; then
            die "all backends failed"
        fi
    else
        if ! auto_select_backend; then
            die "no build backend available for $KVER"
        fi
        validate_kdir
        detect_kernel_config || true
        check_headers_integrity "$KDIR" || true
        clean_build
        if ! retry_make; then
            die "build failed for backend $BACKEND"
        fi
        if ! verify_build_artifact; then
            die "artifact verification failed"
        fi
        run_post_build_checks || true
    fi

    write_build_report
    install_module
    log_step "DONE"
    log_info "backend used: $BACKEND"
    log_info "artifact: $MOD_SRC_DIR/$MODULE_FILE"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    main_build
}

main "$@"
