#!/usr/bin/env python3
"""lxgr_load.py — install/hotswap/uninstall Zygisk-scheme module ZIPs.

Module layout (Magisk/Zygisk structure):
    module.prop            id=, name=, version=, versionCode=, author=
    zygisk/<abi>.so       payload, one per ABI (arm64-v8a, ...)

Flow per install: validate zip -> pick ABI lib -> stage under a
root-only dir -> lock down (chown 0:0, chmod 0700) -> remote dlopen via
the MEMD driver (optional entry + su window) -> record {handle} in a
per-pid state file -> optionally unlink the staged file (mapping
survives on the inode, path disappears). Hotswap = install new, then
unload old handle. Uninstall = unload recorded handle.

Only stdlib is used (zipfile/struct/fcntl), so this runs on-device
under python3 with no extra packages. Pure helpers are unit-tested in
test_lxgr_load.py; ioctl/socket paths need the live driver.
"""

import argparse
import errno
import json
import os
import platform
import socket
import struct
import sys
import zipfile

ABI_LIB_TEMPLATE = "zygisk/%s.so"
SUPPORTED_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
# The injector stub is arm64 machine code: only arm64 payloads run.
LOADABLE_ABIS = ("arm64-v8a",)

_IOC_READ = 0xC0000000
_IOC_TYPE = ord("W")
NR_LOAD_SOTOAPP = 38
NR_LOAD_SOSUTOAPP = 39
NR_LOADSO_UNLOAD = 41

# struct memd_loadso_cmd: pid@0 path@4 entry@260 flags@324 result@328
# handle@336 entry_result@344 (352 bytes, LP64).
LOADSO_FMT = "<i256s64sii4xQi4x"
LOADSO_SIZE = struct.calcsize(LOADSO_FMT)
# struct memd_loadso_unload_cmd: pid@0 handle@8 result@16 (24 bytes).
UNLOAD_FMT = "<i4xQi4x"
UNLOAD_SIZE = struct.calcsize(UNLOAD_FMT)

LOADSO_EPHEMERAL = 1

# Zip/CLI input caps: fail closed instead of staging unbounded bytes.
MAX_PROP_BYTES = 65536
MAX_SO_BYTES = 64 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
# Survivor-chain cap: every failed unload appends one entry, so an
# install that would push past this refuses instead of growing the
# state file (and the resident set) without bound.
# Interplay (Round-7 audit, Round-8 exactness): a HEALTHY flow never
# approaches 64 -- drain success clears the chain (hotswap drops it,
# uninstall unlinks the record), so the count only grows while no
# drain runs: CONSECUTIVE unload failures (driver/target wedged, 64
# hotswaps in a row) or consecutive reinstalls (each install retires
# the displaced handle until a hotswap/uninstall drains it). The
# refusal happens in cmd_install BEFORE any load (no stranded
# live-but-unrecorded handle), and hotswap inherits it because it
# funnels through cmd_install; write_state re-checks as a backstop for
# externally-grown records. Drain-oldest was rejected: evicting the
# oldest survivor would orphan a still-resident library the next
# uninstall could never find (a silent leak), while refusing keeps
# every resident handle on record for the operator to drain with
# uninstall. 64 is ample for flaky targets and small enough to keep
# the state file (and one retry loop) bounded.
MAX_PREV_HANDLES = 64
MAX_PID = (1 << 31) - 1  # struct "<i" range; real pids are far smaller
MAX_HANDLE = (1 << 64) - 1  # struct "<Q" range


def iowr(nr, size):
    return _IOC_READ | (size << 16) | (_IOC_TYPE << 8) | nr


def check_module_id(module_id):
    if not module_id or not all(ch.isalnum() or ch in "._-" for ch in module_id):
        raise ValueError("module id is missing or not filesystem-safe")
    return module_id


def parse_module_prop(text):
    """Parse module.prop into a dict; id and versionCode are required."""
    props = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key.strip()] = value.strip()
    module_id = props.get("id", "")
    # Filesystem-safe id only: stage/state paths are built by joining,
    # so reject traversal, separators, and empty ids outright.
    check_module_id(module_id)
    if not props.get("versionCode"):
        raise ValueError("module.prop has no versionCode=")
    return props


def pick_abi_lib(names, abi):
    """Select the zygisk/<abi>.so entry; refuse unloadable ABIs."""
    if abi not in SUPPORTED_ABIS:
        raise ValueError("unsupported abi %r" % (abi,))
    if abi not in LOADABLE_ABIS:
        raise ValueError(
            "abi %s is not executable by this injector (arm64 only)" % abi
        )
    want = ABI_LIB_TEMPLATE % abi
    if want not in names:
        raise ValueError("module zip has no %s" % want)
    return want


def default_abi():
    machine = platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "arm64-v8a"
    if machine.startswith("arm"):
        return "armeabi-v7a"
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    return machine


def staging_path(root, module_id):
    return os.path.join(root, module_id, "payload.so")


def state_path(root, module_id, pid):
    return os.path.join(root, module_id, "pid-%d.json" % pid)


def lock_down(path):
    """Root-only perms for a staged payload. Best-effort (-errno)."""
    try:
        os.chown(path, 0, 0)
    except OSError as error:
        return -error.errno
    try:
        os.chmod(path, 0o700)
    except OSError as error:
        return -error.errno
    return 0


def find_driver_family():
    """Probe socket families 12..28 like run.sh: SEQPACKET failing with
    ENOKEY(126) marks ours, then RAW must open."""
    for family in range(12, 28):
        try:
            sock = socket.socket(family, socket.SOCK_SEQPACKET)
            sock.close()
            continue
        except OSError as error:
            if error.errno != 126:
                continue
        try:
            return socket.socket(family, socket.SOCK_RAW)
        except OSError:
            continue
    raise OSError(errno.ENODEV, "MEMD driver socket not found")


def ioctl_load(sock, pid, path, entry, su, ephemeral):
    import fcntl

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or pid > MAX_PID:
        raise ValueError("pid must be a positive 32-bit integer")
    if not isinstance(path, str):
        raise ValueError("path must be a string")
    if entry is not None and not isinstance(entry, str):
        raise ValueError("entry must be a string")
    path_bytes = path.encode()
    entry_bytes = (entry or "").encode()
    if b"\x00" in path_bytes or b"\x00" in entry_bytes:
        raise ValueError("path and entry must not contain NUL bytes")
    # Never silently truncate: the kernel rejects over-long inputs, so
    # fail here with the same meaning instead of loading the wrong file.
    if len(path_bytes) > 255 or path_bytes[:1] != b"/":
        raise ValueError("path must be absolute and fit in 255 bytes")
    if len(entry_bytes) > 63 or b"/" in entry_bytes:
        raise ValueError("entry must fit in 63 bytes with no slashes")
    cmd = iowr(NR_LOAD_SOSUTOAPP if su else NR_LOAD_SOTOAPP, LOADSO_SIZE)
    buf = bytearray(
        struct.pack(
            LOADSO_FMT,
            pid,
            path_bytes,
            entry_bytes,
            LOADSO_EPHEMERAL if ephemeral else 0,
            0,
            0,
            0,
        )
    )
    fcntl.ioctl(sock.fileno(), cmd, buf)
    _pid, _path, _entry, _flags, result, handle, entry_result = struct.unpack(
        LOADSO_FMT, bytes(buf)
    )
    return result, handle, entry_result


def ioctl_unload(sock, pid, handle):
    import fcntl

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or pid > MAX_PID:
        raise ValueError("pid must be a positive 32-bit integer")
    if (
        isinstance(handle, bool)
        or not isinstance(handle, int)
        or handle <= 0
        or handle > MAX_HANDLE
    ):
        raise ValueError("handle must be a nonzero 64-bit integer")
    cmd = iowr(NR_LOADSO_UNLOAD, UNLOAD_SIZE)
    buf = bytearray(struct.pack(UNLOAD_FMT, pid, handle, 0))
    fcntl.ioctl(sock.fileno(), cmd, buf)
    _pid, _handle, result = struct.unpack(UNLOAD_FMT, bytes(buf))
    return result


def stage_module(zip_path, root, abi):
    """Validate + extract; returns (module_id, staged_path, version_code)."""
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ValueError("invalid module zip: %s" % error)
    except RuntimeError as error:
        # Unsupported compression raises NotImplementedError (a
        # RuntimeError); normalize it like any other unreadable zip.
        raise ValueError("invalid module zip: %s" % error)
    with archive:
        names = archive.namelist()
        if len(names) > MAX_ZIP_ENTRIES:
            raise ValueError("module zip lists too many entries")
        try:
            prop_info = archive.getinfo("module.prop")
        except KeyError:
            raise ValueError("module zip has no module.prop")
        if prop_info.file_size > MAX_PROP_BYTES:
            raise ValueError("module.prop is too large")
        try:
            prop_text = archive.read("module.prop").decode("utf-8", "replace")
        except KeyError:
            raise ValueError("module zip has no module.prop")
        except RuntimeError as error:
            # Encrypted entries raise here (password required); refuse
            # instead of leaking a traceback through main().
            raise ValueError("unreadable module.prop: %s" % error)
        props = parse_module_prop(prop_text)
        lib = pick_abi_lib(names, abi)
        if archive.getinfo(lib).file_size > MAX_SO_BYTES:
            raise ValueError("payload %s is too large" % lib)
        module_id = props["id"]
        staged = staging_path(root, module_id)
        os.makedirs(os.path.dirname(staged), exist_ok=True)
        # Extract to a temp name and rename: a failed/capped extract must
        # never leave a truncated payload.so behind as if it were staged.
        tmp = staged + ".tmp"
        try:
            with archive.open(lib) as src, open(tmp, "wb") as dst:
                remaining = MAX_SO_BYTES
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError(
                            "payload %s exceeds %d bytes" % (lib, MAX_SO_BYTES)
                        )
                    dst.write(chunk)
        except (OSError, ValueError):
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as error:
            # Stream-read failures only: BadZipFile (CRC), LargeZipFile
            # (>2GB entry), RuntimeError (unsupported compression, which
            # surfaces as NotImplementedError, a RuntimeError subclass).
            # Anything else is a programming error and must propagate.
            # Clean the partial file, then normalize so main() reports
            # instead of tracing.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise ValueError("unreadable payload %s: %s" % (lib, error))
        os.replace(tmp, staged)
    return module_id, staged, props.get("versionCode", "")


def read_state(root, module_id, pid):
    try:
        with open(state_path(root, module_id, pid), encoding="utf-8") as stream:
            state = json.load(stream)
            return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(root, module_id, pid, record):
    """Atomically replace the state file: a crash mid-write must leave
    either the old record or the new one, never truncated JSON (which
    read_state would treat as 'no install' and leak live handles).

    fsyncs the tmp file and its directory so the rename is durable, not
    just atomic: without that, a power loss could roll back to the old
    record and orphan the just-loaded handle. Same-dir os.replace is
    atomic on every kernel filesystem backing the state dir (tmpfs,
    ext4/f2fs); no copy fallback, which could only weaken the guarantee.
    Also refuses an over-cap chain as a backstop (cmd_install checks
    first, before loading anything)."""
    pending = record.get("prev_handles")
    if isinstance(pending, list) and len(pending) > MAX_PREV_HANDLES:
        raise ValueError("prev_handles chain exceeds %d entries"
                         % MAX_PREV_HANDLES)
    path = state_path(root, module_id, pid)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    try:
        dir_fd = os.open(os.path.dirname(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def pending_handles(state):
    """Un-retired handles from earlier installs/hotswaps, oldest first.

    Reads both the current "prev_handles" list and the legacy singular
    "prev_handle" int; junk entries are ignored, never trusted."""
    out = []
    value = state.get("prev_handles")
    candidates = value if isinstance(value, list) else [state.get("prev_handle")]
    for handle in candidates:
        if isinstance(handle, bool) or not isinstance(handle, int):
            continue
        if handle and handle not in out:
            out.append(handle)
    return out


def cmd_install(args):
    module_id, staged, version = stage_module(args.zip, args.root, args.abi)
    print("staged %s -> %s (v%s)" % (args.zip, staged, version))
    if lock_down(staged):
        print("warning: lock_down failed (need root?)")
    # Fail closed before touching the driver: a full survivor chain means
    # unloads keep failing, so refuse another load rather than pile a new
    # resident handle on top. Checked here (not after the load) so a
    # refusal never strands a live-but-unrecorded handle in the target.
    already = read_state(args.root, module_id, args.pid)
    if len(pending_handles(already)) >= MAX_PREV_HANDLES:
        raise ValueError("too many un-unloaded handles (%d); "
                         "uninstall --id %s --pid %d first"
                         % (len(pending_handles(already)), module_id,
                            args.pid))
    sock = find_driver_family()
    try:
        result, handle, entry_result = ioctl_load(
            sock, args.pid, staged, args.entry, args.su, args.ephemeral
        )
    finally:
        sock.close()
    print("load result=%d handle=0x%x entry=%d" % (result, handle, entry_result))
    if result != 0:
        return result
    # A reinstall displaces the live handle: retire it into the pending
    # chain (same record, atomic write) instead of orphaning it. A crash
    # after this point still has every resident handle on record; the
    # next hotswap/uninstall drains them.
    record = {"id": module_id, "version": version, "handle": handle}
    displaced = already
    pend = []
    old = displaced.get("handle", 0)
    if (
        isinstance(old, int)
        and not isinstance(old, bool)
        and old
        and old != handle
    ):
        pend.append(old)
    for prev in pending_handles(displaced):
        if prev != handle and prev not in pend:
            pend.append(prev)
    if pend:
        record["prev_handles"] = pend
        print("previous handle(s) retained pending unload: %s"
              % ", ".join("0x%x" % h for h in pend))
    write_state(args.root, module_id, args.pid, record)
    if args.unlink:
        try:
            os.unlink(staged)
            print("unlinked staged file (mapping persists)")
        except OSError as error:
            print("warning: unlink failed: %s" % error)
    return 0


def cmd_hotswap(args):
    if args.ephemeral:
        print("error: hotswap needs a resident (non-ephemeral) load", file=sys.stderr)
        return errno.EINVAL
    try:
        archive = zipfile.ZipFile(args.zip)
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        print("error: invalid module zip: %s" % error, file=sys.stderr)
        return errno.EINVAL
    except RuntimeError as error:
        print("error: invalid module zip: %s" % error, file=sys.stderr)
        return errno.EINVAL
    try:
        with archive:
            try:
                prop_info = archive.getinfo("module.prop")
            except KeyError:
                print("error: module zip has no module.prop", file=sys.stderr)
                return errno.EINVAL
            if prop_info.file_size > MAX_PROP_BYTES:
                print("error: module.prop is too large", file=sys.stderr)
                return errno.EINVAL
            try:
                prop_text = archive.read("module.prop").decode("utf-8", "replace")
            except KeyError:
                print("error: module zip has no module.prop", file=sys.stderr)
                return errno.EINVAL
    except (OSError, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return errno.EINVAL
    except RuntimeError as error:
        print("error: unreadable module.prop: %s" % error, file=sys.stderr)
        return errno.EINVAL
    try:
        props = parse_module_prop(prop_text)
    except ValueError as error:
        print("error: %s" % error, file=sys.stderr)
        return errno.EINVAL
    result = cmd_install(args)
    if result != 0:
        return result
    # cmd_install already folded the displaced handle into prev_handles
    # (atomic with the new record), so every resident handle is on disk
    # before the first unload is attempted: crash-safe by construction.
    state = read_state(args.root, props["id"], args.pid)
    new_handle = state.get("handle", 0)
    targets = [h for h in pending_handles(state) if h != new_handle]
    if not targets:
        return 0
    sock = find_driver_family()
    try:
        failed = 0
        survivors = []
        for old_handle in targets:
            unload_result = ioctl_unload(sock, args.pid, old_handle)
            print("unload old handle=0x%x result=%d" % (old_handle, unload_result))
            if unload_result != 0:
                survivors.append(old_handle)
                if not failed:
                    failed = unload_result
    finally:
        sock.close()
    # Survivors stay on record for the next hotswap/uninstall; a clean
    # sweep drops the chain back to the bare current handle.
    state["prev_handles"] = survivors
    if not survivors:
        state.pop("prev_handles", None)
    state.pop("prev_handle", None)  # legacy singular key, superseded
    write_state(args.root, props["id"], args.pid, state)
    return failed


def cmd_uninstall(args):
    try:
        check_module_id(args.id)
    except ValueError as error:
        print("error: %s" % error, file=sys.stderr)
        return errno.EINVAL
    path = state_path(args.root, args.id, args.pid)
    try:
        with open(path, encoding="utf-8") as stream:
            state = json.load(stream)
    except (OSError, ValueError):
        print("no recorded install for %s pid %d" % (args.id, args.pid))
        return errno.ENOENT
    if not isinstance(state, dict):
        print("recorded install for %s pid %d is corrupt" % (args.id, args.pid))
        return errno.EINVAL
    handle = state.get("handle", 0)
    if isinstance(handle, bool) or not isinstance(handle, int) or not handle:
        handle = 0
    # Drain the whole chain: the current handle plus every pending
    # survivor from earlier installs/hotswaps (legacy "prev_handle"
    # included). Unlink the record only when nothing is left resident.
    targets = []
    if handle:
        targets.append(handle)
    for prev in pending_handles(state):
        if prev != handle and prev not in targets:
            targets.append(prev)
    if not targets:
        print("recorded handle is empty")
        return errno.EINVAL
    sock = find_driver_family()
    try:
        failed = 0
        survivors = []
        for target in targets:
            result = ioctl_unload(sock, args.pid, target)
            print("unload handle=0x%x result=%d" % (target, result))
            if result != 0:
                survivors.append(target)
                if not failed:
                    failed = result
    finally:
        sock.close()
    if survivors:
        # Anything still resident stays on record (first survivor as
        # the current handle) for the next uninstall attempt.
        state["handle"] = survivors[0]
        state["prev_handles"] = survivors[1:]
        if not state["prev_handles"]:
            state.pop("prev_handles", None)
        state.pop("prev_handle", None)  # legacy singular key, superseded
        write_state(args.root, args.id, args.pid, state)
        return failed
    try:
        os.unlink(path)
    except OSError:
        pass
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/data/local/tmp/lxgr")
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install")
    install.add_argument("zip")
    install.add_argument("--pid", type=int, required=True)
    install.add_argument("--abi", default=default_abi())
    install.add_argument("--entry", default="lxgr_main")
    install.add_argument("--su", action="store_true")
    install.add_argument("--ephemeral", action="store_true")
    install.add_argument("--unlink", dest="unlink", action="store_true", default=True)
    install.add_argument("--no-unlink", dest="unlink", action="store_false")
    install.set_defaults(func=cmd_install)

    hotswap = sub.add_parser("hotswap")
    hotswap.add_argument("zip")
    hotswap.add_argument("--pid", type=int, required=True)
    hotswap.add_argument("--abi", default=default_abi())
    hotswap.add_argument("--entry", default="lxgr_main")
    hotswap.add_argument("--su", action="store_true")
    hotswap.add_argument("--ephemeral", action="store_true")
    hotswap.add_argument("--unlink", dest="unlink", action="store_true", default=True)
    hotswap.add_argument("--no-unlink", dest="unlink", action="store_false")
    hotswap.set_defaults(func=cmd_hotswap)

    uninstall = sub.add_parser("uninstall")
    uninstall.add_argument("--id", required=True)
    uninstall.add_argument("--pid", type=int, required=True)
    uninstall.set_defaults(func=cmd_uninstall)

    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except (OSError, ValueError, zipfile.BadZipFile, struct.error) as error:
        print("error: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
