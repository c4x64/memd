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

    path_bytes = path.encode()
    entry_bytes = (entry or "").encode()
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

    cmd = iowr(NR_LOADSO_UNLOAD, UNLOAD_SIZE)
    buf = bytearray(struct.pack(UNLOAD_FMT, pid, handle, 0))
    fcntl.ioctl(sock.fileno(), cmd, buf)
    _pid, _handle, result = struct.unpack(UNLOAD_FMT, bytes(buf))
    return result


def stage_module(zip_path, root, abi):
    """Validate + extract; returns (module_id, staged_path, version_code)."""
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        try:
            prop_text = archive.read("module.prop").decode("utf-8", "replace")
        except KeyError:
            raise ValueError("module zip has no module.prop")
        props = parse_module_prop(prop_text)
        lib = pick_abi_lib(names, abi)
        module_id = props["id"]
        staged = staging_path(root, module_id)
        os.makedirs(os.path.dirname(staged), exist_ok=True)
        with archive.open(lib) as src, open(staged, "wb") as dst:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
    return module_id, staged, props.get("versionCode", "")


def cmd_install(args):
    module_id, staged, version = stage_module(args.zip, args.root, args.abi)
    print("staged %s -> %s (v%s)" % (args.zip, staged, version))
    if lock_down(staged):
        print("warning: lock_down failed (need root?)")
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
    with open(state_path(args.root, module_id, args.pid), "w") as stream:
        json.dump(
            {"id": module_id, "version": version, "handle": handle}, stream
        )
    if args.unlink:
        try:
            os.unlink(staged)
            print("unlinked staged file (mapping persists)")
        except OSError as error:
            print("warning: unlink failed: %s" % error)
    return 0


def read_state(root, module_id, pid):
    try:
        with open(state_path(root, module_id, pid), encoding="utf-8") as stream:
            state = json.load(stream)
            return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def cmd_hotswap(args):
    if args.ephemeral:
        print("error: hotswap needs a resident (non-ephemeral) load", file=sys.stderr)
        return errno.EINVAL
    try:
        with zipfile.ZipFile(args.zip) as archive:
            prop_text = archive.read("module.prop").decode("utf-8", "replace")
    except KeyError:
        print("error: module zip has no module.prop", file=sys.stderr)
        return errno.EINVAL
    except zipfile.BadZipFile as error:
        print("error: %s" % error, file=sys.stderr)
        return errno.EINVAL
    try:
        props = parse_module_prop(prop_text)
    except ValueError as error:
        print("error: %s" % error, file=sys.stderr)
        return errno.EINVAL
    old_state = read_state(args.root, props["id"], args.pid)
    old_handle = old_state.get("handle", 0)
    result = cmd_install(args)
    if result != 0:
        return result
    new_state = read_state(args.root, props["id"], args.pid)
    new_handle = new_state.get("handle", 0)
    if old_handle and old_handle != new_handle:
        sock = find_driver_family()
        try:
            result = ioctl_unload(sock, args.pid, old_handle)
        finally:
            sock.close()
        print("unload old handle=0x%x result=%d" % (old_handle, result))
        if result != 0:
            # New library is resident but the old one survived too:
            # keep both handles on record so nothing leaks silently.
            new_state["prev_handle"] = old_handle
            with open(
                state_path(args.root, props["id"], args.pid), "w"
            ) as stream:
                json.dump(new_state, stream)
        return result
    return 0


def cmd_uninstall(args):
    try:
        check_module_id(args.id)
    except ValueError as error:
        print("error: %s" % error, file=sys.stderr)
        return errno.EINVAL
    path = state_path(args.root, args.id, args.pid)
    try:
        with open(path) as stream:
            state = json.load(stream)
    except (OSError, ValueError):
        print("no recorded install for %s pid %d" % (args.id, args.pid))
        return errno.ENOENT
    handle = state.get("handle", 0)
    if not handle:
        print("recorded handle is empty")
        return errno.EINVAL
    sock = find_driver_family()
    try:
        result = ioctl_unload(sock, args.pid, handle)
    finally:
        sock.close()
    print("unload result=%d" % result)
    if result == 0:
        try:
            os.unlink(path)
        except OSError:
            pass
    return result


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
    except (OSError, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
