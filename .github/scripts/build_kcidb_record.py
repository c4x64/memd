#!/usr/bin/env python3
"""Prepare one KernelCI kernel tree and compile rwbridge against it."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


TOOLCHAINS = {
    "alpha": ("alpha", "alpha-linux-gnu-", "gcc-alpha-linux-gnu"),
    "aarch64": ("arm64", "aarch64-linux-gnu-", "gcc-aarch64-linux-gnu"),
    "arm64": ("arm64", "aarch64-linux-gnu-", "gcc-aarch64-linux-gnu"),
    "arc": ("arc", "arc-linux-gnu-", "gcc-arc-linux-gnu"),
    "arm": ("arm", "arm-linux-gnueabi-", "gcc-arm-linux-gnueabi"),
    "armv7l": ("arm", "arm-linux-gnueabi-", "gcc-arm-linux-gnueabi"),
    "csky": ("csky", "csky-linux-gnu-", "gcc-csky-linux-gnu"),
    "hppa": ("parisc", "hppa-linux-gnu-", "gcc-hppa-linux-gnu"),
    "i486": ("x86", "", None),
    "i386": ("x86", "", None),
    "i686": ("x86", "", None),
    "loongarch64": (
        "loongarch",
        "loongarch64-linux-gnu-",
        "gcc-loongarch64-linux-gnu",
    ),
    "m68k": ("m68k", "m68k-linux-gnu-", "gcc-m68k-linux-gnu"),
    "microblaze": (
        "microblaze",
        "microblaze-linux-gnu-",
        "gcc-microblaze-linux-gnu",
    ),
    "x86": ("x86", "", None),
    "x86_64": ("x86", "", None),
    "amd64": ("x86", "", None),
    "mips": ("mips", "mips-linux-gnu-", "gcc-mips-linux-gnu"),
    "mips64": ("mips", "mips64-linux-gnuabi64-", "gcc-mips64-linux-gnuabi64"),
    "mips64el": (
        "mips",
        "mips64el-linux-gnuabi64-",
        "gcc-mips64el-linux-gnuabi64",
    ),
    "mipsel": ("mips", "mipsel-linux-gnu-", "gcc-mipsel-linux-gnu"),
    "nios2": ("nios2", "nios2-linux-gnu-", "gcc-nios2-linux-gnu"),
    "openrisc": ("openrisc", "or1k-linux-gnu-", "gcc-or1k-linux-gnu"),
    "parisc": ("parisc", "hppa-linux-gnu-", "gcc-hppa-linux-gnu"),
    "parisc64": ("parisc", "hppa64-linux-gnu-", "gcc-hppa64-linux-gnu"),
    "powerpc32": ("powerpc", "powerpc-linux-gnu-", "gcc-powerpc-linux-gnu"),
    "powerpc64": ("powerpc", "powerpc64-linux-gnu-", "gcc-powerpc64-linux-gnu"),
    "powerpc": ("powerpc", "powerpc64le-linux-gnu-", "gcc-powerpc64le-linux-gnu"),
    "powerpc64le": (
        "powerpc",
        "powerpc64le-linux-gnu-",
        "gcc-powerpc64le-linux-gnu",
    ),
    "ppc": ("powerpc", "powerpc-linux-gnu-", "gcc-powerpc-linux-gnu"),
    "ppc64": ("powerpc", "powerpc64-linux-gnu-", "gcc-powerpc64-linux-gnu"),
    "ppc64le": ("powerpc", "powerpc64le-linux-gnu-", "gcc-powerpc64le-linux-gnu"),
    "riscv32": ("riscv", "riscv64-linux-gnu-", "gcc-riscv64-linux-gnu"),
    "riscv": ("riscv", "riscv64-linux-gnu-", "gcc-riscv64-linux-gnu"),
    "riscv64": ("riscv", "riscv64-linux-gnu-", "gcc-riscv64-linux-gnu"),
    "s390": ("s390", "s390x-linux-gnu-", "gcc-s390x-linux-gnu"),
    "s390x": ("s390", "s390x-linux-gnu-", "gcc-s390x-linux-gnu"),
    "sh": ("sh", "sh4-linux-gnu-", "gcc-sh4-linux-gnu"),
    "sh4": ("sh", "sh4-linux-gnu-", "gcc-sh4-linux-gnu"),
    "sparc": ("sparc", "sparc64-linux-gnu-", "gcc-sparc64-linux-gnu"),
    "sparc64": ("sparc", "sparc64-linux-gnu-", "gcc-sparc64-linux-gnu"),
    "um": ("um", "", None),
    "xtensa": ("xtensa", "xtensa-linux-gnu-", "gcc-xtensa-linux-gnu"),
}

BASE_PACKAGES = [
    "bc",
    "bison",
    "build-essential",
    "flex",
    "libelf-dev",
    "libssl-dev",
    "make",
    "pkg-config",
]


class HTTPSRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        if urlparse(url).scheme != "https":
            raise ValueError("refusing non-HTTPS config redirect")
        return super().redirect_request(request, response, code, message, headers, url)


def require_https(url, field):
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError(f"{field} must be an HTTPS URL without embedded credentials")
    return url


def run(command, **kwargs):
    subprocess.run(command, check=True, **kwargs)


def download_config(url, destination):
    require_https(url, "config_url")
    request = Request(url, headers={"User-Agent": "rwbridge-kernelci-build/1"})
    opener = build_opener(HTTPSRedirectHandler())
    with opener.open(request, timeout=60) as response:
        if urlparse(response.geturl()).scheme != "https":
            raise ValueError("config download redirected away from HTTPS")
        data = response.read()
    if not data.startswith(b"CONFIG_") and b"\nCONFIG_" not in data[:4096]:
        raise ValueError("config_url did not return a Linux .config file")
    with open(destination, "wb") as stream:
        stream.write(data)


def read_config(path):
    with open(path, encoding="utf-8", errors="replace") as stream:
        return stream.read()


def select_toolchain(record, config_path):
    architecture = record["architecture"].strip().lower()
    if architecture == "powerpc":
        config = read_config(config_path)
        if "CONFIG_CPU_LITTLE_ENDIAN=y" in config:
            toolchain = TOOLCHAINS["powerpc64le"]
        elif "CONFIG_PPC64=y" in config:
            toolchain = TOOLCHAINS["powerpc64"]
        else:
            toolchain = TOOLCHAINS["powerpc32"]
    elif architecture == "mips":
        config = read_config(config_path)
        if "CONFIG_CPU_LITTLE_ENDIAN=y" in config:
            if "CONFIG_64BIT=y" in config:
                toolchain = TOOLCHAINS["mips64el"]
            else:
                toolchain = TOOLCHAINS["mipsel"]
        elif "CONFIG_64BIT=y" in config:
            toolchain = TOOLCHAINS["mips64"]
        else:
            toolchain = TOOLCHAINS["mips"]
    else:
        try:
            toolchain = TOOLCHAINS[architecture]
        except KeyError as error:
            raise ValueError(
                f"no cross-toolchain mapping for KernelCI architecture {architecture!r}"
            ) from error

    arch, cross_compile, compiler_package = toolchain
    if "clang" in str(record.get("compiler", "")).lower():
        return arch, cross_compile, "clang", True
    return arch, cross_compile, compiler_package, False


def ensure_source(repo_url, commit, source_cache):
    require_https(repo_url, "git_repository_url")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
        raise ValueError("kernel_hash must be a full 40- or 64-character commit ID")

    if os.path.isdir(os.path.join(source_cache, ".git")):
        current_url = subprocess.check_output(
            ["git", "-C", source_cache, "remote", "get-url", "origin"],
            text=True,
        ).strip()
        if current_url != repo_url:
            raise ValueError("cached source repository URL does not match this target")
        run(["git", "-C", source_cache, "fetch", "--no-tags", "origin", commit])
    else:
        if os.path.exists(source_cache):
            shutil.rmtree(source_cache)
        os.makedirs(os.path.dirname(source_cache), exist_ok=True)
        run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                repo_url,
                source_cache,
            ]
        )
        run(["git", "-C", source_cache, "fetch", "--no-tags", "origin", commit])

    run(["git", "-C", source_cache, "cat-file", "-e", f"{commit}^{{commit}}"])


def build(record, target_key, cache_root, workspace):
    arch, cross_compile, compiler_package, use_llvm = select_toolchain(
        record, os.path.join(workspace, "kernel.config")
    )
    packages = BASE_PACKAGES + (
        ["clang", "lld", "llvm"]
        if use_llvm
        else ([compiler_package] if compiler_package else [])
    )
    run(["sudo", "apt-get", "update"])
    run(["sudo", "apt-get", "install", "-y", *packages])

    source_cache = os.path.join(cache_root, target_key)
    ensure_source(record["git_repository_url"], record["kernel_hash"], source_cache)

    source = source_cache
    run(["git", "-C", source, "checkout", "--detach", record["kernel_hash"]])

    output = os.path.join(workspace, "output")
    os.makedirs(output)
    shutil.copyfile(
        os.path.join(workspace, "kernel.config"),
        os.path.join(output, ".config"),
    )

    base_make = [
        "make",
        "-C",
        source,
        f"O={output}",
        f"ARCH={arch}",
        f"CROSS_COMPILE={cross_compile}",
        f"-j{os.cpu_count() or 2}",
    ]
    if use_llvm:
        base_make.append("LLVM=1")
    run([*base_make, "olddefconfig"])
    run([*base_make, "modules_prepare"])
    run(
        [
            *base_make,
            f"M={os.path.abspath(os.path.join(os.getcwd(), 'kmod'))}",
            "modules",
        ]
    )

    module = os.path.join(os.getcwd(), "kmod", "rwbridge.ko")
    if not os.path.isfile(module):
        raise ValueError("kernel build succeeded without producing kmod/rwbridge.ko")

    result = {
        "build_id": record["build_id"],
        "checkout_id": record["checkout_id"],
        "kernel_version": record["kernel_version"],
        "kernel_hash": record["kernel_hash"],
        "architecture": record["architecture"],
        "config_name": record["config_name"],
        "device_class": record["device_class"],
        "compiler": record.get("compiler"),
        "target_key": target_key,
        "result": "passed",
    }
    with open(os.path.join(workspace, "result.json"), "w", encoding="utf-8") as stream:
        json.dump(result, stream, separators=(",", ":"))
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--index", required=True, type=int)
    parser.add_argument("--target-key", required=True)
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()

    with open(args.manifest, encoding="utf-8") as stream:
        manifest = json.load(stream)
    try:
        record = manifest["records"][args.index]
    except (KeyError, IndexError, TypeError) as error:
        raise ValueError(f"manifest has no target at index {args.index}") from error
    expected_key = hashlib.sha256(
        "\0".join(str(record[field]) for field in (
            "kernel_hash",
            "git_repository_url",
            "kernel_branch",
            "tree_name",
            "architecture",
            "config_name",
            "device_class",
        )).encode("utf-8")
    ).hexdigest()
    if expected_key != args.target_key:
        raise ValueError("target key does not match the selected manifest row")

    os.makedirs(args.workspace, exist_ok=True)
    config_path = os.path.join(args.workspace, "kernel.config")
    download_config(record["config_url"], config_path)
    build(record, args.target_key, args.cache_root, args.workspace)
    print(f"Built rwbridge for KCIDB build {record['build_id']}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"KernelCI module build failed: {error}", file=sys.stderr)
        sys.exit(1)
