# memd eBPF backend

Minimal eBPF replacement for the `.ko` dependency on Android when the
running kernel exposes BTF (`/sys/kernel/btf/vmlinux`).

## Build

```
./gen_vmlinux.sh          # /sys/kernel/btf/vmlinux -> vmlinux.h
./build.sh                # produces memd_ebpf.bpf.o + memd_ebpf
```

Or `make`.

## Operations

The single `SEC("syscall")` program `memd_ebpf_dispatch` handles:

- `KREAD` / `UREAD` / `KREAD_STR` / `UREAD_STR`
- `UWRITE` / `MEMSET_USER`
- `TASK_READ` (current process only)
- `OFFSET` (struct field offset via CO-RE + cached in `memd_offset_map`)
- `CRC32` / `STRLEN_USER`
- `PING`

Kernel-memory writes are deliberately not exposed (no safe primitive).

## Notes

- Requires libbpf, libelf, zlib on the build host.
- `vmlinux.h` is generated from the exact running kernel's BTF, so
  struct layouts match CO-RE relocations.