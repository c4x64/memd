/* driver.h — MEMD Windows kernel driver (WDM) header.
 * Defines IOCTL codes, device extension, and driver entry points.
 * Targets: Windows 10/11 x64. */

#ifndef MEMD_DRIVER_H
#define MEMD_DRIVER_H

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

/* ---- device/IOCTL identifiers ---- */
#define MEMD_DEVICE_NAME  L"\\Device\\MEMD"
#define MEMD_SYMLINK_NAME L"\\DosDevices\\MEMD"
#define MEMD_POOL_TAG     'DMEM'

#define MEMD_IOCTL_BASE  0x8000
#define IOCTL_MEMD_READ_MEMORY           CTL_CODE(MEMD_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_WRITE_MEMORY          CTL_CODE(MEMD_IOCTL_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_GET_MODULE_BASE       CTL_CODE(MEMD_IOCTL_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_FIND_PROCESS          CTL_CODE(MEMD_IOCTL_BASE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_IS_PROCESS_ALIVE      CTL_CODE(MEMD_IOCTL_BASE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_HIDE_PROCESS          CTL_CODE(MEMD_IOCTL_BASE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_GIVE_ROOT             CTL_CODE(MEMD_IOCTL_BASE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_VERSION               CTL_CODE(MEMD_IOCTL_BASE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_OFFSET_UPDATE         CTL_CODE(MEMD_IOCTL_BASE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_BULK_OFFSET_UPDATE    CTL_CODE(MEMD_IOCTL_BASE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_KASLR_INFO            CTL_CODE(MEMD_IOCTL_BASE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_LIST_PROCESSES        CTL_CODE(MEMD_IOCTL_BASE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_GET_PROC_INFO         CTL_CODE(MEMD_IOCTL_BASE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_READ_PHYSICAL         CTL_CODE(MEMD_IOCTL_BASE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_WRITE_PHYSICAL        CTL_CODE(MEMD_IOCTL_BASE, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_ADDR_TRANSLATE        CTL_CODE(MEMD_IOCTL_BASE, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_PAGE_PERMS            CTL_CODE(MEMD_IOCTL_BASE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MEMD_HIDE_STATUS           CTL_CODE(MEMD_IOCTL_BASE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- command structs (must match client.h) ---- */
typedef struct _MEMD_READ_MEMORY_CMD {
    ULONG pid;
    UINT64 src_va;
    UINT64 dst_va;
    UINT64 size;
    LONG result;
} MEMD_READ_MEMORY_CMD, *PMEMD_READ_MEMORY_CMD;

typedef struct _MEMD_WRITE_MEMORY_CMD {
    ULONG pid;
    UINT64 src_va;
    UINT64 dst_va;
    UINT64 size;
    LONG result;
} MEMD_WRITE_MEMORY_CMD, *PMEMD_WRITE_MEMORY_CMD;

typedef struct _MEMD_GET_MODULE_BASE_CMD {
    ULONG pid;
    CHAR name[256];
    UINT64 base;
    ULONG vm_flag;
    LONG result;
} MEMD_GET_MODULE_BASE_CMD, *PMEMD_GET_MODULE_BASE_CMD;

typedef struct _MEMD_FIND_PROC_CMD {
    CHAR name[256];
    ULONG pid;
    LONG result;
} MEMD_FIND_PROC_CMD, *PMEMD_FIND_PROC_CMD;

typedef struct _MEMD_IS_PROC_ALIVE_CMD {
    ULONG pid;
    LONG alive;
    LONG result;
} MEMD_IS_PROC_ALIVE_CMD, *PMEMD_IS_PROC_ALIVE_CMD;

typedef struct _MEMD_HIDE_PROC_CMD {
    ULONG pid;
    LONG hide;
    LONG result;
} MEMD_HIDE_PROC_CMD, *PMEMD_HIDE_PROC_CMD;

typedef struct _MEMD_GIVE_ROOT_CMD {
    LONG result;
} MEMD_GIVE_ROOT_CMD, *PMEMD_GIVE_ROOT_CMD;

typedef struct _MEMD_VERSION_CMD {
    ULONG major;
    ULONG minor;
    ULONG patch;
    ULONG abi;
    ULONG flags;
    ULONG gen;
    LONG result;
} MEMD_VERSION_CMD, *PMEMD_VERSION_CMD;

typedef struct _MEMD_OFFSET_UPDATE_CMD {
    CHAR field_name[32];
    LONG offset;
    LONG result;
} MEMD_OFFSET_UPDATE_CMD, *PMEMD_OFFSET_UPDATE_CMD;

typedef struct _MEMD_BULK_OFFSET_UPDATE_CMD {
    ULONG count;
    struct {
        CHAR field_name[32];
        LONG offset;
    } entries[32];
    LONG result;
} MEMD_BULK_OFFSET_UPDATE_CMD, *PMEMD_BULK_OFFSET_UPDATE_CMD;

typedef struct _MEMD_KASLR_INFO_CMD {
    UINT64 kernel_base;
    UINT64 kaslr_slide;
    LONG result;
} MEMD_KASLR_INFO_CMD, *PMEMD_KASLR_INFO_CMD;

typedef struct _MEMD_LIST_PROCESSES_CMD {
    ULONG count;
    ULONG pids[256];
    LONG result;
} MEMD_LIST_PROCESSES_CMD, *PMEMD_LIST_PROCESSES_CMD;

typedef struct _MEMD_GET_PROC_INFO_CMD {
    ULONG pid;
    ULONG ppid;
    ULONG session_id;
    CHAR name[256];
    LONG result;
} MEMD_GET_PROC_INFO_CMD, *PMEMD_GET_PROC_INFO_CMD;

typedef struct _MEMD_ADDR_TRANSLATE_CMD {
    ULONG pid;
    UINT64 va;
    UINT64 pa;
    LONG result;
} MEMD_ADDR_TRANSLATE_CMD, *PMEMD_ADDR_TRANSLATE_CMD;

typedef struct _MEMD_PAGE_PERMS_CMD {
    UINT64 va;
    ULONG perms;
    LONG result;
} MEMD_PAGE_PERMS_CMD, *PMEMD_PAGE_PERMS_CMD;

typedef struct _MEMD_HIDE_STATUS_CMD {
    LONG active;
    LONG hidden_count;
    LONG result;
} MEMD_HIDE_STATUS_CMD, *PMEMD_HIDE_STATUS_CMD;

/* ---- device extension ---- */
typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT device;
    UNICODE_STRING symlink_name;
    volatile LONG hidden_count;
    volatile LONG hide_active;
    ULONG hidden_pids[256];
    ULONG hidden_pid_count;
    KSPIN_LOCK lock;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

/* ---- driver entry points ---- */
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD MemdEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL MemdEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_READ MemdEvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE MemdEvtIoWrite;

/* ---- helper functions ---- */
NTSTATUS MemdCreateDevice(WDFDEVICE device);
NTSTATUS MemdHandleIoctl(WDFREQUEST request, ULONG ioctl_code,
                         size_t in_buf_len, size_t out_buf_len);
PEPROCESS MemdGetProcessByPid(ULONG pid);
BOOLEAN MemdIsProcessAlive(ULONG pid);
NTSTATUS MemdHideProcess(ULONG pid, BOOLEAN hide);
NTSTATUS MemdGiveRoot(void);
NTSTATUS MemdGetModuleBase(ULONG pid, const char *name, PUINT64 base);
NTSTATUS MemdFindProcess(const char *name, PULONG pid);
NTSTATUS MemdReadMemory(ULONG pid, UINT64 src_va, PVOID dst, SIZE_T size);
NTSTATUS MemdWriteMemory(ULONG pid, PVOID src, UINT64 dst_va, SIZE_T size);
NTSTATUS MemdTranslateVaddr(ULONG pid, UINT64 va, PUINT64 pa);
NTSTATUS MemdGetProcessInfo(ULONG pid, PMEMD_GET_PROC_INFO_CMD info);
NTSTATUS MemdListProcesses(PMEMD_LIST_PROCESSES_CMD cmd);
NTSTATUS MemdGetPagePerms(UINT64 va, PULONG perms);

#endif /* MEMD_DRIVER_H */
/* Windows/driver.h[∂] */