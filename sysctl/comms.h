#pragma once

#include <stdint.h>
#include "mm.h"
#include "pe.h"

#define COMMS_PATTERN_LENGTH 31

typedef PVOID (NTAPI*MmGetSystemRoutineAddress_t)(PUNICODE_STRING SystemRoutineName);
typedef NTSTATUS (NTAPI*PsLookupProcessByProcessId_t)(HANDLE ProcessId, PEPROCESS* Process);
typedef LONG_PTR (NTAPI*ObfDereferenceObject_t)(PVOID Object);
typedef VOID (NTAPI*KeStackAttachProcess_t)(PEPROCESS PROCESS, PRKAPC_STATE ApcState);
typedef VOID (NTAPI*KeUnstackDetachProcess_t)(PRKAPC_STATE ApcState);
typedef PPEB (NTAPI*PsGetProcessPeb_t)(PEPROCESS Process);
typedef PEPROCESS (NTAPI*IoGetCurrentProcess_t)(VOID);
typedef LONG (NTAPI*RtlCompareUnicodeString_t)(PCUNICODE_STRING String1, PCUNICODE_STRING String2, BOOLEAN CaseInSensitive);
typedef PVOID (NTAPI*ExAllocatePoolWithTag_t)(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
typedef VOID (NTAPI*ExFreePoolWithTag_t)(PVOID P, ULONG Tag);
typedef VOID (__cdecl*RtlCopyMemory_t)(PVOID Dst, PVOID Src, SIZE_T Size);
typedef HANDLE (NTAPI*MmSecureVirtualMemory_t)(PVOID Address, SIZE_T Size, ULONG ProbeMode);
typedef VOID (NTAPI*MmUnsecureVirtualMemory_t)(HANDLE SecureHandle);
typedef ULONG (NTAPI*DbgPrintEx_t)(ULONG ComponentId, ULONG Level, PCSTR Format, ...);
typedef NTSTATUS (NTAPI*MmCopyVirtualMemory_t)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
typedef NTSTATUS (NTAPI*ZwWaitForSingleObject_t)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS (NTAPI*ZwSetEvent_t)(HANDLE EventHandle, PLONG PreviousState);
typedef VOID (NTAPI*ExAcquireFastMutexUnsafe_t)(PVOID FastMutex);
typedef VOID (NTAPI*ExReleaseFastMutexUnsafe_t)(PVOID FastMutex);
typedef NTSTATUS (NTAPI*ZwAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (NTAPI*ZwFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS (NTAPI*ZwDuplicateObject_t)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, HANDLE* TargetHandle, ULONG DesiredAccess, ULONG HandleAttributes, ULONG Options);
typedef NTSTATUS (NTAPI*ZwClose_t)(HANDLE Handle);
typedef LARGE_INTEGER (NTAPI*KeQueryPerformanceCounter_t)(PLARGE_INTEGER PerformanceFrequency);
typedef VOID (NTAPI*KeEnterCriticalRegion_t)(VOID);
typedef VOID (NTAPI* KeLeaveCriticalRegion_t)(VOID);

typedef PMMPTE (NTAPI*MiGetPteAddress_t)(PVOID Address);
typedef NTSTATUS (NTAPI*ZwAlertThreadByThreadId_t)(HANDLE ThreadId);
typedef NTSTATUS (NTAPI*ZwWaitForAlertByThreadId_t)(PVOID Address, UINT64* Milliseconds);

typedef struct {
    uint64_t Msg; // pointer to comms_header_t
    uint64_t Size; // msg size
    uint64_t Timeout; // milliseconds

    struct {
        uint64_t Signal;
        uint64_t ThreadId;
    } UM;

    struct {
        uint64_t Signal;
        uint64_t ThreadId;
    } KM;
} comms_shared_t;

typedef struct {
    PVOID Kernel;

    struct {
        comms_shared_t* Ptr;
        HANDLE Handle;
    } Shared;
    
    struct {
        MmGetSystemRoutineAddress_t MmGetSystemRoutineAddress;
        PsLookupProcessByProcessId_t PsLookupProcessByProcessId;
        ObfDereferenceObject_t ObfDereferenceObject;
        KeStackAttachProcess_t KeStackAttachProcess;
        KeUnstackDetachProcess_t KeUnstackDetachProcess;
        PsGetProcessPeb_t PsGetProcessPeb;
        IoGetCurrentProcess_t IoGetCurrentProcess;
        RtlCompareUnicodeString_t RtlCompareUnicodeString;
        ExAllocatePoolWithTag_t ExAllocatePoolWithTag;
        ExFreePoolWithTag_t ExFreePoolWithTag;
        RtlCopyMemory_t RtlCopyMemory;
        MmSecureVirtualMemory_t MmSecureVirtualMemory;
        MmUnsecureVirtualMemory_t MmUnsecureVirtualMemory;
        DbgPrintEx_t DbgPrintEx;
        MmCopyVirtualMemory_t MmCopyVirtualMemory;
        ZwWaitForSingleObject_t ZwWaitForSingleObject;
        ZwSetEvent_t ZwSetEvent;
        ExAcquireFastMutexUnsafe_t ExAcquireFastMutexUnsafe;
        ExReleaseFastMutexUnsafe_t ExReleaseFastMutexUnsafe;
        ZwAllocateVirtualMemory_t ZwAllocateVirtualMemory;
        ZwFreeVirtualMemory_t ZwFreeVirtualMemory;
        ZwDuplicateObject_t ZwDuplicateObject;
        ZwClose_t ZwClose;
        KeQueryPerformanceCounter_t KeQueryPerformanceCounter;
        KeEnterCriticalRegion_t KeEnterCriticalRegion;
        KeLeaveCriticalRegion_t KeLeaveCriticalRegion;

        void* KiServicesTab;
        ZwAlertThreadByThreadId_t ZwAlertThreadByThreadId;
        ZwWaitForAlertByThreadId_t ZwWaitForAlertByThreadId;

        MiGetPteAddress_t MiGetPteAddress;
    } Api;

    struct {
        PVOID Ptr;
        SIZE_T Size;
    } Buffer;

    BOOLEAN Exit;
} comms_state_t;

enum {
    eCommsGetProcess,
    eCommsDereference,
    eCommsRead,
    eCommsWrite,
    eCommsInit,
    eCommsFindPattern,
    eCommsExit,
    eCommsHeartbeat,
    eCommsGetModule,
    eCommsMemAlloc,
    eCommsMemFree,
    eCommsReplacePtes,
    eCommsRestorePtes,
    eCommsDuplicateHandle,
    eCommsCloseHandle,

    eCommsEnumSize
};

typedef struct {
    uint64_t type;
    uint64_t result;
} comms_header_t;

typedef struct {
    comms_header_t header;
    uint64_t process_id;
} comms_get_process_t;

typedef struct {
    comms_header_t header;
    uint64_t object;
} comms_dereference_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t src;
    uint64_t dst;
    uint64_t size;
} comms_read_t, comms_write_t;

typedef struct {
    comms_header_t header;
    uint64_t kernel_ptr;
    uint64_t kernel_size;
    uint64_t shared;
} comms_init_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t start;
    uint64_t size;
    uint8_t pattern[COMMS_PATTERN_LENGTH + 1];
    uint8_t mask[COMMS_PATTERN_LENGTH + 1];
} comms_find_pattern_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t module; // djb2 hash of base dll name
    uint64_t module_base;
    uint64_t module_size;
} comms_get_module_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t base;
    uint64_t size;
    uint32_t type;
    uint32_t protect;
} comms_mem_alloc_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t base;
    uint64_t size;
    uint32_t type;
    uint32_t pad;
} comms_mem_free_t;

typedef struct {
    comms_header_t header;
    uint64_t src_process;
    uint64_t src_base; // page-aligned
    uint64_t dst_process;
    uint64_t dst_base; // page-aligned
    uint64_t size;
    uint64_t original; // pointer to buffer in current process
} comms_replace_ptes_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t base; // page-aligned
    uint64_t size;
    uint64_t original; // pointer to buffer in current process
} comms_restore_ptes_t;

typedef struct {
    comms_header_t header;
    uint64_t process; // target
    uint64_t handle;
    uint32_t access;
    uint32_t options;
} comms_duplicate_handle_t;

typedef struct {
    comms_header_t header;
    uint64_t process; // target
    uint64_t handle;
} comms_close_handle_t;

void comms_dispatch(comms_state_t* state, comms_header_t* header, size_t size);
