#include <pmmintrin.h>
#include "comms.h"
#include "utils.h"

#define Log(...) state->Api.DbgPrintEx( 77, 0, __VA_ARGS__ )
#define RVA_TO_VA(Base, Offset) ((UINT_PTR)(Base) + (Offset))
#define BUFFER_MAX_SIZE 1048576 // 1 MB

int _fltused = 0; // lul

PVOID GetModuleExport(PVOID Module, PCHAR Symbol) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)RVA_TO_VA(Module, DosHeader->e_lfanew);

    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        DWORD ExportDirectoryRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA_TO_VA(Module, ExportDirectoryRva);

        PDWORD Names = (PDWORD)RVA_TO_VA(Module, ExportDirectory->AddressOfNames);
        PUSHORT Ordinals = (PUSHORT)RVA_TO_VA(Module, ExportDirectory->AddressOfNameOrdinals);
        PDWORD Functions = (PDWORD)RVA_TO_VA(Module, ExportDirectory->AddressOfFunctions);

        for (DWORD i = 0; i < ExportDirectory->NumberOfNames; ++i) {
            PCHAR Name = (PCHAR)RVA_TO_VA(Module, Names[i]);
            if (u_strcmp8((uint8_t*)Name, (uint8_t*)Symbol) == 0) {
                USHORT Ordinal = Ordinals[i];
                if (Ordinal < ExportDirectory->NumberOfFunctions) {
                    return (PVOID)RVA_TO_VA(Module, Functions[Ordinal]);
                } // No handling of forwarded exports :(
            }
        }
    }

    return NULL;
}

VOID ProcessAttach(comms_state_t* state, PEPROCESS Process, PKAPC_STATE ApcState) {
    if (Process) {
        state->Api.KeStackAttachProcess(Process, ApcState);
    }
}

VOID ProcessDetach(comms_state_t* state, PEPROCESS Process, PKAPC_STATE ApcState) {
    if (Process) {
        state->Api.KeUnstackDetachProcess(ApcState);
    }
}

#define ATTACH(Process, ApcState) ProcessAttach(state, (Process), (ApcState))
#define DETACH(Process, ApcState) ProcessDetach(state, (Process), (ApcState))

PVOID AllocatePool(comms_state_t* state, POOL_TYPE Type, SIZE_T Size) {
    return state->Api.ExAllocatePoolWithTag(Type, Size, 0);
}

VOID FreePool(comms_state_t* state, PVOID Ptr) {
    state->Api.ExFreePoolWithTag(Ptr, 0);
}

BOOLEAN EnsureBuffer(comms_state_t* state, SIZE_T RequiredSize) {
    if (RequiredSize > BUFFER_MAX_SIZE) {
        return FALSE;
    }

    if (RequiredSize > state->Buffer.Size) {
        if (state->Buffer.Ptr) {
            FreePool(state, state->Buffer.Ptr);
        }
        state->Buffer.Ptr = AllocatePool(state, NonPagedPool, RequiredSize);
        state->Buffer.Size = RequiredSize;
    }

    return TRUE;
}

BOOLEAN EnsureUserMode(PVOID Start, SIZE_T Size) {
    return (((UINT_PTR)Start) < MM_USER_PROBE_ADDRESS) && (((UINT_PTR)Start + Size) <= MM_USER_PROBE_ADDRESS);
}

SIZE_T NumberOfPages(ULONG_PTR Base, SIZE_T Size) {
    return ((Base + Size - 1) >> PAGE_SHIFT) - (Base >> PAGE_SHIFT) + 1;
}

// Src in target process, Dst in current process
VOID ProcessRead(comms_state_t* state, PEPROCESS Process, PVOID Src, PVOID Dst, SIZE_T Size) {
    KAPC_STATE ApcState;
    HANDLE Memory;

    if (EnsureBuffer(state, Size)) {
        if (EnsureUserMode(Src, Size) && EnsureUserMode(Dst, Size)) { // No kernel-mode r/w
            ATTACH(Process, &ApcState);
            if ((Memory = state->Api.MmSecureVirtualMemory(Src, Size, PAGE_READONLY))) {
                state->Api.RtlCopyMemory(state->Buffer.Ptr, Src, Size); // Src -> Buffer
                state->Api.MmUnsecureVirtualMemory(Memory);
            }
            DETACH(Process, &ApcState);

            if (Memory && (Memory = state->Api.MmSecureVirtualMemory(Dst, Size, PAGE_READWRITE))) {
                state->Api.RtlCopyMemory(Dst, state->Buffer.Ptr, Size); // Buffer -> Dst
                state->Api.MmUnsecureVirtualMemory(Memory);
            }
        }
    }
}

// Src in current process, Dst in target process
VOID ProcessWrite(comms_state_t* state, PEPROCESS Process, PVOID Src, PVOID Dst, SIZE_T Size) {
    KAPC_STATE ApcState;
    HANDLE Memory;

    if (EnsureBuffer(state, Size)) {
        if (EnsureUserMode(Src, Size) && EnsureUserMode(Dst, Size)) { // No kernel-mode r/w
            if ((Memory = state->Api.MmSecureVirtualMemory(Src, Size, PAGE_READONLY))) {
                state->Api.RtlCopyMemory(state->Buffer.Ptr, Src, Size); // Src -> Buffer
                state->Api.MmUnsecureVirtualMemory(Memory);
            }

            ATTACH(Process, &ApcState);
            if (Memory && (Memory = state->Api.MmSecureVirtualMemory(Dst, Size, PAGE_READWRITE))) {
                state->Api.RtlCopyMemory(Dst, state->Buffer.Ptr, Size); // Buffer -> Dst
                state->Api.MmUnsecureVirtualMemory(Memory);
            }
            DETACH(Process, &ApcState);
        }
    }
}

VOID ProcessMemAlloc(comms_state_t* state, PEPROCESS Process, PVOID* Base, PSIZE_T Size, ULONG Type, ULONG Protect) {
    KAPC_STATE ApcState;

    ATTACH(Process, &ApcState);
    state->Api.ZwAllocateVirtualMemory(NtCurrentProcess(), Base, 0, Size, Type, Protect);
    DETACH(Process, &ApcState);
}

VOID ProcessMemFree(comms_state_t* state, PEPROCESS Process, PVOID* Base, PSIZE_T Size, ULONG Type) {
    KAPC_STATE ApcState;

    ATTACH(Process, &ApcState);
    state->Api.ZwFreeVirtualMemory(NtCurrentProcess(), Base, Size, Type);
    DETACH(Process, &ApcState);
}

BOOL ReplacePtes(comms_state_t* state, PEPROCESS SrcProcess, PVOID SrcBase, PEPROCESS DstProcess, PVOID DstBase, SIZE_T Size, PVOID Original) {
    BOOL Result = FALSE;
    KAPC_STATE ApcState;
    HANDLE Memory;

    if (state->Api.MiGetPteAddress) {
        SIZE_T nPages = NumberOfPages((ULONG_PTR)SrcBase, Size);
        SIZE_T BufferSize = nPages * sizeof(MMPTE);

        if ((Memory = state->Api.MmSecureVirtualMemory(Original, BufferSize, PAGE_READWRITE))) {
            if (EnsureBuffer(state, BufferSize)) {
                MMPTE* Buffer = (MMPTE*)state->Buffer.Ptr;
                ULONG_PTR Address;
                SIZE_T Page;

                // Src -> Buffer
                ATTACH(SrcProcess, &ApcState);
                for (Page = 0, Address = (ULONG_PTR)SrcBase; Page < nPages; ++Page, Address += PAGE_SIZE) {
                    Buffer[Page] = *state->Api.MiGetPteAddress((PVOID)Address);
                }
                DETACH(SrcProcess, &ApcState);

                // Buffer <-> Dst
                ATTACH(DstProcess, &ApcState);
                for (Page = 0, Address = (ULONG_PTR)DstBase; Page < nPages; ++Page, Address += PAGE_SIZE) {
                    MMPTE* pPte = state->Api.MiGetPteAddress((PVOID)Address);
                    MMPTE Pte = *pPte;
                    // pPte->u.Hard.PageFrameNumber = Buffer[Page].u.Hard.PageFrameNumber;
                    pPte->u.Long = Buffer[Page].u.Long;
                    Buffer[Page] = Pte;
                }
                DETACH(DstProcess, &ApcState);

                // Buffer -> Original
                state->Api.RtlCopyMemory(Original, Buffer, BufferSize);

                Result = TRUE;
            }

            state->Api.MmUnsecureVirtualMemory(Memory);
        }
    }

    return Result;
}

BOOL RestorePtes(comms_state_t* state, PEPROCESS Process, PVOID Base, SIZE_T Size, PVOID Original) {
    BOOL Result = FALSE;
    KAPC_STATE ApcState;
    HANDLE Memory;

    if (state->Api.MiGetPteAddress) {
        SIZE_T nPages = NumberOfPages((ULONG_PTR)Base, Size);
        SIZE_T BufferSize = nPages * sizeof(MMPTE);

        if ((Memory = state->Api.MmSecureVirtualMemory(Original, BufferSize, PAGE_READONLY))) {
            if (EnsureBuffer(state, BufferSize)) {
                MMPTE* Buffer = (MMPTE*)state->Buffer.Ptr;
                ULONG_PTR Address;
                SIZE_T Page;

                // Original -> Buffer
                state->Api.RtlCopyMemory(Buffer, Original, BufferSize);

                // Buffer -> Base
                ATTACH(Process, &ApcState);
                for (Page = 0, Address = (ULONG_PTR)Base; Page < nPages; ++Page, Address += PAGE_SIZE) {
                    *state->Api.MiGetPteAddress((PVOID)Address) = Buffer[Page];
                }
                DETACH(Process, &ApcState);

                Result = TRUE;
            }

            state->Api.MmUnsecureVirtualMemory(Memory);
        }
    }

    return Result;
}

VOID DuplicateHandle(comms_state_t* state, PEPROCESS Process, HANDLE SrcHandle, HANDLE* DstHandle, ULONG Access, ULONG Options) {
    KAPC_STATE ApcState;
    NTSTATUS Status = -1;
    HANDLE SrcProcess = 0;
    HANDLE DstProcess = NtCurrentProcess();

    Status = state->Api.ZwDuplicateObject(NtCurrentProcess(), NtCurrentProcess(), NtCurrentProcess(), &SrcProcess, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
    if (NT_SUCCESS(Status)) {
        ATTACH(Process, &ApcState);
        state->Api.ZwDuplicateObject(SrcProcess, SrcHandle, DstProcess, DstHandle, Access, 0, Options | DUPLICATE_SAME_ATTRIBUTES);
        DETACH(Process, &ApcState);
        state->Api.ZwClose(SrcProcess);
    }
}

VOID CloseHandle(comms_state_t* state, PEPROCESS Process, HANDLE Handle) {
    KAPC_STATE ApcState;

    ATTACH(Process, &ApcState);
    state->Api.ZwClose(Handle);
    DETACH(Process, &ApcState);
}

BOOL ProcessMemLock(comms_state_t* state, PEPROCESS Process, PVOID Base, SIZE_T Size) {
    KAPC_STATE ApcState;
    NTSTATUS Status = -1;

    ATTACH(Process, &ApcState);
    Status = state->Api.ZwLockVirtualMemory(NtCurrentProcess(), &Base, &Size, MAP_PROCESS);
    DETACH(Process, &ApcState);

    return NT_SUCCESS(Status);
}

BOOL ProcessMemUnlock(comms_state_t* state, PEPROCESS Process, PVOID Base, SIZE_T Size) {
    KAPC_STATE ApcState;
    NTSTATUS Status = -1;

    ATTACH(Process, &ApcState);
    Status = state->Api.ZwUnlockVirtualMemory(NtCurrentProcess(), &Base, &Size, MAP_PROCESS);
    DETACH(Process, &ApcState);

    return NT_SUCCESS(Status);
}

ULONG_PTR DisableWriteProtect(comms_state_t* state, PGROUP_AFFINITY GroupAffinity) {
    // Get current processor
    PROCESSOR_NUMBER ProcessorNumber;
    state->Api.KeGetCurrentProcessorNumberEx(&ProcessorNumber);

    // Make sure we run on that processor only
    GROUP_AFFINITY NewGroupAffinity;
    NewGroupAffinity.Group = ProcessorNumber.Group;
    NewGroupAffinity.Mask = (KAFFINITY)1 << ProcessorNumber.Number;
    state->Api.KeSetSystemGroupAffinityThread(&NewGroupAffinity, GroupAffinity);

    ULONG_PTR Result = 0;

    __asm {
        // cli
        mov rax, cr0
        mov Result, rax
        and rax, 0xFFFFFFFFFFFEFFFF // Clear WP
        mov cr0, rax
    }

    return Result;
}

VOID RestoreWriteProtect(comms_state_t* state, ULONG_PTR _CR0, PGROUP_AFFINITY GroupAffinity) {
    __asm {
        mov rax, _CR0
        mov cr0, rax
        // sti
    }

    state->Api.KeRevertToUserGroupAffinityThread(GroupAffinity);
}

VOID ProcessForceWrite(comms_state_t* state, PEPROCESS Process, PVOID Src, PVOID Dst, SIZE_T Size) {
    KAPC_STATE ApcState;
    HANDLE Memory;

    if (EnsureBuffer(state, Size)) {
        if (EnsureUserMode(Src, Size) && EnsureUserMode(Dst, Size)) { // No kernel-mode r/w
            if ((Memory = state->Api.MmSecureVirtualMemory(Src, Size, PAGE_READONLY))) {
                state->Api.RtlCopyMemory(state->Buffer.Ptr, Src, Size); // Src -> Buffer
                state->Api.MmUnsecureVirtualMemory(Memory);
            }

            ATTACH(Process, &ApcState);
            if (Memory && (Memory = state->Api.MmSecureVirtualMemory(Dst, Size, PAGE_READONLY))) {
                GROUP_AFFINITY GroupAffinity;
                ULONG_PTR CR0 = DisableWriteProtect(state, &GroupAffinity);
                state->Api.RtlCopyMemory(Dst, state->Buffer.Ptr, Size); // Buffer -> Dst
                RestoreWriteProtect(state, CR0, &GroupAffinity);
                state->Api.MmUnsecureVirtualMemory(Memory);
            }
            DETACH(Process, &ApcState);
        }
    }
}

BOOL ProcessMemQuery(comms_state_t* state, comms_mem_info_t* info, PEPROCESS Process, PVOID Base) {
    KAPC_STATE ApcState;
    MEMORY_BASIC_INFORMATION MemInfo;
    NTSTATUS Status = -1;

    ATTACH(Process, &ApcState);
    Status = state->Api.ZwQueryVirtualMemory(NtCurrentProcess(), Base, MemoryBasicInformation, &MemInfo, sizeof(MemInfo), NULL);
    DETACH(Process, &ApcState);

    if (info && NT_SUCCESS(Status)) {
        info->base = (uint64_t)MemInfo.BaseAddress;
        info->size = MemInfo.RegionSize;
        info->state = MemInfo.State;
        info->protect = MemInfo.Protect;
        info->type = MemInfo.Type;

        return TRUE;
    }

    return FALSE;
}

ULONG ProcessMemProtect(comms_state_t* state, PEPROCESS Process, PVOID Base, SIZE_T Size, ULONG Protect) {
    KAPC_STATE ApcState;
    NTSTATUS Status = -1;

    ATTACH(Process, &ApcState);
    Status = state->Api.ZwProtectVirtualMemory(NtCurrentProcess(), &Base, &Size, Protect, &Protect);
    DETACH(Process, &ApcState);

    return NT_SUCCESS(Status) ? Protect : 0;
}

PVOID FindPattern(comms_state_t* state, PEPROCESS Process, PVOID Start, SIZE_T Size, PUCHAR Pattern, PUCHAR Mask) {
    PVOID Result = NULL;
    KAPC_STATE ApcState;
    HANDLE Memory;

    if (EnsureUserMode(Start, Size)) {
        state->Api.KeStackAttachProcess(Process, &ApcState);
        if ((Memory = state->Api.MmSecureVirtualMemory(Start, Size, PAGE_READONLY))) {
            Result = find_pattern(Start, Size, Pattern, Mask);
            state->Api.MmUnsecureVirtualMemory(Memory);
        }
        state->Api.KeUnstackDetachProcess(&ApcState);
    }

    return Result;
}

PVOID FindSectionPattern(PVOID Module, PUCHAR SectionName, PUCHAR Pattern, PUCHAR Mask) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)RVA_TO_VA(Module, DosHeader->e_lfanew);
    if (NtHeaders) {
        PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(NtHeaders);
        for (SIZE_T Pos = 0; Pos < NtHeaders->FileHeader.NumberOfSections; ++Pos) {
            PIMAGE_SECTION_HEADER Section = &Sections[Pos];
            if (u_strncmp8(Section->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
                PVOID Result = find_pattern((PVOID)RVA_TO_VA(Module, Section->VirtualAddress), Section->Misc.VirtualSize, Pattern, Mask);
                if (Result) {
                    return Result;
                }
            }
        }
    }

    return NULL;
}

VOID InitUnicodeString(PUNICODE_STRING Dst, PWCHAR Src) {
    Dst->Buffer = Src;
    Dst->Length = sizeof(WCHAR) * u_strlen16(Src);
    Dst->MaximumLength = Dst->Length + sizeof(WCHAR);
}

PVOID GetSystemRoutine(comms_state_t* state, PWCHAR RoutineName) {
    UNICODE_STRING URoutineName;
    InitUnicodeString(&URoutineName, RoutineName);
    return state->Api.MmGetSystemRoutineAddress(&URoutineName);
}

UINT32 HashSyscall(PCHAR RoutineName) {
    UINT32 Hash = 0, Step = 0;
    for (; *RoutineName; ++RoutineName) {
        Step = 1025 * (Hash + *RoutineName);
        Hash = Step ^ (Step >> 6);
    }
    return Hash;
}

PVOID GetSyscall(comms_state_t* state, UINT32 Hash) {
    PKISERVICESTAB_ENTRY Entry = (PKISERVICESTAB_ENTRY)state->Api.KiServicesTab;
    for (size_t i = 0; i < state->Api.KiServicesTabSize; ++i, ++Entry) {
        if (Entry->NameHash == Hash) {
            return Entry->SystemService;
        }
    }

    return NULL;
}

HANDLE OpenThread(comms_state_t* state, HANDLE ThreadId, ULONG DesiredAccess) {
    HANDLE ThreadHandle = 0;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;
    u_memset((uint8_t*)&ObjectAttributes, 0, sizeof(ObjectAttributes));
    ClientId.UniqueProcess = 0;
    ClientId.UniqueThread = ThreadId;
    state->Api.ZwOpenThread(&ThreadHandle, DesiredAccess, &ObjectAttributes, &ClientId);
    return ThreadHandle;
}

void comms_wait(comms_state_t* state) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER counter;

    while (!state->Exit) {
        counter = state->Api.KeQueryPerformanceCounter(&frequency);
        counter.QuadPart += -state->Shared.Ptr->Timeout * frequency.QuadPart / 10000000LL;
        
        while (!(state->Shared.Ptr->UM.Signal)) {
            state->Api.NtWaitForAlertByThreadId(&(state->Shared.Ptr->UM.Signal), &(state->Shared.Ptr->Timeout));
            if (state->Api.KeQueryPerformanceCounter(NULL).QuadPart > counter.QuadPart) {
                return;
            }
        }
        state->Shared.Ptr->UM.Signal = 0;

        comms_dispatch(state, (comms_header_t*)state->Shared.Ptr->Msg, state->Shared.Ptr->Size);

        counter = state->Api.KeQueryPerformanceCounter(&frequency);
        counter.QuadPart += -state->Shared.Ptr->Timeout * frequency.QuadPart / 10000000LL;

        state->Shared.Ptr->KM.Signal = 1;
        while (state->Shared.Ptr->KM.Signal) {
            state->Api.NtAlertThreadByThreadId((HANDLE)state->Shared.Ptr->UM.ThreadId);
            if (state->Api.KeQueryPerformanceCounter(NULL).QuadPart > counter.QuadPart) {
                return;
            }
        }
    }
}

void comms_get_process(comms_state_t* state, comms_get_process_t* msg, size_t size) {
    if (size < sizeof(comms_get_process_t)) {
        return;
    }

    state->Api.PsLookupProcessByProcessId((void*)msg->process_id, (void**)&msg->header.result);
}

void comms_dereference(comms_state_t* state, comms_dereference_t* msg, size_t size) {
    if (size < sizeof(comms_dereference_t)) {
        return;
    }

    state->Api.ObfDereferenceObject((void*)msg->object);
}

void comms_read(comms_state_t* state, comms_read_t* msg, size_t size) {
    if (size < sizeof(comms_read_t)) {
        return;
    }

    ProcessRead(state, (void*)msg->process, (void*)msg->src, (void*)msg->dst, msg->size);
}

void comms_write(comms_state_t* state, comms_write_t* msg, size_t size) {
    if (size < sizeof(comms_write_t)) {
        return;
    }

    ProcessWrite(state, (void*)msg->process, (void*)msg->src, (void*)msg->dst, msg->size);
}

void comms_find_pattern(comms_state_t* state, comms_find_pattern_t* msg, size_t size) {
    if (size < sizeof(comms_find_pattern_t)) {
        return;
    }

    comms_find_pattern_t msgkm; // to be able to access pattern and mask from a different process context
    u_memcpy((uint8_t*)&msgkm, (uint8_t*)msg, sizeof(*msg));
    msg->header.result = (uint64_t)FindPattern(state, (void*)msg->process, (void*)msg->start, msg->size, msgkm.pattern, msgkm.mask);
}

void comms_exit(comms_state_t* state) {
    state->Exit = TRUE;
}

void comms_mem_alloc(comms_state_t* state, comms_mem_alloc_t* msg, size_t size) {
    if (size < sizeof(comms_mem_alloc_t)) {
        return;
    }

    uint64_t mem_base = msg->base;
    uint64_t mem_size = msg->size;
    ProcessMemAlloc(state, (void*)msg->process, (void**)&mem_base, &mem_size, msg->type, msg->protect);
    msg->base = mem_base;
    msg->size = mem_size;
}

void comms_mem_free(comms_state_t* state, comms_mem_free_t* msg, size_t size) {
    if (size < sizeof(comms_mem_free_t)) {
        return;
    }

    uint64_t mem_base = msg->base;
    uint64_t mem_size = msg->size;
    ProcessMemFree(state, (void*)msg->process, (void**)&mem_base, &mem_size, msg->type);
    msg->base = mem_base;
    msg->size = mem_size;
}

void comms_replace_ptes(comms_state_t* state, comms_replace_ptes_t* msg, size_t size) {
    if (size < sizeof(comms_replace_ptes_t)) {
        return;
    }

    msg->header.result = (uint64_t)ReplacePtes(state, (void*)msg->src_process, (void*)msg->src_base, (void*)msg->dst_process, (void*)msg->dst_base, msg->size, (void*)msg->original);
}

void comms_restore_ptes(comms_state_t* state, comms_restore_ptes_t* msg, size_t size) {
    if (size < sizeof(comms_restore_ptes_t)) {
        return;
    }

    msg->header.result = (uint64_t)RestorePtes(state, (void*)msg->process, (void*)msg->base, msg->size, (void*)msg->original);
}

void comms_duplicate_handle(comms_state_t* state, comms_duplicate_handle_t* msg, size_t size) {
    if (size < sizeof(comms_duplicate_handle_t)) {
        return;
    }

    uint64_t dst_handle = 0;
    DuplicateHandle(state, (void*)msg->process, (void*)msg->handle, (void**)&dst_handle, msg->access, msg->options);
    msg->header.result = dst_handle;
}

void comms_close_handle(comms_state_t* state, comms_close_handle_t* msg, size_t size) {
    if (size < sizeof(comms_close_handle_t)) {
        return;
    }

    CloseHandle(state, (void*)msg->process, (void*)msg->handle);
}

void comms_mem_lock(comms_state_t* state, comms_mem_lock_t* msg, size_t size) {
    if (size < sizeof(comms_mem_lock_t)) {
        return;
    }

    msg->header.result = (uint64_t)ProcessMemLock(state, (void*)msg->process, (void*)msg->base, msg->size);
}

void comms_mem_unlock(comms_state_t* state, comms_mem_unlock_t* msg, size_t size) {
    if (size < sizeof(comms_mem_unlock_t)) {
        return;
    }

    msg->header.result = (uint64_t)ProcessMemUnlock(state, (void*)msg->process, (void*)msg->base, msg->size);
}

void comms_force_write(comms_state_t* state, comms_force_write_t* msg, size_t size) {
    if (size < sizeof(comms_force_write_t)) {
        return;
    }

    ProcessForceWrite(state, (void*)msg->process, (void*)msg->src, (void*)msg->dst, msg->size);
}

void comms_sleep(comms_state_t* state, comms_sleep_t* msg, size_t size) {
    if (size < sizeof(comms_sleep_t)) {
        return;
    }

    LARGE_INTEGER interval;

    interval.QuadPart = -(msg->interval);
    if (interval.QuadPart < state->Shared.Ptr->Timeout) {
        interval.QuadPart = state->Shared.Ptr->Timeout;
    }

    state->Api.KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

void comms_get_peb(comms_state_t* state, comms_get_peb_t* msg, size_t size) {
    if (size < sizeof(comms_get_peb_t)) {
        return;
    }

    msg->header.result = (uint64_t)state->Api.PsGetProcessPeb(msg->process ? (void*)msg->process : state->Api.IoGetCurrentProcess());
}

void comms_mem_query(comms_state_t* state, comms_mem_query_t* msg, size_t size) {
    if (size < sizeof(comms_mem_query_t)) {
        return;
    }

    msg->header.result = (uint64_t)ProcessMemQuery(state, &msg->info, (void*)msg->process, (void*)msg->base);
}

void comms_mem_protect(comms_state_t* state, comms_mem_protect_t* msg, size_t size) {
    if (size < sizeof(comms_mem_protect_t)) {
        return;
    }

    msg->header.result = (uint64_t)ProcessMemProtect(state, (void*)msg->process, (void*)msg->base, msg->size, msg->protect);
}

void comms_init(comms_init_t* msg, size_t size) {
    comms_state_t state;

    if (size < sizeof(comms_init_t)) {
        return;
    }

    if (!msg->kernel_ptr) {
        return;
    }

    state.Kernel = (void*)msg->kernel_ptr;

    state.Api.MmGetSystemRoutineAddress = GetModuleExport(state.Kernel, "MmGetSystemRoutineAddress");
    state.Api.PsLookupProcessByProcessId = GetSystemRoutine(&state, L"PsLookupProcessByProcessId");
    state.Api.ObfDereferenceObject = GetSystemRoutine(&state, L"ObfDereferenceObject");
    state.Api.KeStackAttachProcess = GetSystemRoutine(&state, L"KeStackAttachProcess");
    state.Api.KeUnstackDetachProcess = GetSystemRoutine(&state, L"KeUnstackDetachProcess");
    state.Api.PsGetProcessPeb = GetSystemRoutine(&state, L"PsGetProcessPeb");
    state.Api.IoGetCurrentProcess = GetSystemRoutine(&state, L"IoGetCurrentProcess");
    state.Api.RtlCompareUnicodeString = GetSystemRoutine(&state, L"RtlCompareUnicodeString");
    state.Api.ExAllocatePoolWithTag = GetSystemRoutine(&state, L"ExAllocatePoolWithTag");
    state.Api.ExFreePoolWithTag = GetSystemRoutine(&state, L"ExFreePoolWithTag");
    state.Api.RtlCopyMemory = GetSystemRoutine(&state, L"RtlCopyMemory");
    state.Api.MmSecureVirtualMemory = GetSystemRoutine(&state, L"MmSecureVirtualMemory");
    state.Api.MmUnsecureVirtualMemory = GetSystemRoutine(&state, L"MmUnsecureVirtualMemory");
    state.Api.DbgPrintEx = GetSystemRoutine(&state, L"DbgPrintEx");
    state.Api.MmCopyVirtualMemory = GetSystemRoutine(&state, L"MmCopyVirtualMemory");
    state.Api.ZwWaitForSingleObject = GetSystemRoutine(&state, L"ZwWaitForSingleObject");
    state.Api.ZwSetEvent = GetSystemRoutine(&state, L"ZwSetEvent");
    state.Api.ExAcquireFastMutexUnsafe = GetSystemRoutine(&state, L"ExAcquireFastMutexUnsafe");
    state.Api.ExReleaseFastMutexUnsafe = GetSystemRoutine(&state, L"ExReleaseFastMutexUnsafe");
    state.Api.ZwAllocateVirtualMemory = GetSystemRoutine(&state, L"ZwAllocateVirtualMemory");
    state.Api.ZwFreeVirtualMemory = GetSystemRoutine(&state, L"ZwFreeVirtualMemory");
    state.Api.ZwDuplicateObject = GetSystemRoutine(&state, L"ZwDuplicateObject");
    state.Api.ZwClose = GetSystemRoutine(&state, L"ZwClose");
    state.Api.KeQueryPerformanceCounter = GetSystemRoutine(&state, L"KeQueryPerformanceCounter");
    state.Api.KeEnterCriticalRegion = GetSystemRoutine(&state, L"KeEnterCriticalRegion");
    state.Api.KeLeaveCriticalRegion = GetSystemRoutine(&state, L"KeLeaveCriticalRegion");
    state.Api.ZwLockVirtualMemory = GetSystemRoutine(&state, L"ZwLockVirtualMemory");
    state.Api.ZwUnlockVirtualMemory = GetSystemRoutine(&state, L"ZwUnlockVirtualMemory");
    state.Api.KeGetCurrentProcessorNumberEx = GetSystemRoutine(&state, L"KeGetCurrentProcessorNumberEx");
    state.Api.KeSetSystemGroupAffinityThread = GetSystemRoutine(&state, L"KeSetSystemGroupAffinityThread");
    state.Api.KeRevertToUserGroupAffinityThread = GetSystemRoutine(&state, L"KeRevertToUserGroupAffinityThread");
    state.Api.IoAllocateMdl = GetSystemRoutine(&state, L"IoAllocateMdl");
    state.Api.IoFreeMdl = GetSystemRoutine(&state, L"IoFreeMdl");
    state.Api.MmMapLockedPagesSpecifyCache = GetSystemRoutine(&state, L"MmMapLockedPagesSpecifyCache");
    state.Api.MmUnmapLockedPages = GetSystemRoutine(&state, L"MmUnmapLockedPages");
    state.Api.MmProbeAndLockPages = GetSystemRoutine(&state, L"MmProbeAndLockPages");
    state.Api.MmUnlockPages = GetSystemRoutine(&state, L"MmUnlockPages");
    state.Api.KeDelayExecutionThread = GetSystemRoutine(&state, L"KeDelayExecutionThread");
    state.Api.ZwQueryVirtualMemory = GetSystemRoutine(&state, L"ZwQueryVirtualMemory");
    state.Api.ZwProtectVirtualMemory = GetSystemRoutine(&state, L"ZwProtectVirtualMemory");
    state.Api.ZwOpenThread = GetSystemRoutine(&state, L"ZwOpenThread");

    state.Api.KiServicesTab = (uint64_t*)GetModuleExport(state.Kernel, "NtImageInfo") + 3;
    state.Api.KiServicesTabSize = ((uintptr_t)GetModuleExport(state.Kernel, "NtBuildGUID") - (uintptr_t)state.Api.KiServicesTab) / sizeof(KISERVICESTAB_ENTRY);
    state.Api.NtAlertThreadByThreadId = GetSyscall(&state, HashSyscall("AlertThreadByThreadId"));
    state.Api.NtWaitForAlertByThreadId = GetSyscall(&state, HashSyscall("WaitForAlertByThreadId"));

    uint8_t* MiGetPteAddress_Pattern = (uint8_t*)"\x48\xC1\xE9\x09\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x23\xC8\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3";
    uint8_t* MiGetPteAddress_Mask = (uint8_t*)"xxxxxx????????xxxxx????????xxxx";
    state.Api.MiGetPteAddress = FindSectionPattern(state.Kernel, (uint8_t*)".text", MiGetPteAddress_Pattern, MiGetPteAddress_Mask);

    state.Buffer.Ptr = 0;
    state.Buffer.Size = 0;

    state.Exit = FALSE;

    // secure our access to the shared state
    state.Shared.Ptr = (comms_shared_t*)msg->shared;
    if (!(state.Shared.Handle = state.Api.MmSecureVirtualMemory(state.Shared.Ptr, sizeof(comms_shared_t), PAGE_READWRITE))) {
        return;
    }

    void* ExpEnvironmentLock = 0;
    void* ExpEnvironmentLockLea = 0;
    uint8_t* ExpEnvironmentLockLea_Pattern = (uint8_t*)"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xC7\x44\x24";
    uint8_t* ExpEnvironmentLockLea_Mask = (uint8_t*)"xxx????x????xxx";
    if ((ExpEnvironmentLockLea = FindSectionPattern(state.Kernel, (uint8_t*)"PAGE", ExpEnvironmentLockLea_Pattern, ExpEnvironmentLockLea_Mask))) {
        ExpEnvironmentLock = (void*)((uintptr_t)ExpEnvironmentLockLea + 7 + *(int32_t*)((uintptr_t)ExpEnvironmentLockLea + 3));
        state.Api.ExReleaseFastMutexUnsafe(ExpEnvironmentLock);
    }

    state.Api.KeLeaveCriticalRegion();

    comms_wait(&state);

    state.Api.KeEnterCriticalRegion();
    state.Api.MmUnsecureVirtualMemory(state.Shared.Handle);

    if (state.Buffer.Ptr) {
        FreePool(&state, state.Buffer.Ptr);
        state.Buffer.Ptr = 0;
        state.Buffer.Size = 0;
    }

    if (ExpEnvironmentLock) {
        state.Api.ExAcquireFastMutexUnsafe(ExpEnvironmentLock);
    }
}

// Dispatch message to its handler
// An eCommsInit message MUST be on the calling thread's (UM) stack
// Other types may be anywhere with RW protection
void comms_dispatch(comms_state_t* state, comms_header_t* header, size_t size) {
    HANDLE Memory = 0;
    
    if (size < sizeof(comms_header_t)) {
        return;
    }

    if (state) {
        if (!(Memory = state->Api.MmSecureVirtualMemory(header, size, PAGE_READWRITE))) {
            return;
        }
    }

    if (!state || header->type != eCommsInit) { // eCommsInit only permitted without a state
        switch (header->type) {
        case eCommsGetProcess: comms_get_process(state, (comms_get_process_t*)header, size); break;
        case eCommsDereference: comms_dereference(state, (comms_dereference_t*)header, size); break;
        case eCommsRead: comms_read(state, (comms_read_t*)header, size);  break;
        case eCommsWrite: comms_write(state, (comms_write_t*)header, size);  break;
        case eCommsInit: comms_init((comms_init_t*)header, size);  break; // comms_init creates its own state
        case eCommsFindPattern: comms_find_pattern(state, (comms_find_pattern_t*)header, size); break;
        case eCommsExit: comms_exit(state); break;
        case eCommsMemAlloc: comms_mem_alloc(state, (comms_mem_alloc_t*)header, size); break;
        case eCommsMemFree: comms_mem_free(state, (comms_mem_free_t*)header, size); break;
        case eCommsReplacePtes: comms_replace_ptes(state, (comms_replace_ptes_t*)header, size); break;
        case eCommsRestorePtes: comms_restore_ptes(state, (comms_restore_ptes_t*)header, size); break;
        case eCommsDuplicateHandle: comms_duplicate_handle(state, (comms_duplicate_handle_t*)header, size); break;
        case eCommsCloseHandle: comms_close_handle(state, (comms_close_handle_t*)header, size); break;
        case eCommsMemLock: comms_mem_lock(state, (comms_mem_lock_t*)header, size); break;
        case eCommsMemUnlock: comms_mem_unlock(state, (comms_mem_unlock_t*)header, size); break;
        case eCommsForceWrite: comms_force_write(state, (comms_force_write_t*)header, size); break;
        case eCommsSleep: comms_sleep(state, (comms_sleep_t*)header, size); break;
        case eCommsGetPeb: comms_get_peb(state, (comms_get_peb_t*)header, size); break;
        case eCommsMemQuery: comms_mem_query(state, (comms_mem_query_t*)header, size); break;
        case eCommsMemProtect: comms_mem_protect(state, (comms_mem_protect_t*)header, size); break;
        }
    }

    if (state) {
        state->Api.MmUnsecureVirtualMemory(Memory);
    }
}
