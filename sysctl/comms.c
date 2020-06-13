#include <pmmintrin.h>
#include "comms.h"
#include "utils.h"

#define Log(...) state->Api.DbgPrintEx( 77, 0, __VA_ARGS__ )
#define RVA_TO_VA(Base, Offset) ((UINT_PTR)(Base) + (Offset))
#define BUFFER_MAX_SIZE 1048576 // 1 MB

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

VOID GetProcessModule(comms_state_t* state, PEPROCESS Process, UINT64 Module, PVOID* ModuleBase, ULONG* ModuleSize) {
    KAPC_STATE ApcState;
    PEPROCESS CurrentProcess = state->Api.IoGetCurrentProcess();

    if (Process != CurrentProcess) {
        state->Api.KeStackAttachProcess(Process, &ApcState);
    }

    PPEB Peb = state->Api.PsGetProcessPeb(Process);
    if (Peb) {
        PLIST_ENTRY ListHead = &Peb->Ldr->InLoadOrderModuleList;
        PLIST_ENTRY ListEntry = ListHead->Flink;

        while (ListEntry && ListEntry != ListHead) {
            PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)ListEntry;
            UINT64 EntryHash = u_hash16(Entry->BaseDllName.Buffer, Entry->BaseDllName.Length / sizeof(uint16_t));

            if (EntryHash == Module) {
                if (ModuleBase) {
                    *ModuleBase = Entry->DllBase;
                }

                if (ModuleSize) {
                    *ModuleSize = Entry->SizeOfImage;
                }

                break;
            }

            ListEntry = ListEntry->Flink;
        }
    }

    if (Process != CurrentProcess) {
        state->Api.KeUnstackDetachProcess(&ApcState);
    }
}

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
            state->Api.KeStackAttachProcess(Process, &ApcState);
            if ((Memory = state->Api.MmSecureVirtualMemory(Src, Size, PAGE_READONLY))) {
                state->Api.RtlCopyMemory(state->Buffer.Ptr, Src, Size); // Src -> Buffer
                state->Api.MmUnsecureVirtualMemory(Memory);
            }
            state->Api.KeUnstackDetachProcess(&ApcState);

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

            state->Api.KeStackAttachProcess(Process, &ApcState);
            if (Memory && (Memory = state->Api.MmSecureVirtualMemory(Dst, Size, PAGE_READWRITE))) {
                state->Api.RtlCopyMemory(Dst, state->Buffer.Ptr, Size); // Buffer -> Dst
                state->Api.MmUnsecureVirtualMemory(Memory);
            }
            state->Api.KeUnstackDetachProcess(&ApcState);
        }
    }
}

VOID ProcessMemAlloc(comms_state_t* state, PEPROCESS Process, PVOID* Base, PSIZE_T Size, ULONG Type, ULONG Protect) {
    KAPC_STATE ApcState;

    state->Api.KeStackAttachProcess(Process, &ApcState);
    state->Api.ZwAllocateVirtualMemory(NtCurrentProcess(), Base, 0, Size, Type, Protect);
    state->Api.KeUnstackDetachProcess(&ApcState);
}

VOID ProcessMemFree(comms_state_t* state, PEPROCESS Process, PVOID* Base, PSIZE_T Size, ULONG Type) {
    KAPC_STATE ApcState;

    state->Api.KeStackAttachProcess(Process, &ApcState);
    state->Api.ZwFreeVirtualMemory(NtCurrentProcess(), Base, Size, Type);
    state->Api.KeUnstackDetachProcess(&ApcState);
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
                if (SrcProcess) { state->Api.KeStackAttachProcess(SrcProcess, &ApcState); }
                for (Page = 0, Address = (ULONG_PTR)SrcBase; Page < nPages; ++Page, Address += PAGE_SIZE) {
                    Buffer[Page] = *state->Api.MiGetPteAddress((PVOID)Address);
                }
                if (SrcProcess) { state->Api.KeUnstackDetachProcess(&ApcState); }

                // Buffer <-> Dst
                if (DstProcess) { state->Api.KeStackAttachProcess(DstProcess, &ApcState); }
                for (Page = 0, Address = (ULONG_PTR)DstBase; Page < nPages; ++Page, Address += PAGE_SIZE) {
                    MMPTE* pPte = state->Api.MiGetPteAddress((PVOID)Address);
                    MMPTE Pte = *pPte;
                    *pPte = Buffer[Page];
                    Buffer[Page] = Pte;
                }
                if (DstProcess) { state->Api.KeUnstackDetachProcess(&ApcState); }

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
                if (Process) { state->Api.KeStackAttachProcess(Process, &ApcState); }
                for (Page = 0, Address = (ULONG_PTR)Base; Page < nPages; ++Page, Address += PAGE_SIZE) {
                    *state->Api.MiGetPteAddress((PVOID)Address) = Buffer[Page];
                }
                if (Process) { state->Api.KeUnstackDetachProcess(&ApcState); }

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
        state->Api.KeStackAttachProcess(Process, &ApcState);
        state->Api.ZwDuplicateObject(SrcProcess, SrcHandle, DstProcess, DstHandle, Access, 0, Options | DUPLICATE_SAME_ATTRIBUTES);
        state->Api.KeUnstackDetachProcess(&ApcState);
        state->Api.ZwClose(SrcProcess);
    }
}

VOID CloseHandle(comms_state_t* state, PEPROCESS Process, HANDLE Handle) {
    KAPC_STATE ApcState;

    state->Api.KeStackAttachProcess(Process, &ApcState);
    state->Api.ZwClose(Handle);
    state->Api.KeUnstackDetachProcess(&ApcState);
}

BOOL ProcessMemLock(comms_state_t* state, PEPROCESS Process, PVOID Base, SIZE_T Size) {
    KAPC_STATE ApcState;
    NTSTATUS Status = -1;

    state->Api.KeStackAttachProcess(Process, &ApcState);
    Status = state->Api.ZwLockVirtualMemory(NtCurrentProcess(), &Base, &Size, MAP_PROCESS);
    state->Api.KeUnstackDetachProcess(&ApcState);

    return NT_SUCCESS(Status);
}

BOOL ProcessMemUnlock(comms_state_t* state, PEPROCESS Process, PVOID Base, SIZE_T Size) {
    KAPC_STATE ApcState;
    NTSTATUS Status = -1;

    state->Api.KeStackAttachProcess(Process, &ApcState);
    Status = state->Api.ZwUnlockVirtualMemory(NtCurrentProcess(), &Base, &Size, MAP_PROCESS);
    state->Api.KeUnstackDetachProcess(&ApcState);

    return NT_SUCCESS(Status);
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
    for (size_t i = 0; i < 464; ++i, ++Entry) {
        if (Entry->NameHash == Hash) {
            return Entry->SystemService;
        }
    }

    return NULL;
}

void comms_wait(comms_state_t* state) {
    while (!state->Exit) {

        LARGE_INTEGER frequency;
        LARGE_INTEGER counter = state->Api.KeQueryPerformanceCounter(&frequency);
        counter.QuadPart += state->Shared.Ptr->Timeout * frequency.QuadPart / 1000;

        /*while (!(state->Shared.Ptr->SignalUM)) {
            _mm_monitor(&(state->Shared.Ptr->SignalUM), 0, 0);
            _mm_mwait(0, 0);

            if (state->Api.KeQueryPerformanceCounter(NULL).QuadPart > counter.QuadPart) {
                return;
            }
        }*/

        /*while (!(state->Shared.Ptr->SignalUM)) {
            _mm_pause();
            _mm_mfence();

            if (state->Api.KeQueryPerformanceCounter(NULL).QuadPart > counter.QuadPart) {
                return;
            }
        }*/

        do {
            state->Api.NtWaitForAlertByThreadId(&(state->Shared.Ptr->UM.Signal), &(state->Shared.Ptr->Timeout));
            if (state->Api.KeQueryPerformanceCounter(NULL).QuadPart > counter.QuadPart) {
                return;
            }
        } while (!(state->Shared.Ptr->UM.Signal));
        state->Shared.Ptr->UM.Signal = 0;

        comms_dispatch(state, (comms_header_t*)state->Shared.Ptr->Msg, state->Shared.Ptr->Size);

        counter = state->Api.KeQueryPerformanceCounter(&frequency);
        counter.QuadPart += state->Shared.Ptr->Timeout * frequency.QuadPart / 1000;

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

void comms_get_module(comms_state_t* state, comms_get_module_t* msg, size_t size) {
    if (size < sizeof(comms_get_module_t)) {
        return;
    }

    void* module_base = 0;
    uint32_t module_size = 0;
    GetProcessModule(state, (void*)msg->process, msg->module, &module_base, &module_size);
    msg->module_base = (uint64_t)module_base;
    msg->module_size = (uint64_t)module_size;
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

    state.Api.KiServicesTab = (uint64_t*)GetModuleExport(state.Kernel, "NtImageInfo") + 3;
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
        case eCommsGetModule: comms_get_module(state, (comms_get_module_t*)header, size); break;
        case eCommsMemAlloc: comms_mem_alloc(state, (comms_mem_alloc_t*)header, size); break;
        case eCommsMemFree: comms_mem_free(state, (comms_mem_free_t*)header, size); break;
        case eCommsReplacePtes: comms_replace_ptes(state, (comms_replace_ptes_t*)header, size); break;
        case eCommsRestorePtes: comms_restore_ptes(state, (comms_restore_ptes_t*)header, size); break;
        case eCommsDuplicateHandle: comms_duplicate_handle(state, (comms_duplicate_handle_t*)header, size); break;
        case eCommsCloseHandle: comms_close_handle(state, (comms_close_handle_t*)header, size); break;
        case eCommsMemLock: comms_mem_lock(state, (comms_mem_lock_t*)header, size); break;
        case eCommsMemUnlock: comms_mem_unlock(state, (comms_mem_unlock_t*)header, size); break;
        }
    }

    if (state) {
        state->Api.MmUnsecureVirtualMemory(Memory);
    }
}
