#include "comms.h"
#include "winutils.h"

GUID g_comms_guid = { 0xCC6A5BCD, 0xEC9A, 0x4641, { 0x95, 0x86, 0x5A, 0x32, 0x10, 0xC1, 0x7F, 0x4D } };
UNICODE_STRING g_comms_name = RTL_CONSTANT_STRING(L"tPyNcCxOrSEg");
bool g_comms_ready = false;

void comms_dispatch(comms_header_t* msg, size_t size, comms_shared_t* shared) {
    shared->msg = (uint64_t)msg;
    shared->size = (uint64_t)size;
    _mm_mfence();

    while (!g_comms_ready) {
        Sleep(1);
    }

    shared->um.signal = 1;
    while (shared->um.signal) {
        NtAlertThreadByThreadId((HANDLE)shared->km.thread_id);
    }

    do {
        NtWaitForAlertByThreadId(&(shared->km.signal), INFINITE);
    } while (!(shared->km.signal));
    shared->km.signal = 0;
}

uint64_t comms_get_process(uint32_t process_id, comms_shared_t* shared) {
    comms_get_process_t msg = { { eCommsGetProcess, 0 }, (uint64_t)process_id };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return msg.header.result;
}

void comms_dereference(uint64_t object, comms_shared_t* shared) {
    comms_dereference_t msg = { { eCommsDereference, 0 }, object };
    comms_dispatch(&msg.header, sizeof(msg), shared);
}

void comms_read(uint64_t process, void* src, void* dst, size_t size, comms_shared_t* shared) {
    comms_read_t msg = { { eCommsRead, 0 }, process, (uint64_t)src, (uint64_t)dst, (uint64_t)size };
    comms_dispatch(&msg.header, sizeof(msg), shared);
}

void comms_write(uint64_t process, void* src, void* dst, size_t size, comms_shared_t* shared) {
    comms_write_t msg = { { eCommsWrite, 0 }, process, (uint64_t)src, (uint64_t)dst, (uint64_t)size };
    comms_dispatch(&msg.header, sizeof(msg), shared);
}

void comms_init(uint64_t kernel_ptr, size_t kernel_size, comms_shared_t* shared) {
    comms_init_t msg = {
        { eCommsInit, 0 },
        (uint64_t)kernel_ptr,
        (uint64_t)kernel_size,
        (uint64_t)shared
    };

    shared->km.signal = 0;
    shared->km.thread_id = (uint64_t)GetCurrentThreadId();

    g_comms_ready = true;
    NtSetSystemEnvironmentValueEx(&g_comms_name, &g_comms_guid, &msg, sizeof(msg), 1);
    g_comms_ready = false;
}

void* comms_find_pattern(uint64_t process, void* start, size_t size, const char* pattern, const char* mask, comms_shared_t* shared) {
    comms_find_pattern_t msg = { { eCommsFindPattern, 0 }, process, (uint64_t)start, (uint64_t)size };

    size_t length = strlen(mask);
    if (length <= COMMS_PATTERN_LENGTH) {
        memset(msg.pattern, 0, sizeof(msg.pattern));
        memset(msg.mask, 0, sizeof(msg.mask));
        memcpy(msg.pattern, pattern, length);
        memcpy(msg.mask, mask, length);
        comms_dispatch(&msg.header, sizeof(msg), shared);
    }

    return (void*)msg.header.result;
}

void comms_exit(comms_shared_t* shared) {
    comms_header_t msg = { eCommsExit, 0 };
    comms_dispatch(&msg, sizeof(msg), shared);
}

void comms_heartbeat(comms_shared_t* shared) {
    comms_header_t msg = { eCommsHeartbeat, 0 };
    comms_dispatch(&msg, sizeof(msg), shared);
}

void comms_get_module(uint64_t process, const wchar_t* module, void** module_base, size_t* module_size, comms_shared_t* shared) {
    comms_get_module_t msg = { { eCommsGetModule, 0 }, process, u_hash16(module, wcslen(module)), 0, 0 };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    *module_base = (void*)(uintptr_t)msg.module_base;
    *module_size = (size_t)msg.module_size;
}

void comms_mem_alloc(uint64_t process, void** base, size_t* size, uint32_t type, uint32_t protect, comms_shared_t* shared) {
    comms_mem_alloc_t msg = { { eCommsMemAlloc, 0 }, process, (uint64_t)*base, (uint64_t)*size, type, protect };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    *base = (void*)(uintptr_t)msg.base;
    *size = msg.size;
}

void comms_mem_free(uint64_t process, void** base, size_t* size, uint32_t type, comms_shared_t* shared) {
    comms_mem_free_t msg = { { eCommsMemFree, 0 }, process, (uint64_t)*base, (uint64_t)*size, type, 0 };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    *base = (void*)(uintptr_t)msg.base;
    *size = msg.size;
}

bool comms_replace_ptes(uint64_t process, void* src, void* dst, size_t size, void* original, comms_shared_t* shared) {
    comms_replace_ptes_t msg = { { eCommsReplacePtes, 0 }, process, (uint64_t)src, (uint64_t)dst, (uint64_t)size, (uint64_t)original };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return (bool)msg.header.result;
}

bool comms_restore_ptes(uint64_t process, void* base, size_t size, void* original, comms_shared_t* shared) {
    comms_replace_ptes_t msg = { { eCommsRestorePtes, 0 }, process, (uint64_t)base, (uint64_t)size, (uint64_t)original };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return (bool)msg.header.result;
}

void* comms_duplicate_handle(uint64_t process, void* handle, uint32_t access, uint32_t options, comms_shared_t* shared) {
    comms_duplicate_handle_t msg = { { eCommsDuplicateHandle, 0 }, process, (uint64_t)(uintptr_t)handle, access, options };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return (void*)(uintptr_t)msg.header.result;
}

void comms_close_handle(uint64_t process, void* handle, comms_shared_t* shared) {
    comms_duplicate_handle_t msg = { { eCommsCloseHandle, 0 }, process, (uint64_t)(uintptr_t)handle };
    comms_dispatch(&msg.header, sizeof(msg), shared);
}
