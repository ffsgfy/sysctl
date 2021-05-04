#include "comms.h"
#include "winutils.h"

GUID g_comms_guid = { 0xCC6A5BCD, 0xEC9A, 0x4641, { 0x95, 0x86, 0x5A, 0x32, 0x10, 0xC1, 0x7F, 0x4D } };
UNICODE_STRING g_comms_name = RTL_CONSTANT_STRING(L"tPyNcCxOrSEg");
// bool g_comms_ready = false;
bool g_comms_started = false;
bool g_comms_stopped = false;

void comms_dispatch(comms_header_t* msg, size_t size, comms_shared_t* shared) {
    shared->msg = (uint64_t)msg;
    shared->size = (uint64_t)size;
    _mm_mfence();

    while (!g_comms_started) {
        Sleep(1);
    }

    shared->um.signal = 1;
    while (!g_comms_stopped && shared->um.signal) {
        NtAlertThreadByThreadId((HANDLE)shared->km.thread_id);
    }

    while (!g_comms_stopped && !(shared->km.signal)) {
        NtWaitForAlertByThreadId(&(shared->km.signal), 0);
    }
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

    // g_comms_ready = true;
    g_comms_started = true;
    NtSetSystemEnvironmentValueEx(&g_comms_name, &g_comms_guid, &msg, sizeof(msg), 1);
    // g_comms_ready = false;
    g_comms_stopped = true;
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

bool comms_replace_ptes(uint64_t src_process, void* src_base, uint64_t dst_process, void* dst_base, size_t size, void* original, comms_shared_t* shared) {
    comms_replace_ptes_t msg = { { eCommsReplacePtes, 0 }, src_process, (uint64_t)src_base, dst_process, (uint64_t)dst_base, (uint64_t)size, (uint64_t)original };
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

bool comms_mem_lock(uint64_t process, void* base, size_t size, comms_shared_t* shared) {
    comms_mem_lock_t msg = { { eCommsMemLock, 0 }, process, (uint64_t)(uintptr_t)base, (uint64_t)size };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return (bool)msg.header.result;
}

bool comms_mem_unlock(uint64_t process, void* base, size_t size, comms_shared_t* shared) {
    comms_mem_unlock_t msg = { { eCommsMemUnlock, 0 }, process, (uint64_t)(uintptr_t)base, (uint64_t)size };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return (bool)msg.header.result;
}

void comms_force_write(uint64_t process, void* src, void* dst, size_t size, comms_shared_t* shared) {
    comms_write_t msg = { { eCommsForceWrite, 0 }, process, (uint64_t)src, (uint64_t)(uintptr_t)dst, (uint64_t)size };
    comms_dispatch(&msg.header, sizeof(msg), shared);
}

void comms_sleep(uint64_t interval, comms_shared_t* shared) {
    comms_sleep_t msg = { { eCommsSleep, 0 }, interval };
    comms_dispatch(&msg.header, sizeof(msg), shared);
}

void* comms_get_peb(uint64_t process, comms_shared_t* shared) {
    comms_get_peb_t msg = { { eCommsGetPeb, 0 }, process };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return (void*)(uintptr_t)msg.header.result;
}

bool comms_mem_query(uint64_t process, void* base, comms_mem_info_t* info, comms_shared_t* shared) {
    comms_mem_query_t msg = { { eCommsMemQuery, 0 }, *info, process, (uint64_t)(uintptr_t)base };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    *info = msg.info;
    return (bool)msg.header.result;
}

uint32_t comms_mem_protect(uint64_t process, void* base, size_t size, uint32_t protect, comms_shared_t* shared) {
    comms_mem_protect_t msg = { { eCommsMemProtect, 0 }, process, (uint64_t)(uintptr_t)base, (uint64_t)size, (uint64_t)protect };
    comms_dispatch(&msg.header, sizeof(msg), shared);
    return (uint32_t)msg.header.result;
}
