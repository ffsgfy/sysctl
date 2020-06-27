#pragma once

#include <stdint.h>
#include <stdbool.h>

#define COMMS_PATTERN_LENGTH 31

enum {
    eCommsGetProcess,
    eCommsDereference,
    eCommsRead,
    eCommsWrite,
    eCommsInit,
    eCommsFindPattern,
    eCommsExit,
    eCommsHeartbeat,
    eCommsMemAlloc,
    eCommsMemFree,
    eCommsReplacePtes,
    eCommsRestorePtes,
    eCommsDuplicateHandle,
    eCommsCloseHandle,
    eCommsMemLock,
    eCommsMemUnlock,
    eCommsForceWrite,
    eCommsSleep,
    eCommsGetPeb,
    eCommsMemQuery,

    eCommsEnumSize
};

typedef struct {
    uint64_t msg; // pointer to comms_header_t
    uint64_t size; // msg size
    int64_t timeout; // units of -0.1 microseconds

    struct {
        uint64_t signal;
        uint64_t thread_id;
    } um;

    struct {
        uint64_t signal;
        uint64_t thread_id;
    } km;
} comms_shared_t;

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
} comms_read_t, comms_write_t, comms_force_write_t;

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

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t base;
    uint64_t size;
} comms_mem_lock_t, comms_mem_unlock_t;

typedef struct {
    comms_header_t header;
    uint64_t interval; // units of 0.1 microseconds
} comms_sleep_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
} comms_get_peb_t;

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
    uint32_t pad;
} comms_mem_info_t;

typedef struct {
    comms_header_t header;
    comms_mem_info_t info;
    uint64_t process;
    uint64_t base;
} comms_mem_query_t;

void comms_dispatch(comms_header_t* msg, size_t size, comms_shared_t* shared);
uint64_t comms_get_process(uint32_t process_id, comms_shared_t* shared);
void comms_dereference(uint64_t object, comms_shared_t* shared);
void comms_read(uint64_t process, void* src, void* dst, size_t size, comms_shared_t* shared);
void comms_write(uint64_t process, void* src, void* dst, size_t size, comms_shared_t* shared);
void comms_init(uint64_t kernel_ptr, size_t kernel_size, comms_shared_t* shared);
void* comms_find_pattern(uint64_t process, void* start, size_t size, const char* pattern, const char* mask, comms_shared_t* shared);
void comms_exit(comms_shared_t* shared);
void comms_heartbeat(comms_shared_t* shared);
void comms_mem_alloc(uint64_t process, void** base, size_t* size, uint32_t type, uint32_t protect, comms_shared_t* shared);
void comms_mem_free(uint64_t process, void** base, size_t* size, uint32_t type, comms_shared_t* shared);
bool comms_replace_ptes(uint64_t src_process, void* src_base, uint64_t dst_process, void* dst_base, size_t size, void* original, comms_shared_t* shared);
bool comms_restore_ptes(uint64_t process, void* base, size_t size, void* original, comms_shared_t* shared);
void* comms_duplicate_handle(uint64_t process, void* handle, uint32_t access, uint32_t options, comms_shared_t* shared);
void comms_close_handle(uint64_t process, void* handle, comms_shared_t* shared);
bool comms_mem_lock(uint64_t process, void* base, size_t size, comms_shared_t* shared);
bool comms_mem_unlock(uint64_t process, void* base, size_t size, comms_shared_t* shared);
void comms_force_write(uint64_t process, void* src, void* dst, size_t size, comms_shared_t* shared);
void comms_sleep(uint64_t interval, comms_shared_t* shared);
void* comms_get_peb(uint64_t process, comms_shared_t* shared);
bool comms_mem_query(uint64_t process, void* base, comms_mem_info_t* info, comms_shared_t* shared);
