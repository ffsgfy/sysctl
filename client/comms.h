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
    eCommsGetModule,
    eCommsMemAlloc,
    eCommsMemFree,
    eCommsReplacePtes,
    eCommsRestorePtes,
    eCommsDuplicateHandle,
    eCommsCloseHandle
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
    uint64_t msg_ptr;
    uint64_t msg_size;
    uint64_t event_um;
    uint64_t event_km;
    uint64_t timeout; // in milliseconds
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
    uint64_t process;
    uint64_t src;
    uint64_t dst;
    uint64_t size;
    uint64_t original; // pointer to buffer
} comms_replace_ptes_t;

typedef struct {
    comms_header_t header;
    uint64_t process;
    uint64_t base;
    uint64_t size;
    uint64_t original; // pointer to buffer
} comms_restore_ptes_t;

typedef struct {
    uint64_t msg;
    uint64_t size;
    void* event_um;
    void* event_km;
    uint64_t timeout; // in milliseconds
} comms_state_t;

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

void comms_dispatch(comms_header_t* msg, size_t size, comms_state_t* state);
uint64_t comms_get_process(uint32_t process_id, comms_state_t* state);
void comms_dereference(uint64_t object, comms_state_t* state);
void comms_read(uint64_t process, void* src, void* dst, size_t size, comms_state_t* state);
void comms_write(uint64_t process, void* src, void* dst, size_t size, comms_state_t* state);
void comms_init(uint64_t kernel_ptr, size_t kernel_size, comms_state_t* state);
void* comms_find_pattern(uint64_t process, void* start, size_t size, const char* pattern, const char* mask, comms_state_t* state);
void comms_exit(comms_state_t* state);
void comms_heartbeat(comms_state_t* state);
void comms_get_module(uint64_t process, const wchar_t* module, void** module_base, size_t* module_size, comms_state_t* state);
void comms_mem_alloc(uint64_t process, void** base, size_t* size, uint32_t type, uint32_t protect, comms_state_t* state);
void comms_mem_free(uint64_t process, void** base, size_t* size, uint32_t type, comms_state_t* state);
bool comms_replace_ptes(uint64_t process, void* src, void* dst, size_t size, void* original, comms_state_t* state);
bool comms_restore_ptes(uint64_t process, void* base, size_t size, void* original, comms_state_t* state);
void* comms_duplicate_handle(uint64_t process, void* handle, uint32_t access, uint32_t options, comms_state_t* state);
void comms_close_handle(uint64_t process, void* handle, comms_state_t* state);
