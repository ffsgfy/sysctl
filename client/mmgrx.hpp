#pragma once

#include <functional>
#include "ntx.hpp"

// Extended memory manager
class MmgrX : public Mmgr {
public:
	void iter_memory(std::function<bool(comms_mem_info_t&, void*)> callback, void* arg);
	void iter_modules(std::function<bool(Ptr64<ldr_data_table_entry_t>, void*)> callback, void* arg);
	void get_module(const wchar_t* module, void** base, uint32_t* size);
	void* find_pattern(const wchar_t* module, const char* pattern, const char* mask);
};

extern MmgrX* g_MmgrX;
