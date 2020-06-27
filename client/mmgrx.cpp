#include "mmgrx.hpp"
extern "C" {
#include "winutils.h"
}
#include <cstdio>

void MmgrX::iter_memory(std::function<bool(comms_mem_info_t&, void*)> callback, void* arg) {
	comms_mem_info_t info = { 0, 0, 0, 0, 0, 0 };
	for (uintptr_t base = 0; mem_query((void*)base, &info); base += info.size) {
		if (!callback(info, arg)) {
			break;
		}
	}
}

void MmgrX::iter_modules(std::function<bool(Ptr64<ldr_data_table_entry_t>, void*)> callback, void* arg) {
	ptr_t<peb_t> peb = get_peb();
	if (peb) {
		auto entry_first = peb->Ldr->InLoadOrderModuleList.Flink.as<list_entry_t>();
		auto entry = entry_first.as<ldr_data_table_entry_t>();

		while (entry && entry->InLoadOrderLinks.Flink() != entry_first()) {
			if (!callback(entry, arg)) {
				break;
			}
			else {
				entry = entry->InLoadOrderLinks.Flink.as<ldr_data_table_entry_t>();
			}
		}
	}
}

void MmgrX::get_module(const wchar_t* module, void** base, uint32_t* size) {
	struct arg_t {
		const wchar_t* module;
		void* base;
		uint32_t size;
	};

	auto callback = [](Ptr64<ldr_data_table_entry_t> entry, void* arg) {
		arg_t* myarg = (arg_t*)arg;
		size_t length = entry->BaseDllName.Length / sizeof(wchar_t);
		if (wcsncmp(myarg->module, entry->BaseDllName.Buffer.load(length), length) == 0) {
			myarg->base = entry->DllBase.raw();
			myarg->size = entry->SizeOfImage;
			return false;
		}

		return true;
	};

	if (module) {
		arg_t arg;
		arg.module = module;
		arg.base = nullptr;
		arg.size = 0;
		iter_modules(callback, &arg);
		*base = arg.base;
		*size = arg.size;
	}
}

void* MmgrX::find_pattern(const wchar_t* module, const char* pattern, const char* mask) {
	void* base = nullptr;
	uint32_t size = 0;
	get_module(module, &base, &size);
	if (base && size) {
		return Mmgr::find_pattern(base, size, pattern, mask);
	}

	return nullptr;
}
