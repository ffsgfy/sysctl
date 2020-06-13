#include "mmgr.hpp"
extern "C" {
#include "winutils.h"
}

Mmgr* g_Mmgr;

Mmgr::Mmgr() {
	std::lock_guard<lock_t> lock_guard(m_lock);

	uint64_t kernel_base = 0;
	unsigned long kernel_size = 0;
	GetSystemModule("ntoskrnl.exe", (void**)&kernel_base, &kernel_size);
	if (kernel_base && kernel_size) {
		m_comms_shared.timeout = 5000;
		m_comms_shared.um.signal = 0;
		m_comms_shared.um.thread_id = (uint64_t)GetCurrentThreadId();
		m_comms_thread = std::thread(comms_init, kernel_base, kernel_size, &m_comms_shared);
	}
}

Mmgr::~Mmgr() {
	stop();
}

bool Mmgr::attach(uint32_t process_id) {
	std::lock_guard<lock_t> lock_guard(m_lock);
	
	if (m_process) {
		detach();
	}

	m_process_id = process_id;
	m_process = comms_get_process(process_id, &m_comms_shared);

	return (bool)m_process;
}

bool Mmgr::attach(const wchar_t* process_name) {
	return attach(GetProcessID(process_name));
}

void Mmgr::heartbeat() {
	comms_heartbeat(&m_comms_shared);
}

void Mmgr::detach() {
	std::lock_guard<lock_t> lock_guard(m_lock);

	if (m_process) {
		comms_dereference(m_process, &m_comms_shared);
		m_process_id = 0;
		m_process = 0;
	}
}

void Mmgr::stop() {
	std::lock_guard<lock_t> lock_guard(m_lock);

	detach();
	comms_exit(&m_comms_shared);
	if (m_comms_thread.joinable()) {
		m_comms_thread.join();
	}
}

void Mmgr::get_module(const wchar_t* module, void** module_base, size_t* module_size) {
	comms_get_module(m_process, module, module_base, module_size, &m_comms_shared);
}

void* Mmgr::find_pattern(void* start, size_t size, const char* pattern, const char* mask) {
	return comms_find_pattern(m_process, start, size, pattern, mask, &m_comms_shared);
}

void* Mmgr::find_pattern(const wchar_t* module, const char* pattern, const char* mask) {
	void* module_base = 0;
	size_t module_size = 0;

	get_module(module, &module_base, &module_size);
	if (module_base) {
		return find_pattern(module_base, module_size, pattern, mask);
	}

	return nullptr;
}

void Mmgr::mem_alloc(void** base, size_t* size, uint32_t type, uint32_t protect) {
	comms_mem_alloc(m_process, base, size, type, protect, &m_comms_shared);
}

size_t Mmgr::mem_alloc(void* base, size_t size, uint32_t type, uint32_t protect) {
	size_t mysize = size;
	mem_alloc(&base, &mysize, type, protect);
	return mysize;
}

void* Mmgr::mem_alloc(size_t size, uint32_t type, uint32_t protect) {
	void* base = nullptr;
	mem_alloc(&base, &size, type, protect);
	return base;
}

void Mmgr::mem_free(void** base, size_t* size, uint32_t type) {
	comms_mem_free(m_process, base, size, type, &m_comms_shared);
}

size_t Mmgr::mem_free(void* base, size_t size, uint32_t type) {
	size_t mysize = size;
	mem_free(&base, &mysize, type);
	return mysize;
}

bool Mmgr::replace_ptes(void* src, void* dst, size_t size, void* original) {
	return comms_replace_ptes(m_process, src, dst, size, original, &m_comms_shared);
}

std::unique_ptr<uint64_t[]> Mmgr::replace_ptes(void* src, void* dst, size_t size) {
	std::unique_ptr<uint64_t[]> original(new uint64_t[NumberOfPages((uintptr_t)src, size)]);
	if (!replace_ptes(src, dst, size, original.get())) {
		original.reset();
	}
	return original;
}

bool Mmgr::restore_ptes(void* base, size_t size, void* original) {
	return comms_restore_ptes(m_process, base, size, original, &m_comms_shared);
}

bool Mmgr::restore_ptes(void* base, size_t size, std::unique_ptr<uint64_t[]>& original) {
	return restore_ptes(base, size, original.get());
}

void* Mmgr::duplicate_handle(void* handle, uint32_t access, uint32_t options) {
	return comms_duplicate_handle(m_process, handle, access, options, &m_comms_shared);
}

void Mmgr::close_handle(void* handle) {
	comms_close_handle(m_process, handle, &m_comms_shared);
}
