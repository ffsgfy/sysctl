#include "mmgr.hpp"
extern "C" {
#include "winutils.h"
}

Mmgr* g_Mmgr = nullptr;

Mmgr::Mmgr() {
	std::lock_guard<lock_t> lock_guard(m_lock);

	uint64_t kernel_base = 0;
	unsigned long kernel_size = 0;
	GetSystemModule("ntoskrnl.exe", (void**)&kernel_base, &kernel_size);
	if (kernel_base && kernel_size) {
		m_comms_shared.timeout = 10000; // milliseconds
		m_comms_shared.timeout *= -10000;
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

void Mmgr::sleep(uint64_t interval) {
	comms_sleep(interval, &m_comms_shared);
}

void* Mmgr::find_pattern(void* start, size_t size, const char* pattern, const char* mask) {
	return comms_find_pattern(m_process, start, size, pattern, mask, &m_comms_shared);
}

void* Mmgr::get_peb() {
	return comms_get_peb(m_process, &m_comms_shared);
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

bool Mmgr::mem_lock(void* base, size_t size) {
	return comms_mem_lock(m_process, base, size, &m_comms_shared);
}

bool Mmgr::mem_unlock(void* base, size_t size) {
	return comms_mem_unlock(m_process, base, size, &m_comms_shared);
}

bool Mmgr::mem_query(void* base, comms_mem_info_t* info) {
	return comms_mem_query(m_process, base, info, &m_comms_shared);
}

bool Mmgr::replace_ptes(uint64_t src_process, void* src_base, uint64_t dst_process, void* dst_base, size_t size, void* original) {
	return comms_replace_ptes(src_process, src_base, dst_process, dst_base, size, original, &m_comms_shared);
}

std::unique_ptr<uint64_t[]> Mmgr::replace_ptes(uint64_t src_process, void* src_base, uint64_t dst_process, void* dst_base, size_t size) {
	std::unique_ptr<uint64_t[]> original(new uint64_t[NumberOfPages((uintptr_t)src_base, size)]);
	if (!replace_ptes(src_process, src_base, dst_process, dst_base, size, original.get())) {
		original.reset();
	}

	return original;
}

std::unique_ptr<uint64_t[]> Mmgr::give_ptes(void* src, void* dst, size_t size) {
	return replace_ptes(0, src, m_process, dst, size);
}

std::unique_ptr<uint64_t[]> Mmgr::take_ptes(void* src, void* dst, size_t size) {
	return replace_ptes(m_process, src, 0, dst, size);
}

bool Mmgr::restore_ptes(void* base, size_t size, void* original, bool self) {
	return comms_restore_ptes((self ? 0 : m_process), base, size, original, &m_comms_shared);
}

bool Mmgr::restore_ptes(void* base, size_t size, std::unique_ptr<uint64_t[]>& original, bool free_original, bool self) {
	if (restore_ptes(base, size, original.get(), self)) {
		if (free_original) {
			original.reset();
		}

		return true;
	}

	return false;
}

void* Mmgr::duplicate_handle(void* handle, uint32_t access, uint32_t options) {
	return comms_duplicate_handle(m_process, handle, access, options, &m_comms_shared);
}

void Mmgr::close_handle(void* handle) {
	comms_close_handle(m_process, handle, &m_comms_shared);
}
