#pragma once

#include <mutex>
#include <thread>
#include <memory>
extern "C" {
#include "comms.h"
}

class Mmgr {
private:
	using lock_t = typename std::recursive_mutex;

public:
	Mmgr();
	~Mmgr();

	uint32_t get_process_id() const { return m_process_id; }
	uint64_t get_process() const { return m_process; }

	bool attach(uint32_t process_id);
	bool attach(const wchar_t* process_name);
	void heartbeat();
	void detach();
	void stop(); // this invalidates the object

	template<typename T>
	T read(void* src) {
		T dst;
		comms_read(m_process, src, &dst, sizeof(T), &m_comms_shared);
		return dst;
	}

	template<typename T>
	void read(void* src, T& dst) {
		comms_read(m_process, src, &dst, sizeof(T), &m_comms_shared);
	}

	void read(void* src, void* dst, size_t size) {
		comms_read(m_process, src, dst, size, &m_comms_shared);
	}

	template<typename T>
	void write(const T& src, void* dst) {
		comms_write(m_process, (void*)&src, dst, sizeof(T), &m_comms_shared);
	}

	void write(const void* src, void* dst, size_t size) {
		comms_write(m_process, (void*)src, dst, size, &m_comms_shared);
	}

	void get_module(const wchar_t* module, void** module_base, size_t* module_size);
	void* find_pattern(void* start, size_t size, const char* pattern, const char* mask);
	void* find_pattern(const wchar_t* module, const char* pattern, const char* mask);
	
	void mem_alloc(void** base, size_t* size, uint32_t type, uint32_t protect);
	size_t mem_alloc(void* base, size_t size, uint32_t type, uint32_t protect);
	void* mem_alloc(size_t size, uint32_t type, uint32_t protect);
	void mem_free(void** base, size_t* size, uint32_t type);
	size_t mem_free(void* base, size_t size, uint32_t type);
	bool mem_lock(void* base, size_t size);
	bool mem_unlock(void* base, size_t size);
	
	bool replace_ptes(uint64_t src_process, void* src_base, uint64_t dst_process, void* dst_base, size_t size, void* original);
	std::unique_ptr<uint64_t[]> replace_ptes(uint64_t src_process, void* src_base, uint64_t dst_process, void* dst_base, size_t size);
	std::unique_ptr<uint64_t[]> give_ptes(void* src, void* dst, size_t size);
	std::unique_ptr<uint64_t[]> take_ptes(void* src, void* dst, size_t size);
	bool restore_ptes(void* base, size_t size, void* original, bool self = false);
	bool restore_ptes(void* base, size_t size, std::unique_ptr<uint64_t[]>& original, bool free_original = false, bool self = false);

	void* duplicate_handle(void* handle, uint32_t access, uint32_t options);
	void close_handle(void* handle);

private:
	comms_shared_t m_comms_shared;
	std::thread m_comms_thread;

	uint32_t m_process_id = 0;
	uint64_t m_process = 0;
	lock_t m_lock;
};

extern Mmgr* g_Mmgr;
