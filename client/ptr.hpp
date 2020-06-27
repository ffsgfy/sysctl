#pragma once

#include <unordered_map>
#include "mmgr.hpp"
#include "conf.hpp"

extern size_t g_Nonce;

#pragma pack(push, 1)

template<typename Ptr_t, typename Val_t>
class Ptr {
private:
	using mytype = Ptr<Ptr_t, Val_t>;

public:
	Ptr(Ptr_t ptr) : m_ptr(ptr) { }
	Ptr(void* ptr) : m_ptr((Ptr_t)(uintptr_t)ptr) { }
	Ptr() = default;

	void* raw() {
		return (void*)(uintptr_t)m_ptr;
	}

	Val_t& get() {
		if (s_nonce != g_Nonce) {
			s_nonce = g_Nonce;
			s_cache.clear();
		}

		auto entry = s_cache.find(m_ptr);
		if (entry == s_cache.end()) {
			return (s_cache[m_ptr] = g_Mmgr->read<Val_t>(raw()));
		}
		else {
			return entry->second;
		}
	}

	void set(const Val_t& value) {
		g_Mmgr->write(value, raw());
	}

	void flush() {
		auto entry = s_cache.find(m_ptr);
		if (entry != s_cache.end()) {
			set(entry->second);
		}
	}

	Val_t& operator*() {
		return get();
	}

	Val_t* operator->() {
		return &get();
	}

	mytype& operator=(Ptr_t ptr) {
		m_ptr = ptr;
		return *this;
	}

	mytype& operator=(void* ptr) {
		m_ptr = (Ptr_t)(uintptr_t)ptr;
		return *this;
	}

	Ptr_t operator()() {
		return m_ptr;
	}

	template<typename T>
	mytype operator+(T rhs) {
		return mytype(m_ptr + sizeof(Val_t) * rhs);
	}

	template<typename T>
	mytype operator-(T rhs) {
		return mytype(m_ptr - sizeof(Val_t) * rhs);
	}

	operator Ptr_t() {
		return m_ptr;
	}

	operator bool() {
		return m_ptr;
	}

	template<typename T>
	Ptr<Ptr_t, T> as() {
		return Ptr<Ptr_t, T>(m_ptr);
	}

private:
	Ptr_t m_ptr;

	static std::unordered_map<Ptr_t, Val_t> s_cache;
	static size_t s_nonce;
};

template<typename Ptr_t>
class Ptr<Ptr_t, void> {
private:
	using mytype = Ptr<Ptr_t, void>;

public:
	Ptr(Ptr_t ptr) : m_ptr(ptr) { }
	Ptr(void* ptr) : m_ptr((Ptr_t)(uintptr_t)ptr) { }
	Ptr() = default;

	void* raw() {
		return (void*)(uintptr_t)m_ptr;
	}

	mytype& operator=(Ptr_t ptr) {
		m_ptr = ptr;
		return *this;
	}

	mytype& operator=(void* ptr) {
		m_ptr = (Ptr_t)(uintptr_t)ptr;
		return *this;
	}

	Ptr_t operator()() {
		return m_ptr;
	}

	template<typename T>
	mytype operator+(T rhs) {
		return mytype(m_ptr + rhs);
	}

	template<typename T>
	mytype operator-(size_t rhs) {
		return mytype(m_ptr - rhs);
	}

	operator Ptr_t() {
		return m_ptr;
	}

	operator bool() {
		return m_ptr;
	}

	template<typename T>
	Ptr<Ptr_t, T> as() {
		return Ptr<Ptr_t, T>(m_ptr);
	}

private:
	Ptr_t m_ptr;
};

template<typename Ptr_t, typename Val_t>
class ArrPtr {
private:
	using mytype = ArrPtr<Ptr_t, Val_t>;

	struct CacheEntry {
		Val_t* memory;
		size_t count;
	};

public:
	ArrPtr(Ptr_t ptr) : m_ptr(ptr) { }
	ArrPtr(void* ptr) : m_ptr((Ptr_t)(uintptr_t)ptr) { }
	ArrPtr() = default;

	void* raw() {
		return (void*)(uintptr_t)m_ptr;
	}

	// Allocate memory for n elements and read them
	Val_t* load(size_t n) {
		if (s_nonce != g_Nonce) {
			s_nonce = g_Nonce;
			for (auto& it : s_cache) {
				free(it.second.memory);
			}
			s_cache.clear();
		}

		if (n == 0) {
			return nullptr;
		}

		auto entry = s_cache.find(m_ptr);
		if (entry == s_cache.end()) {
			size_t memsize = sizeof(Val_t) * n;
			Val_t* memory = (Val_t*)malloc(memsize);

			g_Mmgr->read(raw(), memory, memsize);
			s_cache[m_ptr] = { memory, n };
			return memory;
		}
		else {
			return entry->second.memory;
		}
	}

	void unload() {
		auto entry = s_cache.find(m_ptr);
		if (entry != s_cache.end()) {
			free(entry->second.memory);
			s_cache.erase(entry);
		}
	}

	Val_t* reload(size_t n) {
		unload();
		return load(n);
	}

	Val_t* reload() {
		auto entry = s_cache.find(m_ptr);
		if (entry != s_cache.end()) {
			g_Mmgr->read(raw(), entry->second.memory, sizeof(Val_t) * entry->second.count);
			return entry->second.memory;
		}
		return nullptr;
	}

	size_t loaded() {
		auto entry = s_cache.find(m_ptr);
		if (entry != s_cache.end()) {
			return entry->second.count;
		}
		return 0;
	}

	Val_t* get() {
		auto entry = s_cache.find(m_ptr);
		if (entry != s_cache.end()) {
			return entry->second.memory;
		}
		return (Val_t*)nullptr;
	}

	Val_t& get(size_t idx) {
		return get()[idx]; // don't forget to load() to avoid *nullptr
	}

	void flush(size_t n, void* src = nullptr) {
		if (!src) {
			auto entry = s_cache.find(m_ptr);
			if (entry != s_cache.end()) {
				src = entry->second.memory;
			}
		}

		if (src) {
			g_Mmgr->write(src, raw(), sizeof(Val_t) * n);
		}
	}

	void flush() {
		auto entry = s_cache.find(m_ptr);
		if (entry != s_cache.end()) {
			flush(entry->second.count, entry->second.memory);
		}
	}

	mytype& operator=(Ptr_t ptr) {
		m_ptr = ptr;
		return *this;
	}

	mytype& operator=(void* ptr) {
		m_ptr = (Ptr_t)(uintptr_t)ptr;
		return *this;
	}

	Ptr_t operator()() {
		return m_ptr;
	}

	template<typename T>
	mytype operator+(T rhs) {
		return mytype(m_ptr + sizeof(Val_t) * rhs);
	}

	template<typename T>
	mytype operator-(T rhs) {
		return mytype(m_ptr - sizeof(Val_t) * rhs);
	}

	operator Ptr_t() {
		return m_ptr;
	}

	operator bool() {
		return m_ptr;
	}

	Val_t& operator[](size_t idx) {
		return get(idx);
	}

	template<typename T>
	ArrPtr<Ptr_t, T> as() {
		return ArrPtr<Ptr_t, T>(m_ptr);
	}

private:
	Ptr_t m_ptr;

	static std::unordered_map<Ptr_t, CacheEntry> s_cache;
	static size_t s_nonce;
};

#pragma pack(pop)

template<typename Ptr_t, typename Val_t> std::unordered_map<Ptr_t, Val_t> Ptr<Ptr_t, Val_t>::s_cache;
template<typename Ptr_t, typename Val_t> size_t Ptr<Ptr_t, Val_t>::s_nonce = 0;
template<typename Ptr_t, typename Val_t> std::unordered_map<Ptr_t, typename ArrPtr<Ptr_t, Val_t>::CacheEntry> ArrPtr<Ptr_t, Val_t>::s_cache;
template<typename Ptr_t, typename Val_t> size_t ArrPtr<Ptr_t, Val_t>::s_nonce = 0;

template<typename Val_t> using Ptr32 = Ptr<uint32_t, Val_t>;
template<typename Val_t> using Ptr64 = Ptr<uint64_t, Val_t>;
template<typename Val_t> using ArrPtr32 = ArrPtr<uint32_t, Val_t>;
template<typename Val_t> using ArrPtr64 = ArrPtr<uint64_t, Val_t>;

template<typename T> using ptr_t = Ptr<pointer_t, T>;
template<typename T> using arrptr_t = ArrPtr<pointer_t, T>;
