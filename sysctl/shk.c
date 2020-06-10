#include "shk.h"
#include "utils.h"
#include "lend/ld32.h"

size_t g_shk_sizes[eShkTypeSize] = { 5, 6 + sizeof(void*), 7 + sizeof(void*), 12 + sizeof(void*), 12 + sizeof(void*) };

int32_t shk_get_offset(void* src, void* dst) {
	return (int32_t)((uintptr_t)dst - (uintptr_t)src);
}

// Get the actual number of bytes replaced in func_old
size_t shk_get_size(shk_hook_t* hook) {
	return hook->mem.size - (hook->mem.trampoline ? g_shk_sizes[hook->mem.trampoline_type] : 0);
}

size_t shk_disasm(void* func, size_t minsize) {
	size_t size = 0;
	while (size < minsize) {
		size += length_disasm((uint8_t*)func + size);
	}
	return size;
}

void shk_hook_init(shk_hook_t* hook, void* func_old, void* func_new, shk_type_t type, bool trampoline, shk_type_t trampoline_type) {
	hook->func_old = func_old;
	hook->func_new = func_new;
	hook->type = type;
	hook->mem.trampoline = trampoline;
	hook->mem.trampoline_type = trampoline_type;
	hook->mem.size = trampoline ? g_shk_sizes[trampoline_type] : g_shk_sizes[type];
	hook->mem.size += trampoline ? shk_disasm(func_old, g_shk_sizes[type]) : 0;
}

// JMP rel32
void shk_place_rel1(void* ptr, void* src, void* dst) {
	*(uint8_t*)ptr = 0xE9;
	*(int32_t*)((uint8_t*)ptr + 1) = shk_get_offset((uint8_t*)src + 5, dst);
}

// JMP [ip + 0x0]
void shk_place_abs1(void* ptr, void* dst) {
	u_memcpy(ptr, (uint8_t*)"\xFF\x25\x00\x00\x00\x00", 6);
	*(void**)((uint8_t*)ptr + 6) = dst;
}

// PUSH [ip + 0x1]
// RET
void shk_place_abs2(void* ptr, void* dst) {
	u_memcpy(ptr, (uint8_t*)"\xFF\x35\x01\x00\x00\x00\xC3", 7);
	*(void**)((uint8_t*)ptr + 7) = dst;
}

// MOV rax, [ip + 0x5]
// NOT rax
// JMP rax
void shk_place_abs1n(void* ptr, void* dst) {
	u_memcpy(ptr, (uint8_t*)"\x48\x8B\x05\x05\x00\x00\x00\x48\xF7\xD0\xFF\xE0", 12);
	*(uintptr_t*)((uint8_t*)ptr + 12) = ~(uintptr_t)dst;
}

// MOV rax, [ip + 0x5]
// NOT rax
// PUSH rax
// RET
void shk_place_abs2n(void* ptr, void* dst) {
	u_memcpy(ptr, (uint8_t*)"\x48\x8B\x05\x05\x00\x00\x00\x48\xF7\xD0\x50\xC3", 12);
	*(uintptr_t*)((uint8_t*)ptr + 12) = ~(uintptr_t)dst;
}

void shk_place(void* ptr, void* src, void* dst, shk_type_t type) {
	switch (type) {
	case eShkRel1: return shk_place_rel1(ptr, src, dst);
	case eShkAbs1: return shk_place_abs1(ptr, dst);
	case eShkAbs2: return shk_place_abs2(ptr, dst);
	case eShkAbs1n: return shk_place_abs1n(ptr, dst);
	case eShkAbs2n: return shk_place_abs2n(ptr, dst);
	case eShkTypeSize:
	default:
		return;
	}
}

void shk_hook(shk_hook_t* hook) {
	if (!hook->mem.ptr) {
		return;
	}

	size_t size = shk_get_size(hook);

	u_memcpy(hook->mem.ptr, hook->func_old, size);
	if (hook->mem.trampoline) {
		void* ptr = (uint8_t*)hook->mem.ptr + size;
		void* dst = (uint8_t*)hook->func_old + size;
		shk_place(ptr, ptr, dst, hook->mem.trampoline_type);
	}

	shk_place(hook->func_old, hook->func_old, hook->func_new, hook->type);
}

// Swap the original and the hook bytes
// Invalidates trampolines if called an odd number of times on the same hook
void shk_swap(shk_hook_t* hook) {
	u_memswap(hook->func_old, hook->mem.ptr, shk_get_size(hook));
}

void shk_relocation_init(shk_relocation_t* relocation, shk_hook_t* hook) {
	relocation->func_old = hook->func_old;
	relocation->func_new = hook->func_new;
	relocation->mem_ptr = hook->mem.ptr;
}

void shk_relocate(shk_relocation_t* relocation, shk_hook_t* hook) {
	size_t size = shk_get_size(hook);

	if (hook->mem.trampoline) {
		void* ptr = (uint8_t*)hook->mem.ptr + size;
		void* src = (uint8_t*)relocation->mem_ptr + size;
		void* dst = (uint8_t*)relocation->func_old + size;
		shk_place(ptr, src, dst, hook->mem.trampoline_type);
	}

	shk_place(hook->func_old, relocation->func_old, relocation->func_new, hook->type);

	hook->func_old = relocation->func_old;
	hook->func_new = relocation->func_new;
	hook->mem.ptr = relocation->mem_ptr;
}

void shk_off32_init(void* ptr, void* func_new, shk_off32_t* offset) {
	offset->ptr = ptr;
	offset->func_old = ((uint8_t*)ptr + sizeof(int32_t)) + *(int32_t*)ptr;
	offset->func_new = func_new;
}

// Set offet to func_old
void shk_off32_old(shk_off32_t* offset) {
	*(int32_t*)offset->ptr = shk_get_offset((uint8_t*)offset->ptr + sizeof(int32_t), offset->func_old);
}

// Set offet to func_new
void shk_off32_new(shk_off32_t* offset) {
	*(int32_t*)offset->ptr = shk_get_offset((uint8_t*)offset->ptr + sizeof(int32_t), offset->func_new);
}
