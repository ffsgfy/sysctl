#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef enum {
	eShkRel1,
	eShkAbs1,
	eShkAbs2,
	eShkAbs1n,
	eShkAbs2n,
	eShkTypeSize
} shk_type_t;

typedef struct {
	void* func_old;
	void* func_new;
	shk_type_t type;

	struct {
		void* ptr; // user-allocated memory
		size_t size; // size of the whole buffer
		bool trampoline; // is this a trampoline?
		shk_type_t trampoline_type;
	} mem;
} shk_hook_t;

typedef struct {
	void* func_old;
	void* func_new;
	void* mem_ptr;
} shk_relocation_t;

typedef struct {
	void* ptr;
	void* func_old;
	void* func_new;
} shk_off32_t;

void shk_hook_init(shk_hook_t* hook, void* func_old, void* func_new, shk_type_t type, bool trampoline, shk_type_t trampoline_type);
void shk_hook(shk_hook_t* hook);
void shk_swap(shk_hook_t* hook);

void shk_relocation_init(shk_relocation_t* relocation, shk_hook_t* hook);
void shk_relocate(shk_relocation_t* relocation, shk_hook_t* hook);

void shk_off32_init(void* ptr, void* func_new, shk_off32_t* offset);
void shk_off32_old(shk_off32_t* offset);
void shk_off32_new(shk_off32_t* offset);
