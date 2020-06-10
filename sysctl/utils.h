#pragma once

#include <stdint.h>

#define GSTRING_SIZE 1024

typedef struct {
    uint16_t str[GSTRING_SIZE];
    size_t pos;
} gstring;

void gstring_init(gstring* str);
void gstring_write(gstring* dst, const uint16_t* src);

int u_strcmp8(const uint8_t* s1, const uint8_t* s2);
int u_strcmp16(const uint16_t* s1, const uint16_t* s2);
int u_strncmp8(const uint8_t* s1, const uint8_t* s2, size_t n);
int u_strncmp16(const uint16_t* s1, const uint16_t* s2, size_t n);
void u_strcpy8(uint8_t* dst, const uint8_t* src);
void u_strcpy16(uint16_t* dst, const uint16_t* src);
size_t u_strlen8(const uint8_t* str);
size_t u_strlen16(const uint16_t* str);
void u_memcpy(uint8_t* dst, const uint8_t* src, size_t size);
void u_memset(uint8_t* dst, uint8_t val, size_t size);
void u_memswap(uint8_t* p1, uint8_t* p2, size_t size);
uint64_t u_abs64(int64_t n);
uint32_t u_abs32(int32_t n);
uintptr_t u_absptr(intptr_t n);
uint64_t u_hash8(const uint8_t* str, size_t n);
uint64_t u_hash16(const uint16_t* str, size_t n);

void* find_pattern(void* start, size_t size, const uint8_t* pattern, const uint8_t* mask);
