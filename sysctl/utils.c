#include "utils.h"

void gstring_init(gstring* str) {
    str->str[0] = 0;
    str->str[GSTRING_SIZE - 1] = 0;
    str->pos = 0;
}

void gstring_write(gstring* dst, const uint16_t* src) {
    size_t size = u_strlen16(src);
    if (dst->pos + size < GSTRING_SIZE) {
        u_strcpy16(dst->str + dst->pos, src);
        dst->pos += size;
    }
}

int u_strcmp8(const uint8_t* s1, const uint8_t* s2) {
    while (*s1 && *s2 && (*s1 == *s2)) {
        ++s1, ++s2;
    }
    return *s1 - *s2;
}

int u_strcmp16(const uint16_t* s1, const uint16_t* s2) {
    while (*s1 && *s2 && (*s1 == *s2)) {
        ++s1, ++s2;
    }
    return *s1 - *s2;
}

int u_strncmp8(const uint8_t* s1, const uint8_t* s2, size_t n) {
    while (n && *s1 && *s2 && (*s1 == *s2)) {
        ++s1, ++s2, --n;
    }
    return (n == 0) ? 0 : (*s1 - *s2);
}

int u_strncmp16(const uint16_t* s1, const uint16_t* s2, size_t n) {
    while (n && *s1 && *s2 && (*s1 == *s2)) {
        ++s1, ++s2, --n;
    }
    return (n == 0) ? 0 : (*s1 - *s2);
}

void u_strcpy8(uint8_t* dst, const uint8_t* src) {
    do {
        *(dst++) = *src;
    } while (*(src++));
}

void u_strcpy16(uint16_t* dst, const uint16_t* src) {
    do {
        *(dst++) = *src;
    } while (*(src++));
}

size_t u_strlen8(const uint8_t* str) {
    size_t size = 0;
    for (; *str; ++str, ++size) { }
    return size;
}

size_t u_strlen16(const uint16_t* str) {
    size_t size = 0;
    for (; *str; ++str, ++size) { }
    return size;
}

void u_memcpy(uint8_t* dst, const uint8_t* src, size_t size) {
    for (size_t i = 0; i < size; ++i, ++dst, ++src) {
        *dst = *src;
    }
}

void u_memset(uint8_t* dst, uint8_t val, size_t size) {
    for (size_t i = 0; i < size; ++i, ++dst) {
        *dst = val;
    }
}

void u_memswap(uint8_t* p1, uint8_t* p2, size_t size) {
    for (size_t i = 0; i < size; ++i, ++p1, ++p2) {
        uint8_t b = *p1;
        *p1 = *p2;
        *p2 = b;
    }
}

uint64_t u_abs64(int64_t n) {
    return n < 0 ? -n : n;
}

uint32_t u_abs32(int32_t n) {
    return n < 0 ? -n : n;
}

uintptr_t u_absptr(intptr_t n) {
    return n < 0 ? -n : n;
}

uint64_t u_hash8(const uint8_t* str, size_t n) {
    uint64_t hash = 5381;
    while (n--) {
        hash = ((hash << 5) + hash) + *(str++);
    }
    return hash;
}

uint64_t u_hash16(const uint16_t* str, size_t n) {
    uint64_t hash = 5381;
    while (n--) {
        hash = ((hash << 5) + hash) + *(str++);
    }
    return hash;
}

void* find_pattern(void* start, size_t size, const uint8_t* pattern, const uint8_t* mask) {
    size_t pos = 0, length = u_strlen8(mask);

    for (uintptr_t check = (uintptr_t)start; (check + length) <= ((uintptr_t)start + size); ++check) {
        for (pos = 0; pos < length; ++pos) {
            if (mask[pos] == 'x' && (((uint8_t*)check)[pos] != pattern[pos])) {
                break;
            }
        }

        if (pos == length) {
            return (void*)check;
        }
    }

    return 0;
}
