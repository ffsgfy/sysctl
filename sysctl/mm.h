#pragma once

#include "nt.h"

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12
#define MM_ALLOCATION_GRANULARITY 0x10000
#define MM_ALLOCATION_GRANULARITY_SHIFT 16
#define MM_PAGE_FRAME_NUMBER_SIZE 52
#define MI_HIGHEST_USER_ADDRESS 0x7FFFFFEFFFF
#define MM_USER_PROBE_ADDRESS 0x7FFFFFFF0000

typedef struct _MMPTE_SOFTWARE {
    ULONG64 Valid : 1;
    ULONG64 PageFileLow : 4;
    ULONG64 Protection : 5;
    ULONG64 Prototype : 1;
    ULONG64 Transition : 1;
    ULONG64 UsedPageTableEntries : 10;
    ULONG64 Reserved : 10;
    ULONG64 PageFileHigh : 32;
} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE;

typedef struct _MMPTE_TRANSITION {
    ULONG64 Valid : 1;
    ULONG64 Write : 1;
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Protection : 5;
    ULONG64 Prototype : 1;
    ULONG64 Transition : 1;
    ULONG64 PageFrameNumber : 36;
    ULONG64 Unused : 16;
} MMPTE_TRANSITION;

typedef struct _MMPTE_PROTOTYPE {
    ULONG64 Valid : 1;
    ULONG64 Unused0 : 7;
    ULONG64 ReadOnly : 1;
    ULONG64 Unused1 : 1;
    ULONG64 Prototype : 1;
    ULONG64 Protection : 5;
    LONG64 ProtoAddress : 48;
} MMPTE_PROTOTYPE;

typedef struct _MMPTE_SUBSECTION {
    ULONG64 Valid : 1;
    ULONG64 Unused0 : 4;
    ULONG64 Protection : 5;
    ULONG64 Prototype : 1;
    ULONG64 Unused1 : 5;
    LONG64 SubsectionAddress : 48;
} MMPTE_SUBSECTION;

typedef struct _MMPTE_LIST {
    ULONG64 Valid : 1;
    ULONG64 OneEntry : 1;
    ULONG64 filler0 : 3;
    ULONG64 Protection : 5;
    ULONG64 Prototype : 1;
    ULONG64 Transition : 1;
    ULONG64 filler1 : 20;
    ULONG64 NextEntry : 32;
} MMPTE_LIST;

typedef struct _MMPTE_HARDWARE {
    ULONG64 Valid : 1;
    ULONG64 Write : 1;
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;
    ULONG64 Prototype : 1;
    ULONG64 reserved0 : 1;
    ULONG64 PageFrameNumber : 36;
    ULONG64 reserved1 : 4;
    ULONG64 SoftwareWsIndex : 11;
    ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef struct _MMPTE {
    union {
        ULONG_PTR Long;
        MMPTE_HARDWARE Hard;
        MMPTE_PROTOTYPE Proto;
        MMPTE_SOFTWARE Soft;
        MMPTE_TRANSITION Trans;
        MMPTE_SUBSECTION Subsect;
        MMPTE_LIST List;
    } u;
} MMPTE, * PMMPTE, MMPDE, * PMMPDE, MMPPE, * PMMPPE, MMPXE, * PMMPXE;
