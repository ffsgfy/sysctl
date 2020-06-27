#pragma once

#include "ptr.hpp"

struct list_entry_t {
    Ptr64<void> Flink;
    Ptr64<void> Blink;
};

struct unicode_string_t {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t Padding;
    ArrPtr64<wchar_t> Buffer;
};

struct ldr_data_table_entry_t {
    list_entry_t InLoadOrderLinks;
    list_entry_t InMemoryOrderLinks;
    list_entry_t InInitializationOrderLinks;
    Ptr64<void> DllBase;
    Ptr64<void> EntryPoint;
    uint32_t SizeOfImage;
    uint32_t Padding;
    unicode_string_t FullDllName;
    unicode_string_t BaseDllName;
    uint32_t Flags;
    uint16_t LoadCount;
    uint16_t TlsIndex;
    list_entry_t HashLinks;
    uint32_t TimeDateStamp;
};

struct peb_ldr_data_t {
    uint32_t Length;
    uint8_t Initialized;
    uint8_t Padding[3];
    Ptr64<void> SsHandle;
    list_entry_t InLoadOrderModuleList;
    list_entry_t InMemoryOrderModuleList;
    list_entry_t InInitializationOrderModuleList;
};

struct peb_t {
    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    uint8_t BitField;
    uint8_t Padding0[4];
    Ptr64<void> Mutant;
    Ptr64<void> ImageBaseAddress;
    Ptr64<peb_ldr_data_t> Ldr;
    Ptr64<void> ProcessParameters;
    Ptr64<void> SubSystemData;
    Ptr64<void> ProcessHeap;
    Ptr64<void> FastPebLock;
    Ptr64<void> AtlThunkSListPtr;
    Ptr64<void> IFEOKey;
    uint32_t CrossProcessFlags;
    uint8_t Padding1[4];
    Ptr64<void> KernelCallbackTable;
    Ptr64<void> UserSharedInfoPtr;
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    Ptr64<void> ApiSetMap;
};
