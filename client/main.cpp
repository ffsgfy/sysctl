#include <cstdint>
#include <cstdio>
#include <ctime>
#include <thread>

#include "mmgrx.hpp"
extern "C" {
#include "winutils.h"
}

#pragma comment(lib, "ntdll")

struct pause_t {
    pause_t(double duration) {
        target = duration;
        interval = duration;
        QueryPerformanceFrequency(&frequency);
    }

    void operator()(Mmgr& mmgr) {
        LARGE_INTEGER counter_before;
        LARGE_INTEGER counter_after;

        QueryPerformanceCounter(&counter_before);
        mmgr.sleep(std::chrono::duration<double>(interval));
        QueryPerformanceCounter(&counter_after);

        double delta = (double)(counter_after.QuadPart - counter_before.QuadPart) / (double)frequency.QuadPart;
        interval += factor * (target - delta);
    }

    double target = 1.0; // seconds
    double interval = 1.0;
    double factor = 0.05;
    LARGE_INTEGER frequency;
};

int main() {
    if (!NT_SUCCESS(GetEnvironmentPrivilege())) {
        return GetLastError();
    }
    
    MmgrX mmgr;
    if (!mmgr.start()) {
        return 1;
    }

    if (!mmgr.attach(L"explorer.exe")) {
        return 1;
    }

    g_Mmgr = &mmgr;
    g_MmgrX = &mmgr;

    void* ex_base = nullptr;
    uint32_t ex_size = 0;
    mmgr.get_module(L"Explorer.EXE", &ex_base, &ex_size);

    printf("%p %i\n", ex_base, ex_size);

    while (true) {
        mmgr.heartbeat();
        printf("Looping\n");
        Sleep(500);
    }

    // mmgr.mem_protect(ex_base, PAGE_SIZE, PAGE_READONLY);
    // DebugBreak();
    // mmgr.force_write((void*)"HA", ex_base, 2);

    printf("exiting\n");
    mmgr.stop();

    return 0;
}

int main6() {
    if (!NT_SUCCESS(GetEnvironmentPrivilege())) {
        return GetLastError();
    }

    Mmgr mmgr;

    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);

    LARGE_INTEGER time_before;
    LARGE_INTEGER time_after;
    long double time_sum = 0.0;
    long double time_count = 0.0;

    /*for (size_t i = 0; i < 5000; ++i) {
        QueryPerformanceCounter(&time_before);
        Sleep(1);
        QueryPerformanceCounter(&time_after);
        // mmgr.heartbeat();
        time_sum += (long double)(time_after.QuadPart - time_before.QuadPart);
        time_count += 1.0;
    }

    printf("%Lf per Sleep\n", time_sum / time_count / (long double)frequency.QuadPart);

    time_sum = 0.0;
    time_count = 0.0;*/

    pause_t pause(0.001);
    for (size_t i = 0; i < 1000; ++i) {
        QueryPerformanceCounter(&time_before);
        // mmgr.sleep(std::chrono::milliseconds(1));
        pause(mmgr);
        QueryPerformanceCounter(&time_after);
        time_sum += (long double)(time_after.QuadPart - time_before.QuadPart);
        time_count += 1.0;
    }

    printf("%Lf per mmgr.sleep\n", time_sum / time_count / (long double)frequency.QuadPart);

    return 0;
}

int main4() {
    HANDLE section = 0;
    LARGE_INTEGER section_maxsize;
    section_maxsize.QuadPart = PAGE_SIZE;
    NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_maxsize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!section) {
        return 1;
    }

    PVOID base_1 = 0;
    SIZE_T size_1 = 0;
    NtMapViewOfSection(section, GetCurrentProcess(), &base_1, 0, PAGE_SIZE, NULL, &size_1, ViewShare, 0, PAGE_READWRITE);
    VirtualLock(base_1, PAGE_SIZE);
    printf("Map 1: %p\n", base_1);
    system("pause");

    PVOID base_2 = 0;
    SIZE_T size_2 = 0;
    NtMapViewOfSection(section, GetCurrentProcess(), &base_2, 0, PAGE_SIZE, NULL, &size_2, ViewShare, 0, PAGE_READWRITE);
    VirtualLock(base_2, PAGE_SIZE);
    printf("Map 2: %p\n", base_2);
    system("pause");

    VirtualUnlock(base_1, PAGE_SIZE);
    VirtualUnlock(base_2, PAGE_SIZE);
    NtUnmapViewOfSection(GetCurrentProcess(), base_1);
    NtUnmapViewOfSection(GetCurrentProcess(), base_2);

    return 0;
}

int main3() {
    if (!NT_SUCCESS(GetEnvironmentPrivilege())) {
        return GetLastError();
    }

    Mmgr mmgr;
    if (!mmgr.attach(L"explorer.exe")) {
        return 1;
    }

    void* mem_remote = mmgr.mem_alloc(PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mmgr.mem_lock(mem_remote, PAGE_SIZE)) {
        return 2;
    }

    void* mem_local = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE, PAGE_NOACCESS);
    VirtualFree(mem_local, 0, MEM_RELEASE);
    /*if (!VirtualLock(mem_local, PAGE_SIZE)) {
        return 3;
    }*/
    
    // mmgr.write(mem_local, mem_remote, PAGE_SIZE); // touch
    auto ptes = mmgr.take_ptes(mem_remote, mem_local, PAGE_SIZE);

    printf("Mem remote: %p\nMem local: %p\n", mem_remote, mem_local);
    system("pause");

    MEMORY_BASIC_INFORMATION meminfo;
    VirtualQuery(mem_local, &meminfo, sizeof(meminfo));

    system("pause");

    mmgr.restore_ptes(mem_local, PAGE_SIZE, ptes, true, true);
    mmgr.mem_unlock(mem_remote, PAGE_SIZE);
    mmgr.mem_free(mem_remote, 0, MEM_RELEASE);

    // VirtualUnlock(mem_local, PAGE_SIZE);
    // VirtualFree(mem_local, 0, MEM_RELEASE);

    return 0;
}

int main2() {
    if (!NT_SUCCESS(GetEnvironmentPrivilege())) {
        return GetLastError();
    }

    Mmgr mmgr;

    LARGE_INTEGER time_before;
    LARGE_INTEGER time_after;
    long double time_sum = 0.0;
    long double time_count = 0.0;

    printf("Starting...\n");
    for (size_t i = 0; i < 10000000; ++i) {
        QueryPerformanceCounter(&time_before);
        mmgr.heartbeat();
        QueryPerformanceCounter(&time_after);
        time_sum += (long double)(time_after.QuadPart - time_before.QuadPart);
        time_count += 1.0;

        if (i % 10000 == 0) {
            printf("Dun %lli\n", i);
        }
    }

    printf("%Lf per iteration\n", time_sum / time_count);

    return 0;
}

int main1() {
    if (!NT_SUCCESS(GetEnvironmentPrivilege())) {
        return GetLastError();
    }

    Mmgr mmgr;
    if (mmgr.attach(L"idle.exe")) {
        size_t remote_size = 200;
        void* remote_base = nullptr;
        mmgr.mem_alloc(&remote_base, &remote_size, MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
        if (remote_base) {
            printf("Remote allocation success: %p\n", remote_base);
            mmgr.mem_free(remote_base, 0, MEM_RELEASE);

            void* local_base = VirtualAlloc(nullptr, 200, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (local_base) {
                printf("Local allocation success: %p\n", local_base);
                if (VirtualLock(local_base, 200)) {
                    printf("Lock success\n");

                    auto orig_ptes = mmgr.give_ptes(local_base, remote_base, 200);
                    if (orig_ptes.get()) {
                        printf("Pte replacement success\n");
                        system("timeout 300");
                        mmgr.restore_ptes(remote_base, 200, orig_ptes);
                    }
                    else {
                        printf("Pte replacement failure\n");
                    }

                    VirtualUnlock(local_base, 200);
                }
                else {
                    printf("Lock failure\n");
                }

                VirtualFree(local_base, 0, MEM_RELEASE);
            }
            else {
                printf("Local allocation failure\n");
            }
        }
        else {
            printf("Remote allocation failure\n");
        }
    }

    return 0;
}
