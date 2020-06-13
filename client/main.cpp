#include <cstdint>
#include <cstdio>
#include <ctime>
#include <thread>

#include "mmgr.hpp"
extern "C" {
#include "winutils.h"
}

int main() {
    if (!NT_SUCCESS(GetEnvironmentPrivilege())) {
        return GetLastError();
    }

    Mmgr mmgr;

    LARGE_INTEGER time_before;
    LARGE_INTEGER time_after;
    long double time_sum = 0.0;
    long double time_count = 0.0;

    printf("Starting...\n");
    for (size_t i = 0; i < 100000; ++i) {
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

                    auto orig_ptes = mmgr.replace_ptes(local_base, remote_base, 200);
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
