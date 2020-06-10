#include "winutils.h"
#include <TlHelp32.h>

#pragma comment(lib, "ntdll")

DWORD GetProcessID(LPCWSTR ProcessName) {
	DWORD Result = 0;
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Snapshot) {
		PROCESSENTRY32W Entry;
		Entry.dwSize = sizeof(Entry);

		if (Process32FirstW(Snapshot, &Entry)) {
			do {
				if (wcscmp(Entry.szExeFile, ProcessName) == 0) {
					Result = Entry.th32ProcessID;
					break;
				}
			} while (Process32NextW(Snapshot, &Entry));
		}

		CloseHandle(Snapshot);
	}

	return Result;
}

VOID GetProcessModule(DWORD ProcessId, LPCWSTR ModuleName, PVOID* ModuleBase, DWORD* ModuleSize) {
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
	if (Snapshot) {
		MODULEENTRY32W Entry;
		Entry.dwSize = sizeof(Entry);

		if (Module32FirstW(Snapshot, &Entry)) {
			do {
				if (wcscmp(Entry.szModule, ModuleName) == 0) {
					if (ModuleBase) {
						*ModuleBase = Entry.modBaseAddr;
					}

					if (ModuleSize) {
						*ModuleSize = Entry.modBaseSize;
					}

					break;
				}
			} while (Module32NextW(Snapshot, &Entry));
		}

		CloseHandle(Snapshot);
	}
}

NTSTATUS GetEnvironmentPrivilege() {
	BOOLEAN WasEnabled;
	return RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE, FALSE, &WasEnabled);
}

VOID GetSystemModule(LPCSTR ModuleName, PVOID* ModuleBase, ULONG* ModuleSize) {
	PVOID InformationBuffer = NULL;
	ULONG InformationSize = 0;

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &InformationSize);
	if (InformationSize > 0) {
		InformationBuffer = VirtualAlloc(NULL, InformationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (InformationBuffer) {
			if (NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, InformationBuffer, InformationSize, &InformationSize))) {
				PSYSTEM_MODULE_INFORMATION Information = (PSYSTEM_MODULE_INFORMATION)InformationBuffer;
				for (ULONG i = 0; i < Information->Count; ++i) {
					PSYSTEM_MODULE_ENTRY Module = &Information->Module[i];
					if (strncmp((LPCSTR)(Module->FullPathName + Module->OffsetToFileName), ModuleName, sizeof(Module->FullPathName)) == 0) {
						if (ModuleBase) {
							*ModuleBase = Module->ImageBase;
						}

						if (ModuleSize) {
							*ModuleSize = Module->ImageSize;
						}

						break;
					}
				}
			}
			VirtualFree(InformationBuffer, 0, MEM_RELEASE);
		}
	}
}

BOOL GetProcessWow64(DWORD ProcessId) {
	BOOL Result = FALSE;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
	if (hProcess) {
		IsWow64Process(hProcess, &Result);
		CloseHandle(hProcess);
	}

	return Result;
}

typedef struct {
	DWORD procid;
	HWND hwnd;
} GetProcessWindow_CallbackStruct;

BOOL CALLBACK GetProcessWindow_Callback(HWND hwnd, LPARAM lparam) {
	GetProcessWindow_CallbackStruct* s = (GetProcessWindow_CallbackStruct*)lparam;
	DWORD wprocid = 0;
	
	GetWindowThreadProcessId(hwnd, &wprocid);
	if (wprocid == s->procid) {
		WINDOWINFO info;
		info.cbSize = sizeof(info);
		if (GetWindowInfo(hwnd, &info)) {
			if (info.dwStyle & WS_VISIBLE) {
				s->hwnd = hwnd;
				return FALSE;
			}
		}
	}
	return TRUE;
}

HWND GetProcessWindow(DWORD ProcessId) {
	GetProcessWindow_CallbackStruct s = { ProcessId, 0 };
	EnumWindows(GetProcessWindow_Callback, (LPARAM)&s);
	return s.hwnd;
}

BOOL GetWindowSize(HWND hwnd, PUINT32 width, PUINT32 height) {
	RECT r;
	BOOL result = GetClientRect(hwnd, &r);
	*width = (UINT32)r.right;
	*height = (UINT32)r.bottom;
	return result;
}

SIZE_T NumberOfPages(ULONG_PTR Base, SIZE_T Size) {
	return ((Base + Size - 1) >> PAGE_SHIFT) - (Base >> PAGE_SHIFT) + 1;
}

PVOID Rebase(PVOID OldBase, PVOID Ptr, PVOID NewBase) {
	return (PVOID)((UINT_PTR)Ptr - (UINT_PTR)OldBase + (UINT_PTR)NewBase);
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
