#pragma once

#include <stdint.h>
#include <windows.h>

#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12

#define CONCAT_DIRECT(a, b) a ## b
#define CONCAT(a, b) CONCAT_DIRECT(a, b)
#define PAD(n) unsigned __int8 CONCAT( _pad , __LINE__ ) [ n ]

typedef enum _SYSTEM_INFO_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    _SystemPowerInformation,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFO_CLASS;

typedef enum _PROCESS_INFO_CLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessResourceManagement,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    ProcessHandleInformation,
    ProcessMitigationPolicy,
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode,
    ProcessKeepAliveCount,
    ProcessRevokeFileHandles,
    ProcessWorkingSetControl,
    ProcessHandleTable,
    ProcessCheckStackExtentsMode,
    ProcessCommandLineInformation,
    ProcessProtectionInformation,
    ProcessMemoryExhaustion,
    ProcessFaultInformation,
    ProcessTelemetryIdInformation,
    ProcessCommitReleaseInformation,
    ProcessDefaultCpuSetsInformation,
    ProcessAllowedCpuSetsInformation,
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation,
    ProcessInPrivate,
    ProcessRaiseUMExceptionOnInvalidHandleClose,
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation,
    ProcessHighGraphicsPriorityInformation,
    ProcessSubsystemInformation,
    ProcessEnergyValues,
    ProcessActivityThrottleState,
    ProcessActivityThrottlePolicy,
    ProcessWin32kSyscallFilterInformation,
    ProcessDisableSystemAllowedCpuSets,
    ProcessWakeInformation,
    ProcessEnergyTrackingState,
    ProcessManageWritesToExecutableMemory,
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging,
    ProcessUptimeInformation,
    ProcessImageSection,
    ProcessDebugAuthInformation,
    ProcessSystemResourceManagement,
    ProcessSequenceNumber,
    ProcessLoaderDetour,
    ProcessSecurityDomainInformation,
    ProcessCombineSecurityDomainsInformation,
    ProcessEnableLogging,
    ProcessLeapSecondInformation,
    ProcessFiberShadowStackAllocation,
    ProcessFreeFiberShadowStackAllocation,
    ProcessAltSystemCallInformation,
    ProcessDynamicEHContinuationTargets,
    MaxProcessInfoClass
} PROCESS_INFO_CLASS;

typedef struct _ANSI_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PSTR   Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), (s) }
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

EXTERN_C_START
NTSYSAPI NTSTATUS NTAPI NtSetSystemEnvironmentValueEx(UNICODE_STRING* VariableName, GUID* VendorGuid, PVOID Value, ULONG ValueLength, ULONG Attributes);
NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, BOOLEAN* WasEnabled);
NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFO_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI NtWaitForAlertByThreadId(PVOID Address, DWORD Milliseconds);
NTSYSAPI NTSTATUS NTAPI NtAlertThreadByThreadId(HANDLE ThreadId);
EXTERN_C_END

typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

DWORD GetProcessID(LPCWSTR ProcessName);
VOID GetProcessModule(DWORD ProcessId, LPCWSTR ModuleName, PVOID* ModuleBase, DWORD* ModuleSize);
NTSTATUS GetEnvironmentPrivilege();
VOID GetSystemModule(LPCSTR ModuleName, PVOID* ModuleBase, ULONG* ModuleSize);
BOOL GetProcessWow64(DWORD ProcessId);
HWND GetProcessWindow(DWORD ProcessId);
BOOL GetWindowSize(HWND hwnd, PUINT32 width, PUINT32 height);
SIZE_T NumberOfPages(ULONG_PTR Start, SIZE_T Size);
PVOID Rebase(PVOID OldBase, PVOID Ptr, PVOID NewBase);

uint64_t u_hash8(const uint8_t* str, size_t n);
uint64_t u_hash16(const uint16_t* str, size_t n);
