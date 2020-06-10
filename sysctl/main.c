#include "efi/system-table.h"
#include "efi/protocol/loaded-image.h"

#include "utils.h"
#include "comms.h"
#include "shk.h"
#include "nt.h"

#define SUCCESS(x) (!EFI_ERROR(x))

efi_guid g_VirtualAddressChange = EFI_EVENT_GROUP_VIRTUAL_ADDRESS_CHANGE;
efi_guid g_ExitBootServices = EFI_EVENT_GROUP_EXIT_BOOT_SERVICES;
efi_guid g_LoadedImageProtocol = EFI_LOADED_IMAGE_PROTOCOL_GUID;
efi_handle g_ImageHandle = NULL;
efi_boot_services* g_BS = NULL;
efi_runtime_services* g_RS = NULL;
bool g_Virtual = false;
bool g_Runtime = false;

efi_guid g_CustomProtocol = { 0xCC6A5BCD, 0xEC9A, 0x4642, { 0x95, 0x86, 0x5A, 0x32, 0x10, 0xC1, 0x7F, 0x4D } };
struct {
    uint32_t x;
} g_CustomProtocolData;

typedef efi_status(EFIAPI*SetVariable_t)(char16_t*, efi_guid*, uint32_t, size_t, const void*);
shk_hook_t shk_SetVariable;

efi_status EFIAPI hkSetVariable(char16_t* var_name, efi_guid* vendor_guid, uint32_t attributes, size_t data_size, const void* data) {
    if (g_Virtual && g_Runtime) {
        if (data && vendor_guid && var_name && (u_strcmp16(var_name, L"tPyNcCxOrSEg") == 0)) {
            // At this point we are in a critical region and holding a FAST_MUTEX (ExpEnvironmentLock);
            comms_dispatch(0, (comms_header_t*)data, data_size);

            return EFI_SUCCESS;
        }
    }

    /*shk_swap(&hk_set_variable);
    efi_status status = o_SetVariable(var_name, vendor_guid, attributes, data_size, data);
    shk_swap(&hk_set_variable);
    
    return status;*/
    return ((SetVariable_t)shk_SetVariable.mem.ptr)(var_name, vendor_guid, attributes, data_size, data);
}

void EFIAPI evtVirtualAddressChange(efi_event Event, void* Context) {
    // g_BS->CloseEvent(Event);
    g_Virtual = true;

    shk_relocation_t shkr_SetVariable;
    shk_relocation_init(&shkr_SetVariable, &shk_SetVariable);
    g_RS->ConvertPointer(EFI_OPTIONAL_PTR, (void**)&shkr_SetVariable.func_old);
    g_RS->ConvertPointer(EFI_OPTIONAL_PTR, (void**)&shkr_SetVariable.func_new);
    g_RS->ConvertPointer(EFI_OPTIONAL_PTR, (void**)&shkr_SetVariable.mem_ptr);
    shk_relocate(&shkr_SetVariable, &shk_SetVariable);

    g_RS->ConvertPointer(EFI_OPTIONAL_PTR, (void**)&g_BS);
    g_RS->ConvertPointer(EFI_OPTIONAL_PTR, (void**)&g_RS);
}

void EFIAPI evtExitBootServices(efi_event Event, void* Context) {
    g_BS->CloseEvent(Event);
    g_Runtime = true;
    
    shk_hook(&shk_SetVariable);
}

efi_status EFIAPI efi_unload(efi_handle ImageHandle) {
    return EFI_ACCESS_DENIED;
}

efi_status EFIAPI efi_main(efi_handle ImageHandle, efi_system_table* SystemTable) {
    efi_status status = 0;

    efi_loaded_image_protocol* loaded_image;

    status = SystemTable->BootServices->OpenProtocol(ImageHandle, &g_LoadedImageProtocol, (void**)&loaded_image, ImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (SUCCESS(status)) {
        loaded_image->Unload = &efi_unload;
        g_ImageHandle = ImageHandle;
        g_BS = SystemTable->BootServices;
        g_RS = SystemTable->RuntimeServices;

        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Loaded image protocol opened\n\r");

        efi_event virtual_address_change;
        g_BS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, &evtVirtualAddressChange, NULL, &g_VirtualAddressChange, &virtual_address_change);
        efi_event exit_boot_services;
        g_BS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, &evtExitBootServices, NULL, &g_ExitBootServices, &exit_boot_services);

        g_BS->InstallProtocolInterface(&ImageHandle, &g_CustomProtocol, EFI_NATIVE_INTERFACE, &g_CustomProtocolData);

        shk_hook_init(&shk_SetVariable, g_RS->SetVariable, &hkSetVariable, eShkAbs2n, true, eShkAbs1);
        status = g_BS->AllocatePool(EfiRuntimeServicesCode, shk_SetVariable.mem.size, &shk_SetVariable.mem.ptr);

        if (shk_SetVariable.mem.size && SUCCESS(status)) {
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Buffer allocated\n\r");
        }
        else {
            SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Failed to allocate buffer\n\r");
            status = EFI_UNSUPPORTED;
        }

        g_BS->CloseProtocol(ImageHandle, &g_LoadedImageProtocol, ImageHandle, NULL);
    }
    else {
        SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Failed to open loaded image protocol\n\r");
    }

    SystemTable->ConOut->OutputString(SystemTable->ConOut, L"Exiting\n\r");

    return status;
}
