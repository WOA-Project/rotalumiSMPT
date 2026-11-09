// Driver.c - DriverEntry of ftpmsim.sys
//
// RE: 0x1c0004bb0 GsDriverEntry   (/GS cookie init 0x1c0056098, then FxDriverEntry)
//     0x1c0004be0 FxDriverEntry   (WDF bootstrap from WdfDriverEntry.lib: WdfVersionBind(KMDF 1.15)
//                                  then calls DriverEntry below, hooks DriverObject->DriverUnload with
//                                  FxDriverUnload 0x1c0004b70)
//     0x1c0056000 DriverEntry     (this file)
//
// The binary has no WPP/ETW provider and no registry parameters; diagnostics
// are plain DbgPrintEx(DPFLTR_IHVDRIVER_ID, ...) messages.

#include "FtpmSim.h"

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG       config;
    WDF_OBJECT_ATTRIBUTES   attributes;

    WDF_DRIVER_CONFIG_INIT(&config, FtpmSimEvtDeviceAdd);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = FtpmSimEvtDriverContextCleanup;

    return WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
}

// The cleanup callback (and EvtIoStop in Queue.c) is empty: the linker folded
// both into the same one-instruction stub as _guard_check_icall (0x1c0003f30).
VOID
FtpmSimEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
}
