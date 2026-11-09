// Device.c - device creation and power callbacks
//
// RE: 0x1c00541e0 FtpmSimEvtDeviceAdd
//     0x1c0054000 FtpmSimCreateDevice
//     0x1c0054260 FtpmSimEvtDeviceD0Entry
//     0x1c0054300 FtpmSimEvtDeviceD0Exit
//     0x1c0054430 FtpmSimStartCrbThread

#include <initguid.h>          // instantiates GUID_DEVINTERFACE_FTPMSIM below
#include "FtpmSim.h"

NTSTATUS
FtpmSimEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;

    UNREFERENCED_PARAMETER(Driver);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDeviceD0Entry = FtpmSimEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit  = FtpmSimEvtDeviceD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    return FtpmSimCreateDevice(DeviceInit);
}

NTSTATUS
FtpmSimCreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS                status;
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    WDF_OBJECT_ATTRIBUTES   lockAttributes;
    WDF_IO_QUEUE_CONFIG     queueConfig;
    WDFDEVICE               device;
    PDEVICE_CONTEXT         deviceContext;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    deviceContext = FtpmSimGetDeviceContext(device);

    WDF_OBJECT_ATTRIBUTES_INIT(&lockAttributes);
    lockAttributes.ParentObject = device;

    // The shipped string says "WdfSpinLockCreate failed", but the call made is
    // WdfWaitLockCreate (WDF function table index 312; the thread uses
    // WdfWaitLockAcquire/Release).
    status = WdfWaitLockCreate(&lockAttributes, &deviceContext->TpmLock);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_INFO, "WdfSpinLockCreate failed 0x%x\n", status);
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_FTPMSIM, NULL);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Default parallel queue; every request is completed immediately, see Queue.c.
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = FtpmSimEvtIoDeviceControl;
    queueConfig.EvtIoStop          = FtpmSimEvtIoStop;
    queueConfig.Settings.Parallel.NumberOfPresentedRequests = (ULONG)-1;

    return WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
}

// During a system power transition (sleep, hibernate, shutdown, reset, power
// off, warm eject: POWER_ACTION 2..7) the CRB publication and the worker thread
// are left untouched, so the TPM state survives S3/S4 and shutdown.
static BOOLEAN
FtpmSimIsSystemPowerTransition(
    _In_ WDFDEVICE Device
    )
{
    POWER_ACTION action = WdfDeviceGetSystemPowerAction(Device);

    return (action >= PowerActionSleep && action <= PowerActionWarmEject);
}

NTSTATUS
FtpmSimEvtDeviceD0Entry(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(PreviousState);

    DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_INFO, "FTPMSimEvtDeviceD0Entry\n");

    if (!FtpmSimIsSystemPowerTransition(Device))
    {
        if (!FtpmSimCrbPublish())
        {
            return STATUS_UNSUCCESSFUL;
        }

        status = FtpmSimStartCrbThread(Device);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
FtpmSimEvtDeviceD0Exit(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
    )
{
    LARGE_INTEGER interval;
    NTSTATUS      waitStatus;

    UNREFERENCED_PARAMETER(TargetState);

    if (!FtpmSimIsSystemPowerTransition(Device))
    {
        // Closes NVChip.dat (committing the image first).
        _plat__Signal_PowerOff();

        g_TpmStarted = FALSE;
        g_ThreadControl->StopRequested = 1;

        if (g_OwnsCrbPublication)
        {
            // Give a command that is currently being executed time to finish.
            interval.QuadPart = FTPM_THREAD_STOP_WAIT_100NS;
            KeDelayExecutionThread(KernelMode, FALSE, &interval);
        }

        if (g_WorkerThread != NULL)
        {
            interval.QuadPart = FTPM_THREAD_STOP_WAIT_100NS;
            waitStatus = KeWaitForSingleObject(g_WorkerThread, Executive, KernelMode, FALSE, &interval);
            if (waitStatus != STATUS_TIMEOUT)
            {
                ObDereferenceObject(g_WorkerThread);
                g_WorkerThread = NULL;
            }
        }

        if (g_OwnsCrbPublication)
        {
            FtpmSimCrbRelease();
        }

        DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_INFO, "FTPMSimEvtDeviceD0Exit\n");
    }

    return STATUS_SUCCESS;
}

NTSTATUS
FtpmSimStartCrbThread(
    _In_ WDFDEVICE Device
    )
{
    NTSTATUS          status;
    HANDLE            threadHandle;
    OBJECT_ATTRIBUTES objectAttributes;

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(&threadHandle, 0, &objectAttributes, NULL, NULL,
                                  FtpmSimCrbWorkerThread, Device);
    if (NT_SUCCESS(status))
    {
        ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL, KernelMode,
                                  (PVOID*)&g_WorkerThread, NULL);
        KeSetBasePriorityThread(g_WorkerThread, FTPM_THREAD_START_PRIORITY);
        ZwClose(threadHandle);
    }

    // The binary ignores the PsCreateSystemThread status (void function).
    return STATUS_SUCCESS;
}
