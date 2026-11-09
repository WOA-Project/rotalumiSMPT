// Queue.c - default I/O queue
//
// RE: 0x1c0004a70 FtpmSimEvtIoDeviceControl
//
// The driver has no IOCTL interface of its own. The only queue is the default
// parallel queue (power managed: WdfUseDefault) and every device control
// request is completed with STATUS_SUCCESS without looking at it. All TPM
// traffic goes through the CRB / ACPI TPM2 table path (Crb.c).

#include "FtpmSim.h"

VOID
FtpmSimEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(IoControlCode);

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

// Empty in the shipped binary (folded with the CFG stub, see Driver.c).
VOID
FtpmSimEvtIoStop(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG      ActionFlags
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(ActionFlags);
}
