// Crb.c - ACPI TPM2 table takeover and CRB (Command Response Buffer) emulation
//
// RE: 0x1c0003f60 FtpmSimCrbPublish
//     0x1c0003f38 FtpmSimCrbRelease
//     0x1c0004840 FtpmSimCrbWorkerThread

#include "FtpmSim.h"

PACPI_TPM2_TABLE        g_AcpiTpm2Table;
PFTPM_CRB_CONTROL_AREA  g_CrbControl;
PUCHAR                  g_CrbCommandBuffer;
PUCHAR                  g_CrbResponseBuffer;
PVOID                   g_CrbControlAllocation;
PFTPM_THREAD_CONTROL    g_ThreadControl;
PKTHREAD                g_WorkerThread;
BOOLEAN                 g_CrbInitialized;
BOOLEAN                 g_OwnsCrbPublication;
BOOLEAN                 g_TpmStarted;
BOOLEAN                 g_NvImportedFromFirmware;
BOOLEAN                 g_CrbCmdReady;
ULONG                   g_CrbIdlePolls;

// HalDispatchTable (ntddk.h) slot 21 / +0xa8 is HalGetCachedAcpiTable(Signature, OemId, OemTableId).

static VOID
FtpmSimUpdateAcpiChecksum(
    _Inout_ PACPI_TPM2_TABLE Table
    )
{
    PUCHAR bytes = (PUCHAR)Table;
    UCHAR  sum   = 0;
    ULONG  i;

    Table->Checksum = 0;
    for (i = 0; i < Table->Length; i++)
    {
        sum = (UCHAR)(sum + bytes[i]);
    }
    Table->Checksum = (UCHAR)(0 - sum);
}

//
// FtpmSimCrbPublish
//
// Finds the firmware TPM2 table, converts it to a CRB table backed by this
// driver and makes the CRB buffers available. Returns FALSE on any failure
// (D0Entry then fails with STATUS_UNSUCCESSFUL). Idempotent: once successful it
// returns TRUE without doing anything.
//
// Ownership: g_OwnsCrbPublication is TRUE if the table already carries our
// marker or if its ControlAddress was still 0, i.e. we (or an earlier instance
// of the driver) are the party that publishes the buffers; it is FALSE if some
// other component already published a control area, in which case the existing
// area is only mapped and never unpublished.
//
BOOLEAN
FtpmSimCrbPublish(
    VOID
    )
{
    PACPI_TPM2_TABLE        table;
    PFTPM_CRB_CONTROL_AREA  control;
    PHYSICAL_ADDRESS        low, high, boundary, physical;
    LONG64                  previous;
    UCHAR                   markerPresent;

    if (g_CrbInitialized)
    {
        return TRUE;
    }

    table = (PACPI_TPM2_TABLE)HalGetCachedAcpiTable(ACPI_TPM2_SIGNATURE, NULL, NULL);
    g_AcpiTpm2Table = table;
    if (table == NULL || table->Revision != ACPI_TPM2_EXPECTED_REVISION)
    {
        return FALSE;
    }

    markerPresent = (table->MarkerHigh == FTPM_SIM_MARKER_HI && table->MarkerLow == FTPM_SIM_MARKER_LO);
    if (markerPresent || (KeMemoryBarrier(), table->ControlAddress == 0))
    {
        g_OwnsCrbPublication = TRUE;
    }
    else
    {
        table->MarkerLow  = FTPM_SIM_MARKER_LO;
        table->MarkerHigh = FTPM_SIM_MARKER_HI;
        g_OwnsCrbPublication = FALSE;
    }

    table->StartMethod              = ACPI_TPM2_START_METHOD_CRB;
    table->PlatformClassAndReserved = 0;

    low.QuadPart      = 0;
    high.QuadPart     = (LONGLONG)-1;
    boundary.QuadPart = 0;

    g_ThreadControl = (PFTPM_THREAD_CONTROL)MmAllocateContiguousMemorySpecifyCache(
                            sizeof(FTPM_THREAD_CONTROL), low, high, boundary, MmNonCached);
    if (g_ThreadControl == NULL)
    {
        return FALSE;
    }
    g_ThreadControl->StopRequested = 0;

    KeMemoryBarrier();
    if (table->ControlAddress == 0)
    {
        // Nobody published a CRB yet: allocate the control area and both buffers.
        g_CrbControlAllocation = MmAllocateContiguousMemorySpecifyCache(
                                    FTPM_CRB_CONTROL_AREA_ALLOC, low, high, boundary, MmNonCached);
        if (g_CrbControlAllocation == NULL)
        {
            return FALSE;
        }

        RtlZeroMemory(g_CrbControlAllocation, FTPM_CRB_CONTROL_AREA_ALLOC);
        g_CrbControl = (PFTPM_CRB_CONTROL_AREA)g_CrbControlAllocation;
        control = g_CrbControl;
        control->CommandSize  = FTPM_CRB_BUFFER_SIZE;
        control->ResponseSize = FTPM_CRB_BUFFER_SIZE;
        control->Request      = 0;
        control->Status       = 0;

        g_CrbCommandBuffer = (PUCHAR)MmAllocateContiguousNodeMemory(
                                    FTPM_CRB_BUFFER_SIZE, low, high, boundary, PAGE_READWRITE, MM_ANY_NODE_OK);
        if (g_CrbCommandBuffer == NULL)
        {
            return FALSE;
        }

        g_CrbResponseBuffer = (PUCHAR)MmAllocateContiguousNodeMemory(
                                    FTPM_CRB_BUFFER_SIZE, low, high, boundary, PAGE_READWRITE, MM_ANY_NODE_OK);
        if (g_CrbResponseBuffer == NULL)
        {
            return FALSE;
        }

        control->CommandAddress  = (ULONG64)MmGetPhysicalAddress(g_CrbCommandBuffer).QuadPart;
        control->ResponseAddress = (ULONG64)MmGetPhysicalAddress(g_CrbResponseBuffer).QuadPart;
        physical = MmGetPhysicalAddress(g_CrbControlAllocation);

        // Publish with a compare-exchange so that two instances cannot both win.
        previous = InterlockedCompareExchange64((volatile LONG64*)&table->ControlAddress,
                                                physical.QuadPart, 0);
        if (previous != 0)
        {
            // Lost the race: drop our buffers and attach to the published area below.
            // RE: g_CrbControlAllocation is not cleared here in the binary, so a later
            // FtpmSimCrbRelease() would still zero somebody else's ControlAddress.
            MmFreeContiguousMemory(g_CrbControlAllocation);
            MmFreeContiguousMemory(g_CrbCommandBuffer);
            MmFreeContiguousMemory(g_CrbResponseBuffer);
            goto AttachToPublished;
        }
    }
    else
    {
AttachToPublished:
        KeMemoryBarrier();
        physical.QuadPart = (LONGLONG)table->ControlAddress;
        g_CrbControl = (PFTPM_CRB_CONTROL_AREA)MmMapIoSpaceEx(
                            physical, FTPM_CRB_CONTROL_AREA_MAP_SIZE, PAGE_READWRITE | PAGE_NOCACHE);
        if (g_CrbControl == NULL)
        {
            return FALSE;
        }

        physical.QuadPart = (LONGLONG)g_CrbControl->CommandAddress;
        g_CrbCommandBuffer = (PUCHAR)MmMapIoSpaceEx(physical, g_CrbControl->CommandSize, PAGE_READWRITE);
        if (g_CrbCommandBuffer == NULL)
        {
            return FALSE;
        }

        physical.QuadPart = (LONGLONG)g_CrbControl->ResponseAddress;
        g_CrbResponseBuffer = (PUCHAR)MmMapIoSpaceEx(physical, g_CrbControl->ResponseSize, PAGE_READWRITE);
        if (g_CrbResponseBuffer == NULL)
        {
            return FALSE;
        }
    }

    g_CrbCmdReady    = FALSE;
    g_CrbIdlePolls   = 0;
    table->Checksum  = 0;
    FtpmSimUpdateAcpiChecksum(table);
    g_CrbInitialized = TRUE;
    return TRUE;
}

//
// FtpmSimCrbRelease
//
// Withdraws a control area that this driver allocated by zeroing
// TPM2.ControlAddress. The memory itself is not freed (the binary leaks it, the
// mapping is reused by the next D0Entry).
//
VOID
FtpmSimCrbRelease(
    VOID
    )
{
    if (g_CrbControlAllocation != NULL)
    {
        if (g_AcpiTpm2Table != NULL)
        {
            KeMemoryBarrier();
            g_AcpiTpm2Table->ControlAddress = 0;
        }
        g_CrbControlAllocation = NULL;
    }
}

//
// FtpmSimCrbWorkerThread
//
// Polls the CRB control area every 10 ms:
//
//   Start == 1   If Status is 0 (tpmIdle clear): bring the TPM up if necessary
//                (FtpmInit), run the command under the device wait lock and clear
//                Start. If Status != 0 the request is dropped (Start cleared).
//   Request == 2 goIdle: drop out of the ready state.
//   Request == 1 cmdReady: enter the ready state and clear Status.
//   Neither      after FTPM_CRB_IDLE_POLLS + 1 consecutive polls without being
//                ready, report tpmIdle (Status = 2).
//
// A PPI pseudo command (TPM_CC_EmulatePPI, 0x200001FF) is intercepted before the
// TPM library sees the command, see PlatformAdminPpi.c.
//
VOID
FtpmSimCrbWorkerThread(
    _In_ PVOID StartContext
    )
{
    WDFDEVICE               device = (WDFDEVICE)StartContext;
    NTSTATUS                exitStatus;
    PDEVICE_CONTEXT         deviceContext;
    PFTPM_CRB_CONTROL_AREA  control;
    LARGE_INTEGER           pollInterval;
    ULONG                   commandSize;
    ULONG                   responseSize;
    PUCHAR                  response;

    if (g_ThreadControl == NULL || g_CrbControl == NULL)
    {
        exitStatus = STATUS_UNSUCCESSFUL;
        PsTerminateSystemThread(exitStatus);
        return;
    }

    deviceContext = FtpmSimGetDeviceContext(device);
    pollInterval.QuadPart = FTPM_CRB_POLL_INTERVAL_100NS;

    while (g_ThreadControl->StopRequested == 0)
    {
        control = g_CrbControl;

        if (control->Start == FTPM_CRB_START_COMMAND)
        {
            if (control->Status != 0)
            {
                // tpmIdle: the start request is ignored.
                control->Start = 0;
                continue;
            }

            g_CrbIdlePolls = 0;
            g_CrbCmdReady  = FALSE;

            // The TPM header carries the command size at offset 2, big endian.
            commandSize = RtlUlongByteSwap(*(UNALIGNED ULONG*)(g_CrbCommandBuffer + 2));

            FtpmInit();

            WdfWaitLockAcquire(deviceContext->TpmLock, NULL);

            responseSize = FTPM_CRB_BUFFER_SIZE;
            response     = g_CrbResponseBuffer;
            if (!_admin__PPICommand(commandSize, g_CrbCommandBuffer, &responseSize, &response))
            {
                responseSize = FTPM_CRB_BUFFER_SIZE;
                response     = g_CrbResponseBuffer;
                ExecuteCommand(commandSize, g_CrbCommandBuffer, &responseSize, &response);
            }

            WdfWaitLockRelease(deviceContext->TpmLock);

            g_CrbControl->Start = 0;
            control = g_CrbControl;
        }

        if (control->Request == FTPM_CRB_REQ_GO_IDLE)
        {
            g_CrbIdlePolls = 0;
            g_CrbCmdReady  = FALSE;
            control->Request = 0;
        }

        if (control->Request == FTPM_CRB_REQ_CMD_READY)
        {
            g_CrbIdlePolls = 0;
            g_CrbCmdReady  = TRUE;
            control->Request = 0;
            control->Status  = 0;
        }

        if (!g_CrbCmdReady && (g_CrbIdlePolls++ > FTPM_CRB_IDLE_POLLS))
        {
            g_CrbIdlePolls = 0;
            control->Status = FTPM_CRB_STS_TPM_IDLE;
        }

        KeDelayExecutionThread(KernelMode, FALSE, &pollInterval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}
