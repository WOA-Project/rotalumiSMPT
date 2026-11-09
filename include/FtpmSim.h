#pragma once

// ftpmsim.sys - "fTPM Simulator Device Driver" (Microsoft, 10.0.17763.1577).
//
// A KMDF 1.15 ARM64 driver that statically links the Microsoft TPM 2.0
// reference library (ms-tpm-20-ref, command set 1.38+ with a SymCrypt / "MsBn"
// crypto back end) and exposes it to the OS as a *memory mapped Command
// Response Buffer (CRB) TPM*:
//
//   * HalDispatchTable->HalGetAcpiTable('TPM2') returns the firmware's ACPI TPM2
//     table. The driver patches it in place (StartMethod = 7 = CRB, a private
//     "ETALUMIS" marker, new ControlAddress, new checksum), so that the inbox TPM
//     stack (tpm.sys / TBS) sees a CRB TPM without any hardware behind it.
//   * The driver allocates the CRB control area, the command buffer and the
//     response buffer from contiguous non-paged memory and publishes the control
//     area's physical address in TPM2.ControlAddress.
//   * A system thread polls the control area every 10 ms (the "start" register),
//     runs the command through the TPM library and writes the response back.
//   * The TPM NV image (32 KiB) is persisted in "NVChip.dat" on the EFI system
//     partition. An image prepared by a pre-boot simulator can be handed over
//     through the TPM2 table (LAML field), see FtpmSimCrbPublish().
//
// There is no hardware, no interrupt and no IOCTL interface: the default I/O
// queue completes every request with STATUS_SUCCESS.

#include <ntddk.h>
#include <wdf.h>

#include "Crb.h"
#include "FtpmSimPlatform.h"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define FTPM_POOL_TAG                   'fTPM'      // "MPTf" in pool dumps

// DbgPrintEx component / levels used by every message of this driver.
#define FTPM_DPFLTR_COMPONENT           DPFLTR_IHVDRIVER_ID     // 0x4d
#define FTPM_DBG_ERROR                  DPFLTR_ERROR_LEVEL      // 0 : NV file problems
#define FTPM_DBG_INFO                   DPFLTR_INFO_LEVEL       // 3 : everything else

// Worker thread timing.
#define FTPM_CRB_POLL_INTERVAL_100NS    (-100000LL)             // 10 ms between polls of the control area
#define FTPM_CRB_IDLE_POLLS             20                      // polls without cmdReady before tpmIdle is raised
#define FTPM_THREAD_STOP_WAIT_100NS     (-600000LL)             // 60 ms
#define FTPM_THREAD_START_PRIORITY      3                       // KeSetBasePriorityThread increment

// ---------------------------------------------------------------------------
// Device context
// ---------------------------------------------------------------------------

//
// The only object context of the driver: a wait lock that serialises TPM
// command execution (the worker thread takes it around ExecuteCommand).
// Binary type info: ContextName "DEVICE_CONTEXT", ContextSize 8.
//
typedef struct _DEVICE_CONTEXT
{
    WDFWAITLOCK TpmLock;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, FtpmSimGetDeviceContext)

// Device interface registered on the (single) device: {6BBF6CAB-5463-4714-B7CD-F0203C0368D4}
// (the binary has no symbolic link and no device name).
DEFINE_GUID(GUID_DEVINTERFACE_FTPMSIM,
            0x6bbf6cab, 0x5463, 0x4714, 0xb7, 0xcd, 0xf0, 0x20, 0x3c, 0x03, 0x68, 0xd4);

// ---------------------------------------------------------------------------
// Driver / device callbacks (Driver.c, Device.c, Queue.c)
// ---------------------------------------------------------------------------

DRIVER_INITIALIZE                       DriverEntry;
EVT_WDF_OBJECT_CONTEXT_CLEANUP          FtpmSimEvtDriverContextCleanup;
EVT_WDF_DRIVER_DEVICE_ADD               FtpmSimEvtDeviceAdd;
EVT_WDF_DEVICE_D0_ENTRY                 FtpmSimEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT                  FtpmSimEvtDeviceD0Exit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL      FtpmSimEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_STOP                FtpmSimEvtIoStop;

NTSTATUS FtpmSimCreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit);
NTSTATUS FtpmSimStartCrbThread(_In_ WDFDEVICE Device);

// ---------------------------------------------------------------------------
// CRB emulation (Crb.c)
// ---------------------------------------------------------------------------

BOOLEAN FtpmSimCrbPublish(VOID);
VOID    FtpmSimCrbRelease(VOID);
KSTART_ROUTINE FtpmSimCrbWorkerThread;

// State shared between Crb.c, FtpmInit.c and Device.c.
extern PACPI_TPM2_TABLE         g_AcpiTpm2Table;        // DAT_1c0043358
extern PFTPM_CRB_CONTROL_AREA   g_CrbControl;           // DAT_1c0043360
extern PUCHAR                   g_CrbCommandBuffer;     // DAT_1c0043338 (0x2000 bytes)
extern PUCHAR                   g_CrbResponseBuffer;    // DAT_1c0043368 (0x2000 bytes)
extern PVOID                    g_CrbControlAllocation; // DAT_1c0043348 (non-NULL only when we allocated)
extern PFTPM_THREAD_CONTROL     g_ThreadControl;        // DAT_1c0043328
extern PKTHREAD                 g_WorkerThread;         // DAT_1c0043320
extern BOOLEAN                  g_CrbInitialized;       // DAT_1c0043350
extern BOOLEAN                  g_OwnsCrbPublication;   // DAT_1c0043330
extern BOOLEAN                  g_TpmStarted;           // DAT_1c0043331: FtpmInit() completed
extern BOOLEAN                  g_NvImportedFromFirmware; // DAT_1c0043351
extern BOOLEAN                  g_CrbCmdReady;          // DAT_1c0043352
extern ULONG                    g_CrbIdlePolls;         // DAT_1c0043340

// ---------------------------------------------------------------------------
// FTPMInit (FtpmInit.c)
// ---------------------------------------------------------------------------

VOID FtpmInit(VOID);
