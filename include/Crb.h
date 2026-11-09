#pragma once

// ACPI TPM2 table and TCG PC Client Platform TPM Profile (PTP) CRB layouts as
// used by ftpmsim.sys.

#include <ntddk.h>

// 'TPM2' ACPI table signature.
#define ACPI_TPM2_SIGNATURE             0x324D5054

// Start methods of the TPM2 table (TCG ACPI spec). ftpmsim forces CRB.
#define ACPI_TPM2_START_METHOD_CRB      7

// The driver only works with revision 3 of the table (the binary rejects every
// other revision).
#define ACPI_TPM2_EXPECTED_REVISION     3

//
// Private marker written into StartMethodSpecificParameters[0..7] of the TPM2
// table once the simulator has taken the table over. The bytes are the string
// "SIMULATE" reversed ("ETALUMIS"); the binary keeps it as the two dwords
// 'ETAL' (+0x34) and 'UMIS' (+0x38) of the literal "TPM2UMISETAL".
//
#define FTPM_SIM_MARKER_LO              'LATE'      // bytes "ETAL" at +0x34
#define FTPM_SIM_MARKER_HI              'SIMU'      // bytes "UMIS" at +0x38

#include <pshpack1.h>

typedef struct _ACPI_TPM2_TABLE
{
    ULONG   Signature;                              // +0x00 'TPM2'
    ULONG   Length;                                 // +0x04
    UCHAR   Revision;                               // +0x08
    UCHAR   Checksum;                               // +0x09
    UCHAR   OemId[6];                               // +0x0a
    UCHAR   OemTableId[8];                          // +0x10
    ULONG   OemRevision;                            // +0x18
    ULONG   CreatorId;                              // +0x1c
    ULONG   CreatorRevision;                        // +0x20
    ULONG   PlatformClassAndReserved;               // +0x24 PlatformClass(2) + Reserved(2), forced to 0
    ULONG64 ControlAddress;                         // +0x28 physical address of the CRB control area
    ULONG   StartMethod;                            // +0x30
    ULONG   MarkerLow;                              // +0x34 StartMethodSpecificParameters[0..3]
    ULONG   MarkerHigh;                             // +0x38 StartMethodSpecificParameters[4..7]
    ULONG   StartMethodParametersTail;              // +0x3c
    ULONG   Laml;                                   // +0x40 reused: physical address of a 32 KiB NV image
                                                    //       left by a pre-boot simulator (0 = none)
    ULONG64 Lasa;                                   // +0x44
} ACPI_TPM2_TABLE, *PACPI_TPM2_TABLE;

#include <poppack.h>

//
// CRB control area (TCG PTP spec, "Control Area" at locality-relative 0x40).
// The driver maps / uses the first 0x20 bytes (up to and including
// CRB_CTRL_CMD_HADDR) and the response address qword at 0x28.
//
// Register semantics as implemented by the polling thread:
//   Request  1 = cmdReady, 2 = goIdle
//   Status   bit1 (value 2) = tpmIdle; bit0 would be tpmSts (never set)
//   Start    1 = execute the command in the command buffer
//
#include <pshpack4.h>

typedef struct _FTPM_CRB_CONTROL_AREA
{
    volatile ULONG Request;                         // +0x00 CRB_CTRL_REQ
    volatile ULONG Status;                          // +0x04 CRB_CTRL_STS
    volatile ULONG Cancel;                          // +0x08 CRB_CTRL_CANCEL (ignored by the driver)
    volatile ULONG Start;                           // +0x0c CRB_CTRL_START
    ULONG   InterruptEnable;                        // +0x10
    ULONG   InterruptStatus;                        // +0x14
    ULONG   CommandSize;                            // +0x18 CRB_CTRL_CMD_SIZE (0x2000)
    ULONG64 CommandAddress;                         // +0x1c physical address of the command buffer
    ULONG   ResponseSize;                           // +0x24 CRB_CTRL_RSP_SIZE (0x2000)
    ULONG64 ResponseAddress;                        // +0x28 physical address of the response buffer
} FTPM_CRB_CONTROL_AREA, *PFTPM_CRB_CONTROL_AREA;

#include <poppack.h>

#define FTPM_CRB_REQ_CMD_READY          1
#define FTPM_CRB_REQ_GO_IDLE            2
#define FTPM_CRB_STS_TPM_IDLE           2
#define FTPM_CRB_START_COMMAND          1

#define FTPM_CRB_CONTROL_AREA_ALLOC     0x1000      // contiguous, MmNonCached
#define FTPM_CRB_CONTROL_AREA_MAP_SIZE  0x20        // size mapped when attaching to an existing area
#define FTPM_CRB_BUFFER_SIZE            0x2000      // command and response buffers

//
// 8 bytes of non-cached contiguous memory shared with the worker thread. Only the
// second dword is used: D0Exit sets StopRequested, the thread polls it.
//
typedef struct _FTPM_THREAD_CONTROL
{
    ULONG Reserved;
    volatile ULONG StopRequested;
} FTPM_THREAD_CONTROL, *PFTPM_THREAD_CONTROL;
