#pragma once

// Platform layer of ftpmsim.sys (the "Platform" half of ms-tpm-20-ref, written
// for Windows, plus the fTPM "admin"/PPI emulation taken from the OP-TEE fTPM
// sample: github.com/microsoft/MSRSec TAs/optee_ta/fTPM/platform).

#include <ntddk.h>

// ---------------------------------------------------------------------------
// TPM library API implemented by the linked ms-tpm-20-ref code (see ..\Tpm)
// ---------------------------------------------------------------------------

VOID  ExecuteCommand(_In_ ULONG RequestSize, _In_ PUCHAR Request,
                     _Inout_ PULONG ResponseSize, _Inout_ PUCHAR *Response);
VOID  _TPM_Init(VOID);
int   TPM_Manufacture(_In_ int FirstTime);
int   TPM_TearDown(VOID);

// ms-tpm-20-ref TpmFail.c (FAIL_TRACE build, NO_LONGJMP): returns after recording the
// failure. 'Function' is __FUNCTION__ of the failing library function.
VOID  TpmFail(_In_ const char *Function, _In_ int Line, _In_ int Code);

// FATAL_ERROR_* codes passed to TpmFail().
#define FATAL_ERROR_ALLOCATION          1
#define FATAL_ERROR_DIVIDE_ZERO         2
#define FATAL_ERROR_INTERNAL            3
#define FATAL_ERROR_PARAMETER           4
#define FATAL_ERROR_NV_UNRECOVERABLE    8

// Platform layer failures use the library's own TpmFail(); the Windows build stores the
// low 32 bits of the __FUNCTION__ string address in s_failFunction.
#define FTPM_FAIL(Name, Line, Code)     TpmFail((Name), (Line), (Code))

// ---------------------------------------------------------------------------
// NV memory image
// ---------------------------------------------------------------------------
//
// The whole NV chip is one flat 32 KiB image (s_NV, .data 0x1c00439f0) backed by
// the file NVChip.dat. Layout:
//
//   0x0000 .. 0x3fff  TPM NV space seen by the library (NV_MEMORY_SIZE)
//   0x4000 .. 0x504f  "admin" sections, see NV_STATE_SECTION below
//   0x7bf4            UINT32 checksum  = -(sum of bytes 0x0000..0x3fff); 0 = unchecked
//   0x7bf8            UINT64 chip revision, must equal FTPM_NV_CHIP_REVISION
//
#define FTPM_NV_IMAGE_SIZE              0x8000
#define FTPM_NV_TPM_SIZE                0x4000
#define FTPM_NV_CHECKSUM_OFFSET         0x7bf4
#define FTPM_NV_REVISION_OFFSET         0x7bf8
#define FTPM_NV_CHIP_REVISION           0x0011540020170213ULL   // constant in .text (0x1c0037180)

#define FTPM_NV_FILE_PATH_ESP           L"\\EFI\\Microsoft\\Boot\\NVChip.dat"
#define FTPM_NV_FILE_PATH_ESP_FALLBACK  L"\\Boot\\NVChip.dat"
#define FTPM_SETUP_KEY_PATH             L"\\Registry\\Machine\\System\\Setup"
#define FTPM_SYSTEM_PARTITION_VALUE     L"SystemPartition"

// _admin__NvInitState(): runtime state kept after the TPM NV space.
// The binary builds this table at the first FtpmInit() call (0x1c00042d8) with
// the sizes below, starting at FTPM_NV_TPM_SIZE and packing back to back; the
// sum is checked against the 0x8000 image size.
typedef enum _NV_STATE_SECTION
{
    NV_STATE_CHIP_FLAGS = 0,        // 0x004 TPM_CHIP_STATE (Remanufacture | TpmStatePresent)
    NV_STATE_DRTM_OBJECT,           // 0x0c0 head of s_objects[0] (.data 0x1c004ccc0): the DRTM event sequence object that g_DRTMHandle indexes
    NV_STATE_PCRS,                  // 0x960 restored into .data 0x1c004e8a0 (s_pcrs: 24 PCRs x (SHA-1+SHA-256+SHA-384) = 24*100)
    NV_STATE_DRTM_HANDLE,           // 0x004 restored into .data 0x1c0050bc4 (g_DRTMHandle)
    NV_STATE_PERSISTENT_COPY,       // 0x318 == sizeof(gp) of the shipped library (PERSISTENT_DATA); sized but never read or written
    NV_STATE_RESERVED_5,            // 0x004 never touched
    NV_STATE_PPI,                   // 0x00c FTPM_PPI_STATE (pending op, last-boot op, response)
    NV_STATE_RESERVED_7,            // 0x400 never touched
    NV_STATE_COUNT
} NV_STATE_SECTION;

typedef union _TPM_CHIP_STATE
{
    ULONG Flags;
    struct
    {
        ULONG Remanufacture   : 1;
        ULONG TpmStatePresent : 1;      // set once Startup(STATE) state is held in the saved sections
        ULONG Reserved        : 30;
    } Fields;
} TPM_CHIP_STATE;

#include <pshpack1.h>
typedef struct _FTPM_PPI_STATE
{
    ULONG PendingPseudoOp;
    ULONG PseudoOpFromLastBoot;
    ULONG ReturnResponse;
} FTPM_PPI_STATE;
#include <poppack.h>

extern UCHAR            g_NvImage[FTPM_NV_IMAGE_SIZE];  // .data 0x1c00439f0
extern TPM_CHIP_STATE   g_ChipFlags;                    // .data 0x1c004bc70
extern ULONG            g_NvSectionSize[NV_STATE_COUNT];    // 0x1c00439b0
extern ULONG            g_NvSectionOffset[NV_STATE_COUNT];  // 0x1c00439d0

// ---------------------------------------------------------------------------
// Platform API (ms-tpm-20-ref Platform_fp.h names where they exist)
// ---------------------------------------------------------------------------

// PlatformNv.c
int     _plat__NVEnable(_In_opt_ PVOID PlatParameter);  // returns TRUE if an existing, valid NVChip.dat was opened
VOID    _plat__NVDisable(VOID);                         // commit + close (== _plat__Signal_PowerOff)
int     _plat__NvCommit(VOID);                          // write the 32 KiB image back (checksum refreshed); always returns 0
BOOLEAN FtpmNvLoadFromFile(VOID);                       // 0x1c0036ab8
BOOLEAN FtpmNvIsFileOpen(VOID);
VOID    _plat__NvMemoryRead(ULONG StartOffset, ULONG Size, PVOID Data);
VOID    _plat__NvMemoryWrite(ULONG StartOffset, ULONG Size, const VOID *Data);
VOID    _plat__NvMemoryClear(ULONG StartOffset, ULONG Size);
VOID    _plat__NvMemoryMove(ULONG SourceOffset, ULONG DestOffset, ULONG Size);
int     _plat__NvIsDifferent(ULONG StartOffset, ULONG Size, PVOID Data);
int     _plat__IsNvAvailable(VOID);

// PlatformPower.c / PlatformClock.c
int     _plat__Signal_PowerOn(VOID);
int     _plat__Signal_PowerOff(VOID);
int     _plat__Signal_Reset(VOID);
int     _plat__WasPowerLost(VOID);
int     _plat__IsCanceled(VOID);
UCHAR   _plat__LocalityGet(VOID);
int     _plat__PhysicalPresenceAsserted(VOID);
ULONG64 _plat__TimerRead(VOID);
VOID    _plat__TimerReset(VOID);
VOID    _plat__TimerRestart(VOID);
int     _plat__TimerWasReset(VOID);
int     _plat__TimerWasStopped(VOID);
VOID    _plat__ClockAdjustRate(int Adjustment);

// PlatformEntropy.c
ULONG   FtpmGetEntropy(_Out_writes_bytes_(Size) PUCHAR Buffer, _In_ ULONG Size);
LONG    _plat__GetEntropy(_Out_writes_bytes_opt_(Amount) PUCHAR Entropy, _In_ ULONG Amount);
ULONG   _plat__GetUnique(_In_ ULONG Which, _In_ ULONG Size, _Out_writes_bytes_(Size) PUCHAR Buffer);

// PlatformAdminPpi.c
int     _admin__PPICommand(_In_ ULONG CommandSize, _In_reads_bytes_(CommandSize) PUCHAR CommandBuffer,
                           _Inout_ PULONG ResponseSize, _Inout_ PUCHAR *ResponseBuffer);

// PlatformFail.c
VOID    _plat__Fail(VOID);
VOID    FtpmDebugPrint(_In_z_ PCSTR Format, ...);       // vDbgPrintEx(IHVDRIVER, INFO, ...) wrapper (0x1c0037758)

// Exported only for the simulator/UEFI front end (see ftpmsim.def).
extern BOOLEAN  g_NvIsInitialized;      // .data 0x1c004bc0c  image is valid (zeroed or loaded)
extern BOOLEAN  g_NvImported;           // .data 0x1c004bc0d  image came from firmware, file still has to be written
extern BOOLEAN  g_NvNeedManufacture;    // .data 0x1c004bc20