// FtpmInit.c - lazy power-up of the simulated TPM
//
// RE: 0x1c00042d8 FTPMInit (the strings "FTPMInit: ..." belong to it)
//
// Called by the worker thread in front of every command. The first call after the
// driver started (or after a D0Exit) brings the whole TPM up:
//
//   1. builds the admin section table behind the TPM NV area (_admin__NvInitState)
//   2. optionally imports an NV image handed over by pre-boot firmware through the
//      TPM2 table (LAML field, a 32-bit physical address of a 0x8000 byte image)
//   3. opens/loads NVChip.dat, manufactures the TPM if the chip is blank
//   4. closes the file, powers the platform on, runs _TPM_Init()
//   5. sends TPM2_Startup(STATE) when the image says a saved TPM state is present,
//      otherwise (or if that fails) TPM2_Startup(CLEAR)
//   6. copies the saved runtime sections (RAM state, PCRs, DRTM handle) over the
//      library's globals, clears the chip flags and stores them back into the image
//
// Later calls (g_TpmStarted already set) only repair the case where the NV file
// handle was lost.

#include "FtpmSim.h"

// Globals of the TPM library that the saved state is copied into. In the binary
// these are plain .data addresses; the names follow ms-tpm-20-ref Global.h.
extern UCHAR  s_objects[];              // .data 0x1c004ccc0 OBJECT s_objects[MAX_LOADED_OBJECTS] (Global.c); only the first 0xc0 bytes are saved
extern UCHAR  s_pcrs[];                 // .data 0x1c004e8a0 24 PCRs x 100 bytes
extern ULONG  g_DRTMHandle;             // .data 0x1c0050bc4

// TPM2_Startup(TPM_SU_STATE) and TPM2_Startup(TPM_SU_CLEAR), TPM_ST_NO_SESSIONS, 12 bytes.
static const UCHAR s_StartupState[12] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x01 };
static const UCHAR s_StartupClear[12] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00 };

ULONG g_NvSectionSize[NV_STATE_COUNT];
ULONG g_NvSectionOffset[NV_STATE_COUNT];

// _admin__NvInitState(): lay the sections out back to back behind the TPM NV area.
static VOID
FtpmAdminNvInitState(
    VOID
    )
{
    ULONG offset = FTPM_NV_TPM_SIZE;
    ULONG i;

    g_NvSectionSize[NV_STATE_CHIP_FLAGS]   = 4;
    g_NvSectionSize[NV_STATE_DRTM_OBJECT]  = 0xc0;
    g_NvSectionSize[NV_STATE_PCRS]         = 0x960;
    g_NvSectionSize[NV_STATE_DRTM_HANDLE]  = 4;
    g_NvSectionSize[NV_STATE_PERSISTENT_COPY]   = 0x318;
    g_NvSectionSize[NV_STATE_RESERVED_5]   = 4;
    g_NvSectionSize[NV_STATE_PPI]          = sizeof(FTPM_PPI_STATE);
    g_NvSectionSize[NV_STATE_RESERVED_7]   = 0x400;

    for (i = 0; i < NV_STATE_COUNT; i++)
    {
        g_NvSectionOffset[i] = offset;
        offset += g_NvSectionSize[i];
    }

    if (offset > FTPM_NV_IMAGE_SIZE)
    {
        FTPM_FAIL("_admin__NvInitState", 0x59, FATAL_ERROR_PARAMETER);
    }
}

static VOID
FtpmNvReadSection(
    _In_ NV_STATE_SECTION Section,
    _Out_ PVOID Destination
    )
{
    _plat__NvMemoryRead(g_NvSectionOffset[Section], g_NvSectionSize[Section], Destination);
}

static VOID
FtpmNvWriteSection(
    _In_ NV_STATE_SECTION Section,
    _In_ const VOID *Source
    )
{
    _plat__NvMemoryWrite(g_NvSectionOffset[Section], g_NvSectionSize[Section], Source);
}

// Picks up the NV image a pre-boot simulator left behind (TPM2.LAML = physical address).
// The mapping is never released in the binary.
static VOID
FtpmImportFirmwareNvImage(
    VOID
    )
{
    PHYSICAL_ADDRESS physical;
    PVOID            mapped;

    physical.QuadPart = g_AcpiTpm2Table->Laml;
    g_NvImportedFromFirmware = TRUE;

    mapped = MmMapIoSpaceEx(physical, FTPM_NV_IMAGE_SIZE, PAGE_READWRITE);
    RtlCopyMemory(g_NvImage, mapped, FTPM_NV_IMAGE_SIZE);

    g_NvNeedManufacture = FALSE;
    g_NvIsInitialized   = TRUE;
    g_NvImported        = TRUE;

    FtpmNvReadSection(NV_STATE_CHIP_FLAGS, &g_ChipFlags);

    g_AcpiTpm2Table->Laml = 0;      // consume the hand-off
}

// The saved sections are only meaningful after Startup(STATE) has been attempted.
static VOID
FtpmRestoreSavedTpmState(
    VOID
    )
{
    FtpmNvReadSection(NV_STATE_DRTM_OBJECT, s_objects);
    FtpmNvReadSection(NV_STATE_PCRS,        s_pcrs);
    FtpmNvReadSection(NV_STATE_DRTM_HANDLE, &g_DRTMHandle);
}

VOID
FtpmInit(
    VOID
    )
{
    BOOLEAN needManufacture;
    int     opened;
    ULONG   responseSize;
    PUCHAR  response;
    UCHAR   command[12];

    if (g_TpmStarted)
    {
        // Already running. Only act if the NV file is closed (a previous commit or
        // read failed) and an existing file can be opened again: reload the NV image
        // from it, close it again and re-run _TPM_Init().
        opened = FtpmNvIsFileOpen() ? FALSE : _plat__NVEnable(NULL);
        if (!opened || g_NvImportedFromFirmware)
        {
            return;
        }

        FtpmNvLoadFromFile();
        _plat__NVDisable();
        _plat__Signal_PowerOn();
        _TPM_Init();
        return;
    }

    FtpmAdminNvInitState();

    if (g_AcpiTpm2Table->Laml != 0)
    {
        FtpmImportFirmwareNvImage();
        needManufacture = FALSE;
    }
    else
    {
        needManufacture = g_NvNeedManufacture;
    }

    opened = FALSE;
    if (!FtpmNvIsFileOpen())
    {
        opened = _plat__NVEnable(NULL);
        needManufacture = g_NvNeedManufacture;      // _plat__NVEnable() may have blanked the image
    }
    if (opened)
    {
        FtpmNvLoadFromFile();
        needManufacture = g_NvNeedManufacture;
    }

    if (needManufacture)
    {
        TPM_Manufacture(TRUE);
    }

    _plat__NVDisable();
    _plat__Signal_PowerOn();
    _TPM_Init();
    g_TpmStarted = TRUE;

    // RE: in the binary the response size and pointer locals are left uninitialised on
    // this path (the pointer even aliases the LAML hand-off value); they are set up
    // properly here.
    responseSize = FTPM_CRB_BUFFER_SIZE;
    response     = g_CrbResponseBuffer;

    if (g_ChipFlags.Fields.TpmStatePresent)
    {
        RtlCopyMemory(command, s_StartupState, sizeof(command));
        ExecuteCommand(sizeof(command), command, &responseSize, &response);

        // Success: response length >= 10 and responseCode (offset 6, big endian) == 0.
        if (responseSize >= 10 && RtlUlongByteSwap(*(UNALIGNED ULONG*)(response + 6)) == 0)
        {
            goto StateStarted;
        }
        DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_INFO, "FTPMInit: Failed Startup Save on first call\n");
    }
    DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_INFO, "FTPMInit: No Save State\n");

    responseSize = FTPM_CRB_BUFFER_SIZE;
    response     = g_CrbResponseBuffer;
    RtlCopyMemory(command, s_StartupClear, sizeof(command));
    ExecuteCommand(sizeof(command), command, &responseSize, &response);

StateStarted:
    if (g_ChipFlags.Fields.TpmStatePresent)
    {
        FtpmRestoreSavedTpmState();
    }

    g_ChipFlags.Flags = 0;
    FtpmNvWriteSection(NV_STATE_CHIP_FLAGS, &g_ChipFlags);
}
