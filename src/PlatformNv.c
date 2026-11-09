// PlatformNv.c - NV storage of the simulated TPM (NVChip.dat on the EFI system partition)
//
// RE: 0x1c0036e58 _plat__NVEnable        0x1c0036ab8 FtpmNvLoadFromFile
//     0x1c0036d80 _plat__NvCommit        0x1c0037190 _plat__NVDisable (_plat__Signal_PowerOff tail-calls it)
//     0x1c0036cc8 FtpmQuerySystemPartition
//
// Persistence model:
//
//   * The 32 KiB image g_NvImage lives in the driver's .data. The TPM library
//     reads and writes it through _plat__NvMemory*() (inlined into the library
//     functions in the shipped binary; the range checks produce the strings
//     "_plat__NvMemoryRead/Write/Clear/Move" seen in the binary).
//   * Backing store: file "NVChip.dat" on the *EFI system partition*. The partition
//     path is read from HKLM\System\Setup\SystemPartition (a NT device path such
//     as \Device\HarddiskVolume2) with RtlQueryRegistryValuesEx, then
//     "\EFI\Microsoft\Boot\NVChip.dat" is tried, falling back to "\Boot\NVChip.dat".
//   * The file is created (FILE_OPEN_IF) and, when new, zero filled to 0x8000 bytes.
//   * Everything that touches the file runs only at PASSIVE_LEVEL, otherwise the
//     call silently does nothing.
//   * The whole image is rewritten at offset 0 on every commit; there is no journal.

#include "FtpmSim.h"

UCHAR           g_NvImage[FTPM_NV_IMAGE_SIZE];
TPM_CHIP_STATE  g_ChipFlags;
BOOLEAN         g_NvIsInitialized;
BOOLEAN         g_NvImported;
BOOLEAN         g_NvNeedManufacture;

static HANDLE           s_NvFile;                   // .data 0x1c004bc18
static UNICODE_STRING   s_SystemPartition;          // .data 0x1c004bc30 (Buffer allocated by RtlQueryRegistryValues)
static ULONG            s_NvChecksum;               // .data 0x1c004bc10 (checksum last read from / written to the file)
static ULONG64          s_ExpectedRevision;         // .data 0x1c004bc28

typedef NTSTATUS (NTAPI *PFN_RTL_QUERY_REGISTRY_VALUES_EX)(
    _In_ ULONG RelativeTo,
    _In_ PCWSTR Path,
    _In_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Environment);

//
// NV memory primitives, as inlined in the binary. Range violations end in
// TpmFail(<function>, <line>, FATAL_ERROR_PARAMETER); the line numbers are those of
// the Windows source of NVMem.c (0x1df read, 0x1ef write, 0x1fe clear, 0x20f move).
//
VOID
_plat__NvMemoryRead(
    ULONG StartOffset,
    ULONG Size,
    PVOID Data
    )
{
    if ((ULONG64)StartOffset + Size > FTPM_NV_IMAGE_SIZE)
    {
        FTPM_FAIL("_plat__NvMemoryRead", 0x1df, FATAL_ERROR_PARAMETER);
        return;
    }
    RtlCopyMemory(Data, g_NvImage + StartOffset, Size);
}

VOID
_plat__NvMemoryWrite(
    ULONG StartOffset,
    ULONG Size,
    const VOID *Data
    )
{
    if ((ULONG64)StartOffset + Size > FTPM_NV_IMAGE_SIZE)
    {
        FTPM_FAIL("_plat__NvMemoryWrite", 0x1ef, FATAL_ERROR_PARAMETER);
        return;
    }
    RtlCopyMemory(g_NvImage + StartOffset, Data, Size);
}

VOID
_plat__NvMemoryClear(
    ULONG StartOffset,
    ULONG Size
    )
{
    // Unlike read/write (limit 0x8000, so the admin sections stay reachable), clear is
    // limited to the TPM NV area. The Windows build zeroes the range (ms-tpm-20-ref
    // fills with 0xff).
    if ((ULONG64)StartOffset + Size > FTPM_NV_TPM_SIZE)
    {
        FTPM_FAIL("_plat__NvMemoryClear", 0x1fe, FATAL_ERROR_PARAMETER);
        return;
    }
    RtlZeroMemory(g_NvImage + StartOffset, Size);
}

VOID
_plat__NvMemoryMove(
    ULONG SourceOffset,
    ULONG DestOffset,
    ULONG Size
    )
{
    if ((ULONG64)SourceOffset + Size > FTPM_NV_IMAGE_SIZE)
    {
        FTPM_FAIL("_plat__NvMemoryMove", 0x20f, FATAL_ERROR_PARAMETER);
        return;
    }
    if ((ULONG64)DestOffset + Size > FTPM_NV_IMAGE_SIZE)
    {
        FTPM_FAIL("_plat__NvMemoryMove", 0x210, FATAL_ERROR_PARAMETER);
        return;
    }
    RtlMoveMemory(g_NvImage + DestOffset, g_NvImage + SourceOffset, Size);
}

// Library helpers of ms-tpm-20-ref's platform interface (NvDynamic.c, NvReserved.c). In the
// binary both are folded into their callers: the comparison is a memcmp against the
// image and NV is always available.
int
_plat__NvIsDifferent(
    ULONG StartOffset,
    ULONG Size,
    PVOID Data
    )
{
    if ((ULONG64)StartOffset + Size > FTPM_NV_IMAGE_SIZE)
    {
        FTPM_FAIL("_plat__NvIsDifferent", __LINE__, FATAL_ERROR_PARAMETER);   // RE: no such function in the binary
        return TRUE;
    }
    return RtlCompareMemory(g_NvImage + StartOffset, Data, Size) != Size;
}

int
_plat__IsNvAvailable(
    VOID
    )
{
    return 0;       // 0: available, 1: recoverable error, 2: unrecoverable
}

// -(sum of the first 0x4000 image bytes), the "negative checksum" stored at 0x7bf4.
static ULONG
FtpmNvComputeChecksum(
    VOID
    )
{
    ULONG sum = 0;
    ULONG i;

    for (i = 0; i < FTPM_NV_TPM_SIZE; i++)
    {
        sum += g_NvImage[i];
    }
    return (ULONG)(0 - sum);
}

//
// Reads HKLM\System\Setup\SystemPartition into s_SystemPartition.
//
static BOOLEAN
FtpmQuerySystemPartition(
    VOID
    )
{
    RTL_QUERY_REGISTRY_TABLE            queryTable[2];
    UNICODE_STRING                      routineName;
    PFN_RTL_QUERY_REGISTRY_VALUES_EX    queryEx;
    NTSTATUS                            status;

    RtlZeroMemory(queryTable, sizeof(queryTable));
    queryTable[0].Flags         = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
    queryTable[0].Name          = FTPM_SYSTEM_PARTITION_VALUE;
    queryTable[0].EntryContext  = &s_SystemPartition;

    RtlInitUnicodeString(&routineName, L"RtlQueryRegistryValuesEx");
    queryEx = (PFN_RTL_QUERY_REGISTRY_VALUES_EX)MmGetSystemRoutineAddress(&routineName);

    status = queryEx(RTL_REGISTRY_ABSOLUTE, FTPM_SETUP_KEY_PATH, queryTable, NULL, NULL);
    return NT_SUCCESS(status);
}

//
// Writes the whole image to NVChip.dat (the "commit" of the platform layer).
// On a write error the file handle is closed and dropped; the image is then only
// in memory until the next _plat__NVEnable().
//
int
_plat__NvCommit(
    VOID
    )
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER   offset;
    NTSTATUS        status;

    if (s_NvFile == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return 0;
    }

    s_NvChecksum = FtpmNvComputeChecksum();
    *(UNALIGNED ULONG*)(g_NvImage + FTPM_NV_CHECKSUM_OFFSET) = s_NvChecksum;

    offset.QuadPart = 0;
    status = ZwWriteFile(s_NvFile, NULL, NULL, NULL, &iosb, g_NvImage, FTPM_NV_IMAGE_SIZE, &offset, NULL);
    if (!NT_SUCCESS(status))
    {
        ZwClose(s_NvFile);
        s_NvFile = NULL;
    }

    // The library's NvCommit() tests the result for 0; the binary never reports a failure.
    return 0;
}

//
// Re-reads NVChip.dat into the image. A file whose revision or checksum does not
// match is replaced by the current (blank) image. A file that cannot be read is
// closed and the TPM runs from the in-memory image only.
//
BOOLEAN
FtpmNvLoadFromFile(
    VOID
    )
{
    PUCHAR          buffer;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER   offset;
    NTSTATUS        status;
    ULONG64         revision;
    PCSTR           message;
    ULONG           i, sum;

    if (s_NvFile == NULL || g_NvImported || KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, FTPM_NV_IMAGE_SIZE, FTPM_POOL_TAG);
    if (buffer == NULL)
    {
        message = "fTPMsim: Unable to load existing NVChip.dat!\n";
        goto Failure;
    }

    offset.QuadPart = 0;
    status = ZwReadFile(s_NvFile, NULL, NULL, NULL, &iosb, buffer, FTPM_NV_IMAGE_SIZE, &offset, NULL);
    if (!NT_SUCCESS(status))
    {
        message = "fTPMsim: Unable to read existing NVChip.dat!\n";
        goto Failure;
    }

    revision = *(UNALIGNED ULONG64*)(buffer + FTPM_NV_REVISION_OFFSET);
    if (revision != s_ExpectedRevision)
    {
        DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_ERROR,
                   "fTPM: NVChip revision (0x%08x%08x) does not match expected value (0x%08x%08x)!\n",
                   (ULONG)(revision >> 32), (ULONG)revision,
                   (ULONG)(FTPM_NV_CHIP_REVISION >> 32), (ULONG)(FTPM_NV_CHIP_REVISION & 0xffffffff));
        _plat__NvCommit();      // replace the foreign file by the blank image
    }
    else
    {
        s_NvChecksum = *(UNALIGNED ULONG*)(buffer + FTPM_NV_CHECKSUM_OFFSET);
        if (s_NvChecksum != 0)
        {
            sum = 0;
            for (i = 0; i < FTPM_NV_TPM_SIZE; i++)
            {
                sum += buffer[i];
            }
            if ((ULONG)(0 - sum) != s_NvChecksum)
            {
                DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_ERROR, "fTPMsim: NVChip failed checksum!\n");
                _plat__NvCommit();
                ExFreePoolWithTag(buffer, FTPM_POOL_TAG);
                return TRUE;
            }
        }

        RtlCopyMemory(g_NvImage, buffer, FTPM_NV_IMAGE_SIZE);
        g_NvNeedManufacture = FALSE;
        g_NvIsInitialized   = TRUE;
    }

    ExFreePoolWithTag(buffer, FTPM_POOL_TAG);
    return TRUE;

Failure:
    DbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_ERROR, message);
    if (s_NvFile != NULL)
    {
        ZwClose(s_NvFile);
        s_NvFile = NULL;
    }
    if (buffer != NULL)
    {
        ExFreePoolWithTag(buffer, FTPM_POOL_TAG);
    }
    return FALSE;
}

//
// Opens (creating if necessary) NVChip.dat and prepares the in-memory image.
//
// Returns TRUE if an existing file with the right size was opened (the caller then
// loads it), FALSE if the file was just created, could not be opened, or has the
// wrong size. The TPM library calls this from _TPM_Init() when power was lost.
//
int
_plat__NVEnable(
    _In_opt_ PVOID PlatParameter
    )
{
    UNICODE_STRING      path;
    OBJECT_ATTRIBUTES   objectAttributes;
    IO_STATUS_BLOCK     iosb;
    FILE_STANDARD_INFORMATION standardInfo;
    NTSTATUS            status;
    PVOID               pathBuffer;
    UCHAR               zeros[0x200];
    ULONG               written;
    int                 result;

    UNREFERENCED_PARAMETER(PlatParameter);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FALSE;
    }

    if (!g_NvIsInitialized)
    {
        RtlZeroMemory(g_NvImage, FTPM_NV_IMAGE_SIZE);
        s_ExpectedRevision = FTPM_NV_CHIP_REVISION;
        *(UNALIGNED ULONG64*)(g_NvImage + FTPM_NV_REVISION_OFFSET) = FTPM_NV_CHIP_REVISION;
        g_NvIsInitialized = TRUE;
        if (!g_NvImported)
        {
            g_ChipFlags.Flags   = 0;
            g_NvNeedManufacture = TRUE;
        }
    }

    if (s_SystemPartition.Length == 0 && !FtpmQuerySystemPartition())
    {
        return FALSE;
    }

    pathBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, s_SystemPartition.Length + 0x3c, FTPM_POOL_TAG);
    if (pathBuffer == NULL)
    {
        return FALSE;
    }

    path.Length        = 0;
    path.MaximumLength = (USHORT)(s_SystemPartition.Length + 0x3c);
    path.Buffer        = (PWCH)pathBuffer;
    RtlAppendUnicodeStringToString(&path, &s_SystemPartition);
    RtlAppendUnicodeToString(&path, FTPM_NV_FILE_PATH_ESP);

    InitializeObjectAttributes(&objectAttributes, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&s_NvFile, GENERIC_ALL, &objectAttributes, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        // Not a Windows-style ESP layout: try \Boot\NVChip.dat.
        path.Length = 0;
        RtlAppendUnicodeStringToString(&path, &s_SystemPartition);
        RtlAppendUnicodeToString(&path, FTPM_NV_FILE_PATH_ESP_FALLBACK);

        InitializeObjectAttributes(&objectAttributes, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwCreateFile(&s_NvFile, GENERIC_ALL, &objectAttributes, &iosb, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                              FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(pathBuffer, FTPM_POOL_TAG);
            return FALSE;
        }
    }

    if (iosb.Information == FILE_CREATED)
    {
        // New file: pre-extend it with zeroes to the full image size.
        RtlZeroMemory(zeros, sizeof(zeros));
        for (written = 0; written < FTPM_NV_IMAGE_SIZE; written += sizeof(zeros))
        {
            status = ZwWriteFile(s_NvFile, NULL, NULL, NULL, &iosb, zeros, sizeof(zeros), NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                FTPM_FAIL("_plat__NVEnable", 0x18b, FATAL_ERROR_PARAMETER);
            }
        }
        result = FALSE;
    }
    else
    {
        status = ZwQueryInformationFile(s_NvFile, &iosb, &standardInfo, sizeof(standardInfo),
                                        FileStandardInformation);
        if (!NT_SUCCESS(status) || standardInfo.EndOfFile.LowPart != FTPM_NV_IMAGE_SIZE)
        {
            ExFreePoolWithTag(pathBuffer, FTPM_POOL_TAG);
            return FALSE;       // the handle stays open, as in the binary
        }
        result = TRUE;
    }

    if (g_NvImported)
    {
        // The image came from the firmware hand-off: make the file match it.
        _plat__NvCommit();
    }

    ExFreePoolWithTag(pathBuffer, FTPM_POOL_TAG);
    return result;
}

// Flush the image and close the file. Also the body of _plat__Signal_PowerOff().
VOID
_plat__NVDisable(
    VOID
    )
{
    if (s_NvFile != NULL && KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        _plat__NvCommit();
        ZwClose(s_NvFile);
        s_NvFile = NULL;
    }
}

// FtpmInit() needs to know whether the NV file is currently open.
BOOLEAN
FtpmNvIsFileOpen(
    VOID
    )
{
    return (BOOLEAN)(s_NvFile != NULL);
}