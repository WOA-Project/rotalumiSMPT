// PlatformAdminPpi.c - emulated TCG Physical Presence Interface (PPI)
//
// RE: 0x1c0037378 _admin__PPICommand
//     0x1c00371e8 ExecutePPICommand
//
// Same code as AdminPPI.c of the OP-TEE fTPM sample (github.com/microsoft/MSRSec,
// TAs/optee_ta/fTPM/platform), adapted to the NV admin sections of this driver.
//
// The OS PPI ACPI _DSM is mapped onto a vendor TPM command, TPM_CC_EmulatePPI
// (0x200001FF), that the CRB worker thread offers to _admin__PPICommand() before it
// calls ExecuteCommand(). Command layout (big endian):
//
//   TPM_ST_NO_SESSIONS(0x8001) | paramSize | 0x200001FF | FunctionIndex | [Op]
//
// Response: 0x8001 | size | responseCode | up to three UINT32 results (see below).
// Only the pending operation is recorded; nothing here ever acts on it.

#include "FtpmSim.h"

#define TPM_CC_EMULATE_PPI              0x200001FF
#define TPM_ST_NO_SESSIONS_VALUE        0x8001
#define TPM_RC_SUCCESS_VALUE            0x000
#define TPM_RC_BAD_TAG_VALUE            0x01E
#define TPM_RC_FAILURE_VALUE            0x101
#define TPM_RC_COMMAND_SIZE_VALUE       0x142

#define TPM2_COMMAND_HEADER_SIZE        10
#define PPI_VERSION_1_2                 0x00322E31      // "1.2"
#define PPI_QUERY_FUNCTIONS_MASK        0x1AB           // per PPI 1.2 specification

// PPI function indices (_DSM function numbers).
#define PPI_CMD_QUERY                   0
#define PPI_CMD_VERSION                 1
#define PPI_CMD_SUBMIT_OP_REQ           2
#define PPI_CMD_GET_PENDING_OP          3
#define PPI_CMD_GET_PLATFORM_ACTION     4
#define PPI_CMD_RETURN_OP_RESP          5
#define PPI_CMD_SUBMIT_USER_LANG        6
#define PPI_CMD_SUBMIT_OP_REQ2          7
#define PPI_CMD_GET_USER_CONF           8

#define PPI_OP_CLEAR                    5
#define PPI_OP_C_E_A                    14
#define PPI_OP_SET_NO_CLEAR_FALSE       17
#define PPI_OP_SET_NO_CLEAR_TRUE        18
#define PPI_OP_E_A_C                    21
#define PPI_OP_E_A_C_E_A                22

#include <pshpack1.h>
typedef struct _PPI_RESPONSE
{
    USHORT Tag;
    ULONG  ResponseSize;
    ULONG  ResponseCode;
    ULONG  Result1;
    ULONG  Result2;
    ULONG  Result3;
} PPI_RESPONSE;
#include <poppack.h>

static FTPM_PPI_STATE   s_PpiState;         // .data 0x1c004ba08
static PPI_RESPONSE     s_PpiResponse;      // .data 0x1c004b9f0

static ULONG
ReadBigEndian32(
    _In_ const UCHAR *Bytes
    )
{
    return ((ULONG)Bytes[0] << 24) | ((ULONG)Bytes[1] << 16) | ((ULONG)Bytes[2] << 8) | Bytes[3];
}

static VOID
ExecutePpiCommand(
    _In_  ULONG  FunctionIndex,
    _In_  ULONG  Op,
    _Out_ PULONG Result1,
    _Out_ PULONG Result2,
    _Out_ PULONG Result3
    )
{
    ULONG section = g_NvSectionOffset[NV_STATE_PPI];

    // _admin__RestorePPIState()
    _plat__NvMemoryRead(section, g_NvSectionSize[NV_STATE_PPI], &s_PpiState);

    *Result1 = 0;
    *Result2 = 0;
    *Result3 = 0;

    switch (FunctionIndex)
    {
    case PPI_CMD_QUERY:
        *Result1 = PPI_QUERY_FUNCTIONS_MASK;
        break;

    case PPI_CMD_VERSION:
        *Result1 = PPI_VERSION_1_2;
        break;

    case PPI_CMD_SUBMIT_OP_REQ:
    case PPI_CMD_GET_PLATFORM_ACTION:
        *Result1 = 2;                       // reboot / general failure
        break;

    case PPI_CMD_GET_PENDING_OP:
        *Result1 = 0;
        *Result2 = s_PpiState.PendingPseudoOp;
        break;

    case PPI_CMD_RETURN_OP_RESP:
        *Result1 = 0;
        *Result2 = s_PpiState.PseudoOpFromLastBoot;
        *Result3 = s_PpiState.ReturnResponse;
        break;

    case PPI_CMD_SUBMIT_OP_REQ2:
        // Everything up to op 16 and ops 19..22 is accepted; SET_NO_CLEAR_* (17, 18)
        // and the reserved/vendor range are "not implemented".
        if (Op <= 16 || (Op - 19) < 4)
        {
            *Result1 = 0;
            s_PpiState.PendingPseudoOp = Op;

            // _admin__SavePPIState()
            _plat__NvMemoryWrite(section, g_NvSectionSize[NV_STATE_PPI], &s_PpiState);
            _plat__NvCommit();
        }
        else
        {
            *Result1 = 1;
        }
        break;

    case PPI_CMD_GET_USER_CONF:
        if (Op < 12)
        {
            *Result1 = (Op == PPI_OP_CLEAR) ? 3 : 4;    // 3 = allowed, PP user required; 4 = allowed, not required
        }
        else if (Op == PPI_OP_C_E_A || Op == PPI_OP_E_A_C || Op == PPI_OP_E_A_C_E_A)
        {
            *Result1 = 3;
        }
        else
        {
            *Result1 = 0;                               // not implemented
        }
        break;

    case PPI_CMD_SUBMIT_USER_LANG:
        *Result1 = 3;                       // not implemented
        break;

    default:
        break;
    }
}

//
// Returns 1 if the buffer held a TPM_CC_EmulatePPI command (a response has been
// produced in *ResponseBuffer, even if it is an error), 0 if the command is not a
// PPI command and must be passed to the TPM. Commands shorter than a TPM header are
// consumed with TPM_RC_COMMAND_SIZE.
//
int
_admin__PPICommand(
    _In_ ULONG   CommandSize,
    _In_reads_bytes_(CommandSize) PUCHAR CommandBuffer,
    _Inout_ PULONG  ResponseSize,
    _Inout_ PUCHAR *ResponseBuffer
    )
{
    ULONG   responseCode = TPM_RC_SUCCESS_VALUE;
    ULONG   numberResults = 0;
    ULONG   functionIndex;
    ULONG   op = 0;
    ULONG   result1, result2, result3;
    ULONG   remaining;
    USHORT  tag;
    ULONG   paramSize;

    RtlZeroMemory(&s_PpiResponse, sizeof(s_PpiResponse));

    if (CommandSize < TPM2_COMMAND_HEADER_SIZE)
    {
        responseCode = TPM_RC_COMMAND_SIZE_VALUE;
        goto Exit;
    }

    if (ReadBigEndian32(CommandBuffer + 6) != TPM_CC_EMULATE_PPI)
    {
        return 0;
    }

    tag       = (USHORT)(((USHORT)CommandBuffer[0] << 8) | CommandBuffer[1]);
    paramSize = ReadBigEndian32(CommandBuffer + 2);
    remaining = CommandSize - TPM2_COMMAND_HEADER_SIZE;

    if (tag != TPM_ST_NO_SESSIONS_VALUE)
    {
        responseCode = TPM_RC_BAD_TAG_VALUE;
        goto Exit;
    }
    if (paramSize < remaining || remaining < sizeof(ULONG))
    {
        responseCode = TPM_RC_COMMAND_SIZE_VALUE;
        goto Exit;
    }

    functionIndex = ReadBigEndian32(CommandBuffer + TPM2_COMMAND_HEADER_SIZE);
    remaining    -= sizeof(ULONG);

    switch (functionIndex)
    {
    case PPI_CMD_QUERY:
    case PPI_CMD_VERSION:
    case PPI_CMD_SUBMIT_OP_REQ:
    case PPI_CMD_GET_PLATFORM_ACTION:
    case PPI_CMD_SUBMIT_USER_LANG:
        numberResults = 1;
        break;

    case PPI_CMD_GET_PENDING_OP:
        numberResults = 2;
        break;

    case PPI_CMD_RETURN_OP_RESP:
        numberResults = 3;
        break;

    case PPI_CMD_SUBMIT_OP_REQ2:
    case PPI_CMD_GET_USER_CONF:
        numberResults = 1;
        if (remaining < sizeof(ULONG))
        {
            responseCode = TPM_RC_COMMAND_SIZE_VALUE;
            goto Exit;
        }
        op = ReadBigEndian32(CommandBuffer + TPM2_COMMAND_HEADER_SIZE + sizeof(ULONG));
        break;

    default:
        numberResults = 0;
        responseCode  = TPM_RC_FAILURE_VALUE;
        goto Exit;
    }

    ExecutePpiCommand(functionIndex, op, &result1, &result2, &result3);
    s_PpiResponse.Result1 = result1;
    s_PpiResponse.Result2 = result2;
    s_PpiResponse.Result3 = result3;

Exit:
    if (responseCode != TPM_RC_SUCCESS_VALUE)
    {
        numberResults = 0;
    }

    *ResponseSize = TPM2_COMMAND_HEADER_SIZE + numberResults * sizeof(ULONG);

    // Header fields are big endian, the results are returned in host byte order.
    s_PpiResponse.Tag          = RtlUshortByteSwap(TPM_ST_NO_SESSIONS_VALUE);
    s_PpiResponse.ResponseSize = RtlUlongByteSwap(*ResponseSize);
    s_PpiResponse.ResponseCode = RtlUlongByteSwap(responseCode);

    RtlCopyMemory(*ResponseBuffer, &s_PpiResponse, *ResponseSize);
    return 1;
}
