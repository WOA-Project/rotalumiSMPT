// PlatformFail.c - failure mode entry and debug output
//
// RE: 0x1c0037758 FtpmDebugPrint
//     0x1c00078d0 random_bytes 0x1c00377a8 __report_gsfailure (fast fail, CRT)

#include <stdarg.h>
#include "FtpmSim.h"

// TpmFail() itself is the unmodified ms-tpm-20-ref TpmFail.c (FAIL_TRACE, NO_LONGJMP): it stores
// s_failCode/s_failLine/s_failFunction, sets g_inFailureMode, clears g_forceFailureMode and
// calls _plat__Fail(). RE: 0x1c0010110 TpmFail, 0x1c0010140 TpmFailureMode.

// _plat__Fail is a bare `ret`: exported at 0x1c0003f30 together with _guard_check_icall,
// and the linker folded every empty function of the driver into it (the WDF cleanup
// callback and EvtIoStop).
VOID
_plat__Fail(
    VOID
    )
{
}

// random_bytes() exists only to satisfy the SymCrypt/MsBn glue; any call is a
// FATAL_ERROR_INTERNAL ("random_bytes", line 0x48).
VOID
random_bytes(
    VOID
    )
{
    FTPM_FAIL("random_bytes", 0x48, FATAL_ERROR_INTERNAL);
}

// printf-style helper used for the "Memory usage statistics" dump of
// MathLibSimulationEnd(): DbgPrintEx(IHVDRIVER, INFO) with an explicit va_list.
VOID
FtpmDebugPrint(
    _In_z_ PCSTR Format,
    ...
    )
{
    va_list args;

    va_start(args, Format);
    vDbgPrintEx(FTPM_DPFLTR_COMPONENT, FTPM_DBG_INFO, Format, args);
    va_end(args);
}
