// PlatformPower.c - power / reset signals of the platform layer
//
// RE: 0x1c0036a10 _plat__Signal_PowerOn   0x1c0036ab0 _plat__Signal_PowerOff
//     0x1c0036a70 _plat__WasPowerLost     0x1c0036a80 _plat__Signal_Reset

#include "FtpmSim.h"

static ULONG s_PowerLost;       // .data 0x1c004bc08
static UCHAR s_Locality;        // .data 0x1c004bc60 read by TPM2_Startup (inlined _plat__LocalityGet: 0 and 3 are accepted); never written but here
static ULONG s_IsCanceled;      // .data 0x1c004bc6c (cancel is not implemented; never set)

int
_plat__Signal_PowerOn(
    VOID
    )
{
    _plat__TimerReset();        // inlined in the binary
    s_PowerLost = TRUE;
    return 0;
}

// Tail call into _plat__NVDisable(): the image is committed and NVChip.dat closed.
int
_plat__Signal_PowerOff(
    VOID
    )
{
    _plat__NVDisable();
    return 0;
}

int
_plat__WasPowerLost(
    VOID
    )
{
    ULONG lost = s_PowerLost;

    s_PowerLost = FALSE;
    return (int)lost;
}

int
_plat__Signal_Reset(
    VOID
    )
{
    s_Locality   = 0;
    s_IsCanceled = FALSE;
    _TPM_Init();
    return 0;
}

// Accessors the library calls through Platform_fp.h. The shipped image has no code for them
// (the library reads the statics above, or folds the constant); they exist here only so that
// the unmodified reference sources link.
int
_plat__IsCanceled(
    VOID
    )
{
    return (int)s_IsCanceled;
}

UCHAR
_plat__LocalityGet(
    VOID
    )
{
    return s_Locality;
}

// Physical presence is emulated by the PPI admin interface, not by a pin.
int
_plat__PhysicalPresenceAsserted(
    VOID
    )
{
    return FALSE;
}
