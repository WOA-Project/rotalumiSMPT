// PlatformClock.c - TPM clock on top of the kernel tick count
//
// RE: 0x1c00375e0 _plat__TimerRead      0x1c0037580 _plat__TimerReset
//     0x1c00375d0 _plat__TimerRestart   0x1c0037690 _plat__TimerWasReset
//     0x1c00376a0 _plat__TimerWasStopped 0x1c00376b0 _plat__ClockAdjustRate
//
// Not the ms-tpm-20-ref Clock.c: the time source is KUSER_SHARED_DATA.TickCount
// (0xFFFFF78000000320), scaled with KeQueryTimeIncrement().

#include "FtpmSim.h"

// KUSER_SHARED_DATA::TickCountQuad, read directly like the binary does.
#define FTPM_KUSER_TICK_COUNT           (*(volatile ULONG64*)0xFFFFF78000000320ULL)

#define CLOCK_NOMINAL                   30000       // reference "nominal" rate: 30000 units
#define CLOCK_ADJUST_LIMIT              5000        // rate is clamped to CLOCK_NOMINAL +/- 5000 (25000..35000)
#define CLOCK_ADJUST_COARSE             300
#define CLOCK_ADJUST_MEDIUM             30
#define CLOCK_ADJUST_FINE               1
#define FTPM_US_PER_NOMINAL_MS          30000000ULL // .rdata literal 0x1c0037680

static ULONG    s_TimerReset      = 1;  // .data 0x1c00432c0
static ULONG    s_AdjustRate      = CLOCK_NOMINAL;  // .data 0x1c00432c4
static ULONG    s_TimerStopped;         // .data 0x1c004bc40
static ULONG64  s_LastTickCount;        // .data 0x1c004bc48
static ULONG    s_RemainderUs;          // .data 0x1c004bc50 leftover microseconds < 1000
static ULONG64  s_ElapsedMs;            // .data 0x1c004bc58

VOID
_plat__TimerReset(
    VOID
    )
{
    s_ElapsedMs     = 0;
    s_RemainderUs   = 0;
    s_AdjustRate    = CLOCK_NOMINAL;
    s_TimerReset    = TRUE;
    s_TimerStopped  = TRUE;
    s_LastTickCount = FTPM_KUSER_TICK_COUNT;
}

VOID
_plat__TimerRestart(
    VOID
    )
{
    s_TimerStopped = TRUE;
}

//
// Returns the time that passed since the previous call in milliseconds, corrected
// by the clock adjustment rate. RE: the reference implementation returns the
// accumulated TPM time here; this build overwrites s_ElapsedMs on each call.
//
ULONG64
_plat__TimerRead(
    VOID
    )
{
    ULONG64 previous = s_LastTickCount;
    ULONG64 deltaMs;
    ULONG64 microseconds;
    ULONG64 total;

    s_LastTickCount = FTPM_KUSER_TICK_COUNT;

    // KeQueryTimeIncrement() is in 100 ns units: ticks * increment / 10000 = ms.
    deltaMs = ((s_LastTickCount - previous) * KeQueryTimeIncrement()) / 10000;

    microseconds = (deltaMs * FTPM_US_PER_NOMINAL_MS) / s_AdjustRate;   // brk #0xf004 on divide by zero
    total        = microseconds + s_RemainderUs;

    s_ElapsedMs   = total / 1000;
    s_RemainderUs = (ULONG)(total - s_ElapsedMs * 1000);
    return s_ElapsedMs;
}

int
_plat__TimerWasReset(
    VOID
    )
{
    ULONG wasReset = s_TimerReset;

    s_TimerReset = FALSE;
    return (int)wasReset;
}

int
_plat__TimerWasStopped(
    VOID
    )
{
    ULONG wasStopped = s_TimerStopped;

    s_TimerStopped = FALSE;
    return (int)wasStopped;
}

VOID
_plat__ClockAdjustRate(
    int Adjustment
    )
{
    switch (Adjustment)
    {
    case -CLOCK_ADJUST_COARSE:  s_AdjustRate -= CLOCK_ADJUST_COARSE;  break;
    case -CLOCK_ADJUST_MEDIUM:  s_AdjustRate -= CLOCK_ADJUST_MEDIUM;  break;
    case -CLOCK_ADJUST_FINE:    s_AdjustRate -= CLOCK_ADJUST_FINE;    break;
    case  CLOCK_ADJUST_FINE:    s_AdjustRate += CLOCK_ADJUST_FINE;    break;
    case  CLOCK_ADJUST_MEDIUM:  s_AdjustRate += CLOCK_ADJUST_MEDIUM;  break;
    case  CLOCK_ADJUST_COARSE:  s_AdjustRate += CLOCK_ADJUST_COARSE;  break;
    default:                                                          break;
    }

    if (s_AdjustRate > CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT)
    {
        s_AdjustRate = CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT;
    }
    if (s_AdjustRate < CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT)
    {
        s_AdjustRate = CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT;
    }
}