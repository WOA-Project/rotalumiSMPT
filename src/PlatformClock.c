//** Description
//
// This file contains the routines that are used by the simulator to mimic
// a hardware clock on a TPM.
//
// In this implementation, all the time values are measured in millisecond.
// However, the precision of the clock functions may be implementation dependent.

//** Includes and Data Definitions
#include "FtpmSim.h"

// KUSER_SHARED_DATA::TickCountQuad, read directly like the binary does.
#define FTPM_KUSER_TICK_COUNT           (*(volatile ULONG64*)0xFFFFF78000000320ULL)


// CLOCK_NOMINAL is the number of hardware ticks per ms. A value of 30000 means
// that the nominal clock rate used to drive the hardware clock is 30 MHz. The
// adjustment rates are used to determine the conversion of the hardware ticks to
// internal hardware clock value. In practice, we would expect that there would be
// a hardware register will accumulated mS. It would be incremented by the output
// of a pre-scaler. The pre-scaler would divide the ticks from the clock by some
// value that would compensate for the difference between clock time and real time.
// The code in Clock does the emulation of this function.
#define CLOCK_NOMINAL 30000
// A 1% change in rate is 300 counts
#define CLOCK_ADJUST_COARSE 300
// A 0.1% change in rate is 30 counts
#define CLOCK_ADJUST_MEDIUM 30
// A minimum change in rate is 1 count
#define CLOCK_ADJUST_FINE 1
// The clock tolerance is +/-15% (4500 counts)
// Allow some guard band (16.7%)
#define CLOCK_ADJUST_LIMIT 5000

#define FTPM_US_PER_NOMINAL_MS          30000000ULL // .rdata literal 0x1c0037680

typedef enum _plat__ClockAdjustStep
{
    PLAT_TPM_CLOCK_ADJUST_COARSE_SLOWER = -3,
    PLAT_TPM_CLOCK_ADJUST_MEDIUM_SLOWER = -2,
    PLAT_TPM_CLOCK_ADJUST_FINE_SLOWER   = -1,
    PLAT_TPM_CLOCK_ADJUST_FINE_FASTER   = 1,
    PLAT_TPM_CLOCK_ADJUST_MEDIUM_FASTER = 2,
    PLAT_TPM_CLOCK_ADJUST_COARSE_FASTER = 3
} _plat__ClockAdjustStep;

//** Simulator Functions
//*** Introduction
// This set of functions is intended to be called by the simulator environment in
// order to simulate hardware events.

static ULONG    s_TimerReset      = 1;  // .data 0x1c00432c0
static ULONG    s_AdjustRate      = CLOCK_NOMINAL;  // .data 0x1c00432c4
static ULONG    s_TimerStopped;         // .data 0x1c004bc40
static ULONG64  s_LastTickCount;        // .data 0x1c004bc48
static ULONG    s_RemainderUs;          // .data 0x1c004bc50 leftover microseconds < 1000
static ULONG64  s_ElapsedMs;            // .data 0x1c004bc58

//***_plat__TimerReset()
// This function sets current system clock time as t0 for counting TPM time.
// This function is called at a power on event to reset the clock. When the clock
// is reset, the indication that the clock was stopped is also set.
VOID _plat__TimerReset(VOID)
{
    s_ElapsedMs     = 0;
    s_RemainderUs   = 0;
    s_AdjustRate    = CLOCK_NOMINAL;
    s_TimerReset    = TRUE;
    s_TimerStopped  = TRUE;
    s_LastTickCount = FTPM_KUSER_TICK_COUNT;
    return;
}

//*** _plat__TimerRestart()
// This function should be called in order to simulate the restart of the timer
// should it be stopped while power is still applied.
VOID _plat__TimerRestart(VOID)
{
    s_TimerStopped = TRUE;
    return;
}

//** Functions Used by TPM
//*** Introduction
// These functions are called by the TPM code. They should be replaced by
// appropriated hardware functions.

//***_plat__TimerRead()
// This function provides access to the tick timer of the platform. The TPM code
// uses this value to drive the TPM Clock.
//
// The tick timer is supposed to run when power is applied to the device. This timer
// should not be reset by time events including _TPM_Init. It should only be reset
// when TPM power is re-applied.
//
// If the TPM is run in a protected environment, that environment may provide the
// tick time to the TPM as long as the time provided by the environment is not
// allowed to go backwards. If the time provided by the system can go backwards
// during a power discontinuity, then the _plat__Signal_PowerOn should call
// _plat__TimerReset().
ULONG64 _plat__TimerRead(VOID)
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

//*** _plat__TimerWasReset()
// This function is used to interrogate the flag indicating if the tick timer has
// been reset.
//
// If the resetFlag parameter is SET, then the flag will be CLEAR before the
// function returns.
int _plat__TimerWasReset(VOID)
{
    int retVal   = (int)s_TimerReset;
    s_TimerReset = FALSE;
    return retVal;
}

//*** _plat__TimerWasStopped()
// This function is used to interrogate the flag indicating if the tick timer has
// been stopped. If so, this is typically a reason to roll the nonce.
//
// This function will CLEAR the s_timerStopped flag before returning. This provides
// functionality that is similar to status register that is cleared when read. This
// is the model used here because it is the one that has the most impact on the TPM
// code as the flag can only be accessed by one entity in the TPM. Any other
// implementation of the hardware can be made to look like a read-once register.
int _plat__TimerWasStopped(VOID)
{
    int retVal     = (int)s_TimerStopped;
    s_TimerStopped = FALSE;
    return retVal;
}

//***_plat__ClockAdjustRate()
// Adjust the clock rate
VOID _plat__ClockRateAdjust(_plat__ClockAdjustStep adjust)
{
    // We expect the caller should only use a fixed set of constant values to
    // adjust the rate
    switch(adjust)
    {
        // slower increases the divisor
        case PLAT_TPM_CLOCK_ADJUST_COARSE_SLOWER:
            s_AdjustRate += CLOCK_ADJUST_COARSE;
            break;
        case PLAT_TPM_CLOCK_ADJUST_MEDIUM_SLOWER:
            s_AdjustRate += CLOCK_ADJUST_MEDIUM;
            break;
        case PLAT_TPM_CLOCK_ADJUST_FINE_SLOWER:
            s_AdjustRate += CLOCK_ADJUST_FINE;
            break;
        // faster decreases the divisor
        case PLAT_TPM_CLOCK_ADJUST_FINE_FASTER:
            s_AdjustRate -= CLOCK_ADJUST_FINE;
            break;
        case PLAT_TPM_CLOCK_ADJUST_MEDIUM_FASTER:
            s_AdjustRate -= CLOCK_ADJUST_MEDIUM;
            break;
        case PLAT_TPM_CLOCK_ADJUST_COARSE_FASTER:
            s_AdjustRate -= CLOCK_ADJUST_COARSE;
            break;
    }

    if(s_AdjustRate > (CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT))
        s_AdjustRate = CLOCK_NOMINAL + CLOCK_ADJUST_LIMIT;
    if(s_AdjustRate < (CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT))
        s_AdjustRate = CLOCK_NOMINAL - CLOCK_ADJUST_LIMIT;

    return;
}
