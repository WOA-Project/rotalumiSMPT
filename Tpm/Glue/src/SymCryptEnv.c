// SymCryptEnv.c - SymCrypt environment selection and the one routine SymCrypt expects in assembler
//
// SymCrypt is configured per binary: exactly one C file invokes an environment macro, which
// instantiates SymCryptInit() & friends for that environment. ftpmsim.sys uses the
// Windows 8.1+ kernel mode environment (env_windowsKernelModeWin8_1.c): on the first
// SymCryptInit() it checks RtlGetVersion() >= 6.3 (otherwise SymCryptFatal -> KeBugCheckEx
// 0x171 CRYPTO_LIBRARY_INTERNAL_ERROR), reads ID_AA64ISAR0_EL1 (SymCryptDetectCpuFeaturesFromRegisters,
// cpuid.c) and sets the "initialised" flag with an interlocked OR. This is what the binary's
// _TPM_Init contains inline (see Tpm\README_TpmLibrary.md). SymCryptInit() is reached
// through the library's CryptHashInit() -> LibHashInit().
//
// RE: 0x1c0035fc0 SymCryptDetectCpuFeaturesFromRegisters, 0x1c0031e18 SymCryptFatalEnv...

#include <windows.h>
#include <symcrypt.h>

SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_WIN8_1_N_LATER

// SymCryptWipe() calls SymCryptWipeAsm(); the reference build assembles lib\arm64\wipe.asm
// (a plain store loop). A volatile C loop is equivalent and avoids the armasm64 step; the
// store cannot be removed by the optimiser.
VOID
SYMCRYPT_CALL
SymCryptWipeAsm(
    _Out_writes_bytes_( cbData ) PVOID pbData,
    SIZE_T cbData
    )
{
    volatile BYTE *p = (volatile BYTE *)pbData;
    SIZE_T i;

    for (i = 0; i < cbData; i++)
    {
        p[i] = 0;
    }
}
