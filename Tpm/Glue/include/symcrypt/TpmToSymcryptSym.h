// TpmToSymcryptSym.h - splice SymCrypt's AES into the TPM symmetric interface
// (SYM_LIB == SYMCRYPT). Counterpart of TpmToOsslSym.h.
//
// The configured algorithm set (see AlgorithmGetImplementedVector in the binary) has AES
// only: ALG_TDES, ALG_SM4 and ALG_CAMELLIA are NO, so no DES support file is needed.
// As for the hashes, the AES key schedule is an opaque blob of the SymCrypt size and the
// block functions live in Tpm\Glue\src\TpmToSymcrypt.c.

#ifndef _TPM_TO_SYMCRYPT_SYM_H_
#define _TPM_TO_SYMCRYPT_SYM_H_

#if SYM_LIB == SYMCRYPT

#if ALG_TDES
#   error "TDES is not implemented by this adapter (ALG_TDES is NO in ftpmsim.sys)"
#endif
#if ALG_SM4
#   error "SM4 is not available"
#endif
#if ALG_CAMELLIA
#   error "Camellia is not available"
#endif

#ifndef FTPM_SC_ALIGN
#   define FTPM_SC_ALIGN                __declspec(align(16))
#endif

// sizeof(SYMCRYPT_AES_EXPANDED_KEY) of SymCrypt v87
#define FTPM_SYMCRYPT_AES_EXPANDED_KEY_SIZE     496

typedef FTPM_SC_ALIGN struct { unsigned char opaque[FTPM_SYMCRYPT_AES_EXPANDED_KEY_SIZE]; } FTPM_SYMCRYPT_AES_KEY;

// SymCrypt's block functions take (expandedKey, in, out), which is exactly the order
// CryptSym.h wants (keySchedule, in, out), so SWIZZLE is the identity.
typedef void(*TpmCryptSetSymKeyCall_t)(
    void        *keySchedule,
    const BYTE  *in,
    BYTE        *out
    );

#define SWIZZLE(keySchedule, in, out)                                   \
    (void *)(keySchedule), (const BYTE *)(in), (BYTE *)(out)

int  FtpmSymcryptAesSetKey(void *schedule, const unsigned char *key, size_t keyBytes);
void FtpmSymcryptAesEncrypt(void *schedule, const unsigned char *in, unsigned char *out);
void FtpmSymcryptAesDecrypt(void *schedule, const unsigned char *in, unsigned char *out);

// SymCryptAesExpandKey() produces a schedule usable in both directions. Like OpenSSL's\r\n// AES_set_encrypt_key() (which CryptRand.c compares with 0) the adapter returns 0 on success.
#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule)              \
    FtpmSymcryptAesSetKey((schedule), (key), (size_t)((keySizeInBits) / 8))
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule)              \
    FtpmSymcryptAesSetKey((schedule), (key), (size_t)((keySizeInBits) / 8))

#define TpmCryptEncryptAES          FtpmSymcryptAesEncrypt
#define TpmCryptDecryptAES          FtpmSymcryptAesDecrypt
#define tpmKeyScheduleAES           FTPM_SYMCRYPT_AES_KEY

typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;

// This definition would change if there were something to report
#define SymLibSimulationEnd()

#endif // SYM_LIB == SYMCRYPT

#endif // _TPM_TO_SYMCRYPT_SYM_H_
