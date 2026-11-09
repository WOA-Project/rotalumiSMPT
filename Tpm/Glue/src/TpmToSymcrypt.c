// TpmToSymcrypt.c - SymCrypt side of the TPM hash / AES glue (see symcrypt\TpmToSymcryptHash.h)
//
// Every function here is a thin adapter that fixes SymCrypt's argument order for the way
// CryptHash.c / CryptSym.c call their methods. This file is the only TPM-side translation
// unit that includes symcrypt.h.
//
// RE: the binary has these as separate small functions: SymCryptSha512StateCopy 0x1c0024e40,
// SymCryptSha1StateCopy 0x1c0026510, SymCryptSha512StateExport/Import Core 0x1c0025140 /
// 0x1c0025238, SymCryptSha384Result 0x1c00250a0 ... (FunctionMap.csv).

#include <windows.h>
#include <symcrypt.h>

#include "symcrypt\TpmToSymcryptHash.h"
#include "symcrypt\TpmToSymcryptSym.h"

C_ASSERT(sizeof(SYMCRYPT_SHA1_STATE)    <= FTPM_SYMCRYPT_SHA1_STATE_SIZE);
C_ASSERT(sizeof(SYMCRYPT_SHA256_STATE)  <= FTPM_SYMCRYPT_SHA256_STATE_SIZE);
C_ASSERT(sizeof(SYMCRYPT_SHA384_STATE)  <= FTPM_SYMCRYPT_SHA384_STATE_SIZE);
C_ASSERT(sizeof(SYMCRYPT_SHA512_STATE)  <= FTPM_SYMCRYPT_SHA512_STATE_SIZE);
C_ASSERT(sizeof(SYMCRYPT_AES_EXPANDED_KEY) == FTPM_SYMCRYPT_AES_EXPANDED_KEY_SIZE);
C_ASSERT(__alignof(SYMCRYPT_AES_EXPANDED_KEY) <= 16 && __alignof(SYMCRYPT_SHA512_STATE) <= 16);
C_ASSERT(SYMCRYPT_SHA1_STATE_EXPORT_SIZE   <= FTPM_SYMCRYPT_SHA1_STATE_SIZE);
C_ASSERT(SYMCRYPT_SHA256_STATE_EXPORT_SIZE <= FTPM_SYMCRYPT_SHA256_STATE_SIZE);
C_ASSERT(SYMCRYPT_SHA384_STATE_EXPORT_SIZE <= FTPM_SYMCRYPT_SHA384_STATE_SIZE);
C_ASSERT(SYMCRYPT_SHA512_STATE_EXPORT_SIZE <= FTPM_SYMCRYPT_SHA512_STATE_SIZE);

void
FtpmSymCryptInit(
    void
    )
{
    SymCryptInit();
}

#define FTPM_DEFINE_HASH_ADAPTERS(Alg, Sc, Ty)                                             \
void FtpmSymcrypt##Alg##Start(void *state)                                              \
{ SymCrypt##Sc##Init((PSYMCRYPT_##Ty##_STATE)state); }                                  \
void FtpmSymcrypt##Alg##Data(void *state, const unsigned char *data, size_t size)       \
{ SymCrypt##Sc##Append((PSYMCRYPT_##Ty##_STATE)state, data, size); }                    \
void FtpmSymcrypt##Alg##End(unsigned char *digest, void *state)                         \
{ SymCrypt##Sc##Result((PSYMCRYPT_##Ty##_STATE)state, digest); }                        \
void FtpmSymcrypt##Alg##Copy(void *to, const void *from, size_t size)                   \
{ UNREFERENCED_PARAMETER(size);                                                         \
  SymCrypt##Sc##StateCopy((PCSYMCRYPT_##Ty##_STATE)from, (PSYMCRYPT_##Ty##_STATE)to); } \
void FtpmSymcrypt##Alg##Export(unsigned char *to, const void *from, size_t size)        \
{ UNREFERENCED_PARAMETER(size);                                                         \
  SymCrypt##Sc##StateExport((PCSYMCRYPT_##Ty##_STATE)from, to); }                       \
void FtpmSymcrypt##Alg##Import(void *to, const unsigned char *from, size_t size)        \
{ UNREFERENCED_PARAMETER(size);                                                         \
  if (SymCrypt##Sc##StateImport((PSYMCRYPT_##Ty##_STATE)to, from) != SYMCRYPT_NO_ERROR) \
      SymCryptFatal('simp'); }

FTPM_DEFINE_HASH_ADAPTERS(SHA1,   Sha1,   SHA1)
FTPM_DEFINE_HASH_ADAPTERS(SHA256, Sha256, SHA256)
FTPM_DEFINE_HASH_ADAPTERS(SHA384, Sha384, SHA384)
FTPM_DEFINE_HASH_ADAPTERS(SHA512, Sha512, SHA512)

int
FtpmSymcryptAesSetKey(
    void                  *schedule,
    const unsigned char   *key,
    size_t                 keyBytes
    )
{
    // Fails only for key sizes other than 16/24/32 bytes.
    return SymCryptAesExpandKey((PSYMCRYPT_AES_EXPANDED_KEY)schedule, key, keyBytes) != SYMCRYPT_NO_ERROR;
}

void
FtpmSymcryptAesEncrypt(
    void                  *schedule,
    const unsigned char   *in,
    unsigned char         *out
    )
{
    SymCryptAesEncrypt((PCSYMCRYPT_AES_EXPANDED_KEY)schedule, in, out);
}

void
FtpmSymcryptAesDecrypt(
    void                  *schedule,
    const unsigned char   *in,
    unsigned char         *out
    )
{
    SymCryptAesDecrypt((PCSYMCRYPT_AES_EXPANDED_KEY)schedule, in, out);
}
