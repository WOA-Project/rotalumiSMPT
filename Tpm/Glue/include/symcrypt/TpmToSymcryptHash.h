// TpmToSymcryptHash.h - splice SymCrypt into the TPM hash interface (HASH_LIB == SYMCRYPT)
//
// ms-tpm-20-ref selects the hash back end with HASH_LIB (Implementation.h). The public
// reference only ships the OpenSSL / LibTomCrypt / wolfSSL headers; the "symcrypt/"
// header named in LibSupport.h is part of the Windows tree. This is a reconstruction in
// the shape of TpmToOsslHash.h on top of github.com/microsoft/SymCrypt (v87).
//
// The TPM sources do not include symcrypt.h (it needs the Windows kernel headers, whose
// type names clash with the TPM's own BaseTypes.h). The hash states are therefore declared
// here as opaque, 16-byte aligned blobs of exactly the SymCrypt state size (checked by
// C_ASSERTs in Tpm\Glue\src\TpmToSymcrypt.c) and every operation is a function of that
// glue file, which includes symcrypt.h.
//
// RE: the shipped ftpmsim.sys contains SymCryptSha1/256/384/512 {Init, Append, Result,
// StateCopy, StateExport, StateImport} (FunctionMap.csv). SHA-512 is not an implemented
// algorithm in this build (ALG_SHA512 == NO) but its code is linked because
// SymCryptSha384* shares it.

#ifndef _TPM_TO_SYMCRYPT_HASH_H_
#define _TPM_TO_SYMCRYPT_HASH_H_

#if HASH_LIB == SYMCRYPT

#define FTPM_SC_ALIGN                   __declspec(align(16))

// Size of the opaque state: max(sizeof(SYMCRYPT_<ALG>_STATE), SYMCRYPT_<ALG>_STATE_EXPORT_SIZE)
// rounded up to 16. SymCrypt v87: state 128/128/224/224, export blob 120/132/236/236. The TPM
// stores an exported state in the same HASH_STATE.state member, so it has to fit.
#define FTPM_SYMCRYPT_SHA1_STATE_SIZE   128
#define FTPM_SYMCRYPT_SHA256_STATE_SIZE 144
#define FTPM_SYMCRYPT_SHA384_STATE_SIZE 240
#define FTPM_SYMCRYPT_SHA512_STATE_SIZE 240

typedef FTPM_SC_ALIGN struct { unsigned char opaque[FTPM_SYMCRYPT_SHA1_STATE_SIZE];   } FTPM_SYMCRYPT_SHA1_STATE;
typedef FTPM_SC_ALIGN struct { unsigned char opaque[FTPM_SYMCRYPT_SHA256_STATE_SIZE]; } FTPM_SYMCRYPT_SHA256_STATE;
typedef FTPM_SC_ALIGN struct { unsigned char opaque[FTPM_SYMCRYPT_SHA384_STATE_SIZE]; } FTPM_SYMCRYPT_SHA384_STATE;
typedef FTPM_SC_ALIGN struct { unsigned char opaque[FTPM_SYMCRYPT_SHA512_STATE_SIZE]; } FTPM_SYMCRYPT_SHA512_STATE;

#define tpmHashStateSHA1_t        FTPM_SYMCRYPT_SHA1_STATE
#define tpmHashStateSHA256_t      FTPM_SYMCRYPT_SHA256_STATE
#define tpmHashStateSHA384_t      FTPM_SYMCRYPT_SHA384_STATE
#define tpmHashStateSHA512_t      FTPM_SYMCRYPT_SHA512_STATE

#if ALG_SM3_256
#   error "SymCrypt has no SM3"
#endif

// One-time SymCrypt environment setup (SymCryptInit()): called from CryptHashInit().
void FtpmSymCryptInit(void);
#define LibHashInit()       FtpmSymCryptInit()

// Adapters implemented in TpmToSymcrypt.c. 'void *' stands for the state types above.
#define FTPM_DECLARE_HASH_ADAPTERS(Alg)                                         \
    void FtpmSymcrypt##Alg##Start(void *state);                                 \
    void FtpmSymcrypt##Alg##Data(void *state, const unsigned char *data, size_t size); \
    void FtpmSymcrypt##Alg##End(unsigned char *digest, void *state);            \
    void FtpmSymcrypt##Alg##Copy(void *to, const void *from, size_t size);      \
    void FtpmSymcrypt##Alg##Export(unsigned char *to, const void *from, size_t size);  \
    void FtpmSymcrypt##Alg##Import(void *to, const unsigned char *from, size_t size);

FTPM_DECLARE_HASH_ADAPTERS(SHA1)
FTPM_DECLARE_HASH_ADAPTERS(SHA256)
FTPM_DECLARE_HASH_ADAPTERS(SHA384)
FTPM_DECLARE_HASH_ADAPTERS(SHA512)

#ifdef _CRYPT_HASH_C_

typedef BYTE          *PBYTE;
typedef const BYTE    *PCBYTE;

// Same method interface as TpmToOsslHash.h; SymCrypt's own argument order differs for
// Result, StateCopy and StateExport/Import and is handled in the adapters.
#define HASH_START_METHOD_DEF   void (HASH_START_METHOD)(PANY_HASH_STATE state)
#define HASH_START(hashState)                                                   \
                ((hashState)->def->method.start)(&(hashState)->state);

#define HASH_DATA_METHOD_DEF                                                    \
                void (HASH_DATA_METHOD)(PANY_HASH_STATE state,                  \
                                    PCBYTE buffer,                              \
                                    size_t size)
#define HASH_DATA(hashState, dInSize, dIn)                                      \
                ((hashState)->def->method.data)(&(hashState)->state, dIn, dInSize)

#define HASH_END_METHOD_DEF                                                     \
                void (HASH_END_METHOD)(BYTE *buffer, PANY_HASH_STATE state)
#define HASH_END(hashState, buffer)                                             \
                ((hashState)->def->method.end)(buffer, &(hashState)->state)

#define HASH_STATE_COPY_METHOD_DEF                                              \
                void (HASH_STATE_COPY_METHOD)(PANY_HASH_STATE to,               \
                                              PCANY_HASH_STATE from,            \
                                              size_t size)
#define HASH_STATE_COPY(hashStateOut, hashStateIn)                              \
                ((hashStateIn)->def->method.copy)(&(hashStateOut)->state,       \
                                              &(hashStateIn)->state,            \
                                              (hashStateIn)->def->contextSize)

// SymCrypt's export format is a versioned, checksummed blob of
// SYMCRYPT_<ALG>_STATE_EXPORT_SIZE bytes; it fits into the (padded) 'state' member.
#define  HASH_STATE_EXPORT_METHOD_DEF                                           \
                void (HASH_STATE_EXPORT_METHOD)(BYTE *to,                       \
                                          PCANY_HASH_STATE from,                \
                                          size_t size)
#define  HASH_STATE_EXPORT(to, hashStateFrom)                                   \
                ((hashStateFrom)->def->method.copyOut)                          \
                        (&(((BYTE *)(to))[offsetof(HASH_STATE, state)]),        \
                         &(hashStateFrom)->state,                               \
                         (hashStateFrom)->def->contextSize)

#define  HASH_STATE_IMPORT_METHOD_DEF                                           \
                void (HASH_STATE_IMPORT_METHOD)(PANY_HASH_STATE to,             \
                                                const BYTE *from,               \
                                                 size_t size)
#define  HASH_STATE_IMPORT(hashStateTo, from)                                   \
                ((hashStateTo)->def->method.copyIn)                             \
                        (&(hashStateTo)->state,                                 \
                         &(((const BYTE *)(from))[offsetof(HASH_STATE, state)]),\
                         (hashStateTo)->def->contextSize)

#define tpmHashStart_SHA1           FtpmSymcryptSHA1Start
#define tpmHashData_SHA1            FtpmSymcryptSHA1Data
#define tpmHashEnd_SHA1             FtpmSymcryptSHA1End
#define tpmHashStateCopy_SHA1       FtpmSymcryptSHA1Copy
#define tpmHashStateExport_SHA1     FtpmSymcryptSHA1Export
#define tpmHashStateImport_SHA1     FtpmSymcryptSHA1Import
#define tpmHashStart_SHA256         FtpmSymcryptSHA256Start
#define tpmHashData_SHA256          FtpmSymcryptSHA256Data
#define tpmHashEnd_SHA256           FtpmSymcryptSHA256End
#define tpmHashStateCopy_SHA256     FtpmSymcryptSHA256Copy
#define tpmHashStateExport_SHA256   FtpmSymcryptSHA256Export
#define tpmHashStateImport_SHA256   FtpmSymcryptSHA256Import
#define tpmHashStart_SHA384         FtpmSymcryptSHA384Start
#define tpmHashData_SHA384          FtpmSymcryptSHA384Data
#define tpmHashEnd_SHA384           FtpmSymcryptSHA384End
#define tpmHashStateCopy_SHA384     FtpmSymcryptSHA384Copy
#define tpmHashStateExport_SHA384   FtpmSymcryptSHA384Export
#define tpmHashStateImport_SHA384   FtpmSymcryptSHA384Import
#define tpmHashStart_SHA512         FtpmSymcryptSHA512Start
#define tpmHashData_SHA512          FtpmSymcryptSHA512Data
#define tpmHashEnd_SHA512           FtpmSymcryptSHA512End
#define tpmHashStateCopy_SHA512     FtpmSymcryptSHA512Copy
#define tpmHashStateExport_SHA512   FtpmSymcryptSHA512Export
#define tpmHashStateImport_SHA512   FtpmSymcryptSHA512Import

#endif // _CRYPT_HASH_C_

// This definition would change if there were something to report
#define HashLibSimulationEnd()

#endif // HASH_LIB == SYMCRYPT

#endif // _TPM_TO_SYMCRYPT_HASH_H_
