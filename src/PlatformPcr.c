
// PCR platform interface functions
#include "FtpmSim.h"

typedef UINT16 TPM_ALG_ID;

#  define MUST_BE(e)

#define YES   1
#define  ALG_YES                    YES

#define ALG_SHA256                          ALG_YES
#define ALG_SHA384                          ALG_YES

#define IMPLEMENTATION_PCR         24

// see the comments below for supportsPolicyAuth to explain this
#define MAX_PCR_GROUP_BITS 3

#define ALG_SHA256_VALUE         0x000B
#define TPM_ALG_SHA256           (TPM_ALG_ID)(ALG_SHA256_VALUE)
#define ALG_SHA384_VALUE         0x000C
#define TPM_ALG_SHA384           (TPM_ALG_ID)(ALG_SHA384_VALUE)

typedef UINT32 TPM_RC;
#define TPM_RC_SUCCESS           (TPM_RC)(0x000)

#define HCRTM_PCR                  0


#  define FUNCTION_NAME __FUNCTION__
#  define CODELOCATOR() FUNCTION_NAME, __LINE__

#define FATAL_ERROR_ASSERT           (500)

// SETFAILED calls TpmFail.  It may or may not return based on the NO_LONGJMP flag.
// CODELOCATOR is a macro that expands to either one 64-bit value that encodes the
// location, or two parameters: Function Name and Line Number.
#define SETFAILED(errorCode) (TpmFail(CODELOCATOR(), errorCode))

#  define FAIL_RC(failCode)                SETFAILED(failCode)

#  define pAssert_RC(a)                    \
      do                                   \
      {                                    \
          if(!(a))                         \
              FAIL_RC(FATAL_ERROR_ASSERT); \
      } while(0);


typedef struct
{
    // SET if the PCR value should be saved in state save
    unsigned int stateSave : 1;

    // SET if the PCR is part of the "TCB group", causes the PCR counter not to increment
    unsigned int doNotIncrementPcrCounter : 1;

    // PCRs may support policy or auth-value authorization.
    //
    // Such authorization values, if supported, are set by
    // TPM2_PCR_SetAuthPolicy and/or TPM2_PCR_SetAuthValue.
    //
    // PCRs that share the same policy/auth value are said to be in a "group".
    // PCRs that don't support authorization are said to be in group Zero.
    //
    // Group numbers are only used internally to indicate which PCRs share an
    // authorization value.  IOW the TPM client cannot refer to PCRs by group
    // number; the range of group numbers is implementation defined. zero
    // indicates the PCR doesn't support policy or auth verification.
    //
    // The size of this field must be large enough to support
    // NUM_POLICY_PCR_GROUP & NUM_AUTHVALUE_PCR_GROUP; the maximum number of groups
    // actually supported by this build of the core library.
    //
    // The number of bits allocated here does not control the number of groups,
    // but there is a static assert that the number of bits here is large
    // enough.
    unsigned int policyAuthGroup : MAX_PCR_GROUP_BITS;
    unsigned int authValuesGroup : MAX_PCR_GROUP_BITS;

    // these bitfields indicating the localities that can
    // reset or extend this PCR. A SET bit indicates the PCR can
    // be extended or reset from that locality.  The low-order bit in
    // each field is locality zero, and the high-order bit is locality 4.
    unsigned int resetLocality  : 5;
    unsigned int extendLocality : 5;
} PCR_Attributes;

// use this as a convenient lookup for hash size for PCRs.
UINT16 CryptHashGetDigestSize(TPM_ALG_ID hashAlg  // IN: hash algorithm to look up
);
void   MemorySet(void* dest, int value, size_t size);

// The initial value of PCR attributes.  The value of these fields should be
// consistent with PC Client specification.  The bitfield meanings are defined by
// the TPM Reference code.
// In this implementation, we assume the total number of implemented PCR is 24.
static const PCR_Attributes s_initAttributes[] = {
    //
    // PCR 0 - 15, static RTM
    // PCR[0]
    {
        1,  // save state
        0,  // in the "do not increment the PcrCounter" group? (0 = increment the PcrCounter)
        0,  // supportsPolicyAuth group number? 0 = policyAuth not supported for this PCR.
        0,  // supportsAuthValue group number? 0 = AuthValue not supported for this PCR.
        0,    // 0 = reset localities (cannot reset)
        0x1F  // 0x1F = extendlocalities [0,4]
    },
    {1, 0, 0, 0, 0, 0x1F},  // PCR 1-3
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 4-6
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 7-9
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 10-12
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 13-15
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},

    // these PCRs are never saved
    {0, 0, 0, 0, 0x0F, 0x1F},  // PCR 16, Debug, reset allowed, extend all
    {0, 0, 0, 0, 0x10, 0x1C},  // PCR 17, Locality 4, extend loc 2+
    {0, 0, 0, 0, 0x10, 0x1C},  // PCR 18, Locality 3, extend loc 2+
    {0, 0, 0, 0, 0x10, 0x0C},  // PCR 19, Locality 2, extend loc 2, 3
    // these three support doNotIncrement, PolicyAuth, and AuthValue.
    // this is consistent with the existing behavior of the TPM Reference code
    // but differs from the behavior of the PC client spec.
    {0, 1, 1, 1, 0x14, 0x0E},  // PCR 20, Locality 1, extend loc 1, 2, 3
    {0, 1, 1, 1, 0x14, 0x04},  // PCR 21, Dynamic OS, extend loc 2
    {0, 1, 1, 1, 0x14, 0x04},  // PCR 22, Dynamic OS, extend loc 2
    {0, 0, 0, 0, 0x0F, 0x1F},  // PCR 23, reset allowed, App specific, extend all
};

#ifndef ARRAYSIZE
#  define ARRAYSIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

MUST_BE(ARRAYSIZE(s_initAttributes) == IMPLEMENTATION_PCR);

#if ALG_SHA256 != YES && ALG_SHA384 != YES
#  error No default PCR banks defined
#endif

static const TPM_ALG_ID DefaultActivePcrBanks[] = {
#if ALG_SHA256
    TPM_ALG_SHA256
#endif
#if ALG_SHA384
#  if ALG_SHA256
    ,
#  endif
    TPM_ALG_SHA384
#endif
};

UINT32 _platPcr__NumberOfPcrs()
{
    return ARRAYSIZE(s_initAttributes);
}

// return the initialization attributes of a given PCR.
// pcrNumber expected to be in [0, _platPcr__NumberOfPcrs)
// returns the attributes for PCR[0] if the requested pcrNumber is out of range.
PCR_Attributes _platPcr__GetPcrInitializationAttributes(UINT32 pcrNumber)
{
    if(pcrNumber >= _platPcr__NumberOfPcrs())
    {
        pcrNumber = 0;
    }
    return s_initAttributes[pcrNumber];
}

// should the given PCR algorithm default to active in a new TPM?
BOOLEAN _platPcr_IsPcrBankDefaultActive(TPM_ALG_ID pcrAlg)
{
    // brute force search is fast enough for a small array.
    for(int i = 0; i < ARRAYSIZE(DefaultActivePcrBanks); i++)
    {
        if(DefaultActivePcrBanks[i] == pcrAlg)
        {
            return TRUE;
        }
    }
    return FALSE;
}

// Fill a given buffer with the PCR initialization value for a particular PCR and hash
// combination, and return its length.  If the platform doesn't have a value, then
// the result size is expected to be zero, and the rfunction will return TPM_RC_PCR.
// If a valid is not available, then the core TPM library will ignore the value and
// treat it as non-existant and provide a default.
// If the buffer is not large enough for a pcr consistent with pcrAlg, then the
// platform will return TPM_RC_FAILURE.
TPM_RC _platPcr__GetInitialValueForPcr(
    UINT32     pcrNumber,        // IN: PCR to be initialized
    TPM_ALG_ID pcrAlg,           // IN: Algorithm of the PCR Bank being initialized
    BYTE       startupLocality,  // IN: locality where startup is being called from
    BYTE*      pcrData,          // OUT: buffer to put PCR initialization value into
    USHORT   bufferSize,       // IN: maximum size of value buffer can hold
    USHORT*  pcrLength  // OUT: size of initialization value returned in pcrBuffer
)
{
    // If the reset locality contains locality 4, then this
    // indicates a DRTM PCR where the reset value is all ones,
    // otherwise it is all zero.  Don't check with equal because
    // resetLocality is a bitfield of multiple values and does
    // not support extended localities.
    USHORT pcrSize = CryptHashGetDigestSize(pcrAlg);
    pAssert_RC(pcrNumber < _platPcr__NumberOfPcrs());
    pAssert_RC(bufferSize >= pcrSize) pAssert_RC(pcrLength != NULL);

    PCR_Attributes pcrAttributes =
        _platPcr__GetPcrInitializationAttributes(pcrNumber);
    BYTE defaultValue = 0;
    // PCRs that can be cleared from locality 4 are DRTM and initialize to all 0xFF
    if((pcrAttributes.resetLocality & 0x10) != 0)
    {
        defaultValue = 0xFF;
    }
    MemorySet(pcrData, defaultValue, pcrSize);
    if(pcrNumber == HCRTM_PCR)
    {
        pcrData[pcrSize - 1] = startupLocality;
    }

    // platform could provide a value here if the platform has initialization rules
    // different from the original PC Client spec (the default used by the Core library).
    *pcrLength = pcrSize;
    return TPM_RC_SUCCESS;
}
