// TpmToMsBnMath.h - big number back end ("BN_MATH_LIB == MSBN") of ftpmsim.sys
//
// ms-tpm-20-ref names MSBN as the math library of the Windows build: the shipped
// binary contains the Windows glue (MsBnContextStart, MsBnPointToBnPoint, BnCurveInit,
// Root2, FindMetric ... see FunctionMap.csv) around SymCrypt's ARM64 Montgomery kernels
// and Microsoft's closed "msbignum" ECC code. That code is not public, so this
// header/TpmToMsBnMath.c pair is a *replacement adapter*: the same interface the TPM
// code needs (BnModMult, BnMult, BnDiv, BnGcd, BnModExp, BnModInverse, BnEccModMult,
// BnEccModMult2, BnEccAdd), written as portable word arithmetic. It is functionally
// equivalent, not instruction-equivalent, and not constant time.

#ifndef _TPM_TO_MSBN_MATH_H
#define _TPM_TO_MSBN_MATH_H

#if BN_MATH_LIB == MSBN

// The curve is simply the TPM's ECC_CURVE_DATA, as in the wolfSSL back end.
typedef const TPMBN_ECC_CURVE_CONSTANTS*    bigCurveData;

TPM_INLINE const TPMBN_ECC_CURVE_CONSTANTS* AccessCurveConstants(
    const bigCurveData* E)
{
    return *E;
}

//*** BnSupportLibInit()
// This does any initialization required by the support library.
LIB_EXPORT int BnSupportLibInit(void);

#define MSBN_ENTER()
#define MSBN_LEAVE()

// Unlike the reference's empty macro the binary exports MathLibSimulationEnd() (ordinal
// 97); it prints the scratch usage statistics of the math code.
void MathLibSimulationEnd(void);

#endif // BN_MATH_LIB == MSBN

#endif // _TPM_TO_MSBN_MATH_H
